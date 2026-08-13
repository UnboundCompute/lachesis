"""Read side of the Kùzu store: a drop-in for ``lachesis.core.query.GraphIndex`` backed
by a Kùzu DB directory instead of an in-RAM dict.

It satisfies the exact accessor surface ``GraphLib`` and the nav tools use — ``.nodes``
(id→node dict), ``.outgoing``/``.incoming`` (adjacency by id), ``targets``/``sources``,
``outgoing_of_kind``/``incoming_of_kind``, ``nodes_of_kind``/``nodes_named``/
``nodes_in_file``/``nodes_owned_by``, ``edges_of_kind``, ``first_target``,
``package_inventory``, ``semantic_edge_kind``, and ``flow_edges`` — so
``GraphStore``/``mcp_server``/every tool is untouched (see ``GraphLib.from_index`` and the
Kùzu branch in ``GraphStore.load``).

Design: everything rides on three primitives, so nothing materializes the whole graph at
load — only light, index-shaped maps and per-node fetches:

  * ``_node(id)``  — PK lookup, reconstructs the canonical ``{id,label,kind,properties}``
    dict by unioning the promoted columns with the ``props`` blob, which carries only
    the tail (see ``_stored_props``: a property in a typed column is not stored a second
    time in the blob) as deflated JSON, against the store's shared preset dictionary
    (``manifest_props_dictionary``, read once at open). Cached.
  * ``_edges(id, reverse)`` — one generic traversal query per node; reconstructs edge
    dicts ``{source,target,kind,properties}``. ``label(e)`` gives the kind for a hot rel
    table; the catch-all ``EDGE`` table carries ``kind``/``semantic_kind`` columns. Cached.
  * light ``by_*`` id-maps — built once at load from a single columnar scan of the
    promoted columns (no ``props`` parsing, no full node dicts held).

Constant props elided at write time are restored here by ``setdefault`` (they are
genuinely constant), so a parity build (prune+elide off) reconstructs the canonical dicts
exactly, and an elided build reconstructs them identically for navigation.
"""
from __future__ import annotations

import json
import zlib
from collections import defaultdict
from typing import Iterable, Optional, Sequence

from lachesis.core.query import GraphIndex
from lachesis.kuzu_store import (
    CODED_PROP_COLUMNS,
    CONSTANT_PROP_DEFAULTS,
    HOT_REL_KINDS,
    PROMOTED_NODE_PROPS,
    _HOT_SET,
    _prefix_code,
    db_file,
    decode_id,
    encode_id,
    manifest_id_prefixes,
    manifest_props_dictionary,
    read_store_manifest,
)

try:  # 3.10+ only
    import kuzu  # type: ignore
except Exception:  # pragma: no cover
    kuzu = None

def _EDGE_SORT(edge: dict) -> tuple:
    """Total order on edges, ``(kind, source, target)`` plus the properties.

    The properties are in the key for the same reason ``materialize_graph`` puts them
    in its own tie-break: two edges can share all three of ``(kind, source, target)``
    and differ only in props — two ``CALLS`` from one constructor to one method, from
    different callsites, is the common case — and without them the tie is resolved by
    whatever order Kùzu happened to scan in. Kùzu promises no scan order, so that made
    the output of ``_edges`` and ``edges_of_kind`` a function of storage layout: coding
    the primary key reordered the scan and the same store answered the same query in a
    different order. Same edges either way, but a navigation tool that lists callers
    twice should list them the same way twice.
    """
    return (edge.get("kind") or "", edge.get("source") or "", edge.get("target") or "",
            json.dumps(edge.get("properties") or {}, sort_keys=True))


def _overlay_edge_key(edge: dict) -> str:
    from lachesis.nav.overlay import edge_key
    return edge_key(edge)


def _inflate(props_blob: bytes, zdict: bytes) -> bytes:
    """Undo ``kuzu_store._deflate``.

    ``zdict`` is the store's shared preset dictionary, from its manifest. zlib only
    consults it when the stream says it needs one, so the wrong dictionary is not a
    silent corruption: a stream written without one inflates regardless, and a stream
    written with a different one raises rather than returning plausible bytes.
    """
    if not zdict:
        return zlib.decompress(props_blob)
    obj = zlib.decompressobj(zlib.MAX_WBITS, zdict)
    return obj.decompress(props_blob) + obj.flush()


def _restore(props_blob: Optional[bytes], zdict: bytes) -> dict:
    """Inflate a stored ``props`` blob back into a properties dict.

    The blob is deflated UTF-8 JSON (see ``kuzu_store._stored_props``). Inflating all
    244,954 nodes of the reference store costs 0.34s, against a materialize of ~5.5s."""
    props = json.loads(_inflate(props_blob, zdict)) if props_blob else {}
    for key, default in CONSTANT_PROP_DEFAULTS.items():
        if key not in props:
            props[key] = list(default) if isinstance(default, list) else default
    return props


# The columns the writer may omit from the ``props`` tail, in the order they are
# selected. ``unit`` is excluded: it is derived from ``file`` rather than being a
# property of its own, so merging it back would invent a key on every node.
_MERGED_COLUMNS = tuple(c for c in PROMOTED_NODE_PROPS if c != "unit")
_MERGED_SELECT = ", ".join(f"n.{c}" for c in _MERGED_COLUMNS)

# Positions in that tuple holding a coded node id, resolved once rather than per row:
# this runs 244,954 times on a materialize and a set lookup per column per node is not
# free at that count.
_CODED_AT = frozenset(i for i, c in enumerate(_MERGED_COLUMNS)
                      if c in CODED_PROP_COLUMNS)


def _restore_node_props(columns, props_blob: Optional[bytes],
                        zdict: bytes, prefixes: Sequence[str]) -> dict:
    """Union the promoted columns with the ``props`` tail.

    The tail wins on any overlap. Nothing overlaps in a store this version wrote —
    the writer drops exactly what the column carries faithfully — but a store written
    before that (whole dict in the blob) reads back correctly for the same reason, so
    tail-wins is the format-compatibility rule, not a rollout crutch.

    A NULL column is skipped rather than restored as ``None``: SQL NULL means either
    "absent" or "held null", and the writer keeps the held-null ones in the tail
    precisely so this can treat NULL as absent.

    The id columns are stored coded against ``prefixes`` (``kuzu_store.encode_id``) and
    are decoded on the way out, so the coding is invisible above this function — which
    is the point of doing it in a column the reader already funnels through here.
    """
    properties = {name: (decode_id(value, prefixes) if i in _CODED_AT else value)
                  for i, (name, value) in enumerate(zip(_MERGED_COLUMNS, columns))
                  if value is not None}
    properties.update(_restore(props_blob, zdict))
    return properties


def materialize_graph(index: "KuzuGraphIndex") -> dict:
    """Rebuild the whole canonical ``{nodes, edges}`` dict from a store.

    The rest of this module exists precisely to avoid this — the per-node primitives
    keep a whole-repo graph off the heap. But two callers genuinely need the dict:
    ``ReasoningQuery`` (``lachesis/cli/query.py``), which builds an in-RAM
    ``GraphIndex``, and overlay enrichment, which folds the graph whole. Both pay the
    peak once, deliberately; no nav navigation tool calls this.

    Two columnar scans rather than ``_node``/``_edges`` per id: a per-id primary-key
    lookup repeated a million times is the slow way to read a columnar store. Ordering
    matches ``combine_graphs`` (nodes by id, edges by ``(kind, source, target)``) so a
    materialized graph compares equal to a freshly composed one.
    """
    nodes = []
    # No `ORDER BY n.id`: the stored id is coded (``kuzu_store.encode_id``) and its
    # order is not the real one — the prefix sorts as a base36 code and the hash as
    # base64, neither of which is order-preserving. Sorting the decoded ids in Python
    # is what keeps this equal to ``combine_graphs``, and it also drops the Cypher sort.
    res = index._conn.execute(
        f"MATCH (n:Node) RETURN n.id, n.kind, n.label, {_MERGED_SELECT}, n.props"
    )
    while res.has_next():
        row = res.get_next()
        nid, kind, label = row[:3]
        nid = decode_id(nid, index._id_prefixes)
        nodes.append({"id": nid, "kind": kind, "label": label,
                      "properties": _restore_node_props(row[3:-1], row[-1],
                                                        index._props_dict,
                                                        index._id_prefixes)})
    nodes.sort(key=lambda n: n["id"])
    prefixes = index._id_prefixes
    edges = []
    for kind in HOT_REL_KINDS:
        res = index._conn.execute(
            f"MATCH (a:Node)-[e:{kind}]->(b:Node) RETURN a.id, b.id, e.props"
        )
        while res.has_next():
            src, tgt, props = res.get_next()
            edges.append({"source": decode_id(src, prefixes),
                          "target": decode_id(tgt, prefixes), "kind": kind,
                          "properties": _restore(props, index._props_dict)})
    res = index._conn.execute(
        "MATCH (a:Node)-[e:EDGE]->(b:Node) RETURN a.id, b.id, e.kind, e.props"
    )
    while res.has_next():
        src, tgt, kind, props = res.get_next()
        edges.append({"source": decode_id(src, prefixes),
                      "target": decode_id(tgt, prefixes), "kind": kind,
                      "properties": _restore(props, index._props_dict)})
    # Kùzu does not promise a scan order, and two edges can share
    # ``(kind, source, target)`` while differing in props, so the tie-break folds the
    # props in: materializing the same store twice must give byte-identical output, or
    # a downstream enrich is not reproducible.
    edges.extend(deferred_edges(index))
    edges.sort(key=lambda e: (e["kind"], e["source"], e["target"],
                              json.dumps(e["properties"], sort_keys=True)))
    return {"nodes": nodes, "edges": edges}


def deferred_edges(index: "KuzuGraphIndex") -> list:
    """The edges this store holds but cannot attach: one endpoint is not resident.

    Empty for every ordinary store. A spine-and-semantic store has many, and they are
    the reason it is worth writing: a semantic fact about a value inside a function is
    an edge into a body node the store dropped on purpose. They become ordinary edges
    again the moment the bodies are recompiled and joined back in, which is why they
    ride in a table of their own rather than as rows nothing can traverse.

    Returned unsorted; ``materialize_graph`` sorts the union.
    """
    if not index._deferred_edge_count:
        return []
    prefixes = index._id_prefixes
    res = index._conn.execute(
        "MATCH (d:DeferredEdge) RETURN d.kind, d.src, d.tgt, d.props"
    )
    out = []
    while res.has_next():
        kind, src, tgt, props = res.get_next()
        out.append({"source": decode_id(src, prefixes),
                    "target": decode_id(tgt, prefixes), "kind": kind,
                    "properties": _restore(props, index._props_dict)})
    return out


class _NodeMap:
    """Lazy id→node mapping with the dict-ish surface callers use."""

    def __init__(self, index: "KuzuGraphIndex") -> None:
        self._index = index

    def get(self, node_id, default=None):
        node = self._index._node(node_id)
        return node if node is not None else default

    def __getitem__(self, node_id):
        node = self._index._node(node_id)
        if node is None:
            raise KeyError(node_id)
        return node

    def __contains__(self, node_id):
        return self._index._node(node_id) is not None

    def __len__(self):
        return self._index._node_count()

    def __iter__(self):
        return iter(self._index._all_ids())

    def values(self):
        return (self._index._node(nid) for nid in self._index._all_ids())

    def items(self):
        return ((nid, self._index._node(nid)) for nid in self._index._all_ids())


class _Adjacency:
    """Lazy id→edge-list adjacency (forward or reverse)."""

    def __init__(self, index: "KuzuGraphIndex", reverse: bool) -> None:
        self._index = index
        self._reverse = reverse

    def get(self, node_id, default=()):
        edges = self._index._edges(node_id, self._reverse)
        return edges if edges else default

    def __getitem__(self, node_id):
        return self._index._edges(node_id, self._reverse)

    def values(self):
        return (self._index._edges(nid, self._reverse)
                for nid in self._index._all_ids())

    def items(self):
        return ((nid, self._index._edges(nid, self._reverse))
                for nid in self._index._all_ids())


class KuzuGraphIndex:
    semantic_edge_kind = staticmethod(GraphIndex.semantic_edge_kind)

    def __init__(self, db_dir: str) -> None:
        if kuzu is None:
            raise RuntimeError(
                "kuzu is not installed; the Kùzu index needs Python 3.10+ with `kuzu`."
            )
        self._db = kuzu.Database(db_file(db_dir), read_only=True)
        self._conn = kuzu.Connection(self._db)
        # Read once at open, not per blob: it is a fixed 32 KB and every `props` in the
        # store needs it. ``GraphStore.load`` has already checked the format stamp in
        # this same manifest, so a store whose dictionary this reader could not use has
        # been rejected before here.
        manifest = read_store_manifest(db_dir)
        self._props_dict = manifest_props_dictionary(manifest)
        self._id_prefixes = manifest_id_prefixes(manifest)
        # The same table inverted, for the lookup direction: `_node`/`_edges` take a
        # real id and have to match it against the coded `id` column. Built once at
        # open rather than per lookup — nav does hundreds of thousands of these.
        self._id_codes = {prefix: _prefix_code(i)
                          for i, prefix in enumerate(self._id_prefixes)}
        # Whether this store carries edges awaiting a recompiled endpoint. Read from the
        # manifest rather than probed for, so an ordinary store costs no query to find
        # out that it has none.
        self._deferred_edge_count = int(manifest.get("deferred_edge_count") or 0)
        self._node_cache: dict[str, Optional[dict]] = {}
        self._out_cache: dict[str, list] = {}
        self._in_cache: dict[str, list] = {}
        self._overlay = None
        self._derived_out: dict = {}
        self._derived_in: dict = {}
        self.nodes = _NodeMap(self)
        self.outgoing = _Adjacency(self, reverse=False)
        self.incoming = _Adjacency(self, reverse=True)
        self._build_maps()

    # -- load-time light maps (one columnar scan, no props) -----------------

    def _build_maps(self) -> None:
        self.by_kind: dict = defaultdict(list)
        self.by_label: dict = defaultdict(list)
        self.by_file: dict = defaultdict(list)
        self.by_owner: dict = defaultdict(list)
        self._ids: list[str] = []
        # Decoded here and nowhere below: every map this builds is keyed by, and holds,
        # the real id, so the coding stops at this loop and the rest of the index — and
        # every nav tool above it — never sees a coded value.
        res = self._conn.execute(
            "MATCH (n:Node) RETURN n.id, n.kind, n.label, n.file, n.absolute_file, "
            "n.owner_function_id, n.function_id"
        )
        while res.has_next():
            nid, kind, label, file, abs_file, owner, fn = res.get_next()
            nid = decode_id(nid, self._id_prefixes)
            self._ids.append(nid)
            self.by_kind[kind].append(nid)
            self.by_label[label].append(nid)
            path = abs_file or file
            if path:
                self.by_file[path].append(nid)
            owner_key = owner or fn
            if owner_key:
                self.by_owner[owner_key].append(nid)
        # The scan used to arrive in id order from `ORDER BY n.id`, which every bucket
        # inherited by construction; the stored id is coded now and that order is not
        # the real one, so sort what the order was doing for us. Buckets included: a
        # tool that lists a file's nodes should list them the same way twice.
        self._ids.sort()
        for buckets in (self.by_kind, self.by_label, self.by_file, self.by_owner):
            for ids in buckets.values():
                ids.sort()

    # -- sidecar overlay ----------------------------------------------------

    def attach_overlay(self, overlay) -> None:
        """Merge a derived-signal sidecar (``nav/overlay.py``) into the live index.

        The store on disk is never rewritten; the overlay's node props, derived nodes
        and derived ``GUARDED``/``UNGUARDED`` edges are folded in as the index answers
        queries, which is the store-backed equivalent of ``Overlay.apply_to`` on a
        graph dict. Must run before any fetch, so it drops the caches.
        """
        if not (overlay.node_props or overlay.edge_props
                or overlay.derived_nodes or overlay.derived_edges):
            return
        self._overlay = overlay
        self._node_cache.clear()
        self._out_cache.clear()
        self._in_cache.clear()
        self._derived_out = defaultdict(list)
        self._derived_in = defaultdict(list)
        for edge in overlay.derived_edges:
            self._derived_out[edge["source"]].append(edge)
            self._derived_in[edge["target"]].append(edge)
        for node in overlay.derived_nodes:
            nid = node["id"]
            if nid in self._node_cache:
                continue
            self._ids.append(nid)
            self.by_kind[node.get("kind")].append(nid)
            self.by_label[node.get("label")].append(nid)
            props = node.get("properties") or {}
            path = props.get("absolute_file") or props.get("file")
            if path:
                self.by_file[path].append(nid)
            owner = props.get("owner_function_id") or props.get("function_id")
            if owner:
                self.by_owner[owner].append(nid)
            self._node_cache[nid] = node
        self._ids.sort()

    def _node_count(self) -> int:
        return len(self._ids)

    def _all_ids(self):
        return list(self._ids)

    # -- primitives ---------------------------------------------------------

    def _node(self, node_id: str) -> Optional[dict]:
        if node_id in self._node_cache:
            return self._node_cache[node_id]
        res = self._conn.execute(
            f"MATCH (n:Node {{id: $id}}) RETURN n.kind, n.label, {_MERGED_SELECT}, "
            "n.props", {"id": encode_id(node_id, self._id_codes)}
        )
        node = None
        if res.has_next():
            row = res.get_next()
            kind, label = row[:2]
            properties = _restore_node_props(row[2:-1], row[-1], self._props_dict,
                                             self._id_prefixes)
            if self._overlay is not None:
                properties.update(self._overlay.node_props.get(node_id) or {})
            node = {"id": node_id, "kind": kind, "label": label,
                    "properties": properties}
        self._node_cache[node_id] = node
        return node

    def _edges(self, node_id: str, reverse: bool) -> list:
        cache = self._in_cache if reverse else self._out_cache
        if node_id in cache:
            return cache[node_id]
        if reverse:
            cypher = ("MATCH (a:Node)-[e]->(b:Node {id: $id}) "
                      "RETURN label(e), a.id, e.kind, e.semantic_kind, e.props")
        else:
            cypher = ("MATCH (a:Node {id: $id})-[e]->(b:Node) "
                      "RETURN label(e), b.id, e.kind, e.semantic_kind, e.props")
        res = self._conn.execute(cypher, {"id": encode_id(node_id, self._id_codes)})
        edges = []
        while res.has_next():
            label, other, kind_col, sem_col, props = res.get_next()
            kind = kind_col if label == "EDGE" else label
            other = decode_id(other, self._id_prefixes)
            src, tgt = (other, node_id) if reverse else (node_id, other)
            edges.append({"source": src, "target": tgt, "kind": kind,
                          "properties": _restore(props, self._props_dict)})
        if self._overlay is not None:
            for edge in edges:
                extra = self._overlay.edge_props.get(_overlay_edge_key(edge))
                if extra:
                    edge["properties"].update(extra)
            derived = self._derived_in if reverse else self._derived_out
            edges.extend({"source": e["source"], "target": e["target"],
                          "kind": e["kind"], "properties": dict(e.get("properties") or {})}
                         for e in derived.get(node_id, ()))
        edges.sort(key=_EDGE_SORT)
        cache[node_id] = edges
        return edges

    # -- GraphIndex accessor surface ----------------------------------------

    def _accepted(self, edge: dict, accepted) -> bool:
        return (edge.get("kind") in accepted
                or self.semantic_edge_kind(edge) in accepted)

    def targets(self, source: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self._edges(source, reverse=False):
            if self._accepted(edge, accepted):
                node = self._node(edge["target"])
                if node is not None:
                    yield node

    def sources(self, target: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self._edges(target, reverse=True):
            if self._accepted(edge, accepted):
                node = self._node(edge["source"])
                if node is not None:
                    yield node

    def outgoing_of_kind(self, source: str, *edge_kinds: str) -> tuple:
        accepted = frozenset(edge_kinds)
        return tuple(e for e in self._edges(source, reverse=False)
                     if self._accepted(e, accepted))

    def incoming_of_kind(self, target: str, *edge_kinds: str) -> tuple:
        accepted = frozenset(edge_kinds)
        return tuple(e for e in self._edges(target, reverse=True)
                     if self._accepted(e, accepted))

    def first_target(self, source: str, *edge_kinds: str) -> Optional[dict]:
        return next(iter(self.targets(source, *edge_kinds)), None)

    def nodes_of_kind(self, *kinds: str) -> Iterable[dict]:
        return (self._node(nid) for kind in kinds
                for nid in self.by_kind.get(kind, ()))

    def nodes_named(self, label: str) -> tuple:
        return tuple(self._node(nid) for nid in self.by_label.get(label, ()))

    def nodes_in_file(self, path: str) -> tuple:
        return tuple(self._node(nid) for nid in self.by_file.get(path, ()))

    def nodes_owned_by(self, owner_id: str) -> tuple:
        return tuple(self._node(nid) for nid in self.by_owner.get(owner_id, ()))

    def edges_of_kind(self, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        edges: list[dict] = []
        for kind in accepted & _HOT_SET:
            res = self._conn.execute(
                f"MATCH (a:Node)-[e:{kind}]->(b:Node) RETURN a.id, b.id, e.props"
            )
            while res.has_next():
                src, tgt, props = res.get_next()
                edges.append({"source": decode_id(src, self._id_prefixes),
                              "target": decode_id(tgt, self._id_prefixes),
                              "kind": kind,
                              "properties": _restore(props, self._props_dict)})
        res = self._conn.execute(
            "MATCH (a:Node)-[e:EDGE]->(b:Node) WHERE e.semantic_kind IN $kinds "
            "RETURN a.id, b.id, e.kind, e.props", {"kinds": list(accepted)}
        )
        while res.has_next():
            src, tgt, kind, props = res.get_next()
            edges.append({"source": decode_id(src, self._id_prefixes),
                          "target": decode_id(tgt, self._id_prefixes), "kind": kind,
                          "properties": _restore(props, self._props_dict)})
        if self._overlay is not None:
            edges.extend(dict(e) for e in self._overlay.derived_edges
                         if e.get("kind") in accepted)
        edges.sort(key=_EDGE_SORT)
        return edges

    def flow_edges(self, kinds) -> list:
        return list(self.edges_of_kind(*kinds))

    def package_inventory(self) -> frozenset:
        names = set()
        for node in self.nodes_of_kind("package"):
            name = (node.get("properties", {}).get("package_name")
                    or node.get("label"))
            if name:
                names.add(name)
        return frozenset(names)
