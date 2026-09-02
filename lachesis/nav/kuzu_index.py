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
    the tail (see ``PropsCodec``: a property in a typed column is not stored a second
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

import os
import zlib
from array import array
from bisect import bisect_left
from collections import defaultdict
from typing import Iterable, Optional, Sequence

from lachesis.core.query import GraphIndex
from lachesis.kuzu_store import (
    CODED_PROP_COLUMNS,
    CONSTANT_PROP_DEFAULTS,
    HOT_REL_KINDS,
    PROMOTED_NODE_PROPS,
    _CALLSITE_INDEX_COLUMNS,
    _DECL_INDEX_COLUMNS,
    _HOT_SET,
    _INDEX_ID_COLUMNS,
    _prefix_code,
    db_file,
    decode_id,
    encode_id,
    manifest_id_prefixes,
    manifest_props_dictionary,
    read_store_manifest,
)
from lachesis.core.graph_wire import decode_document, encode_document
from lachesis.nav.overlay import edge_key
from lachesis.timeit import timeit

try:  # 3.10+ only
    import kuzu  # type: ignore
except Exception:  # pragma: no cover
    kuzu = None


class _LazyDefaultProps(dict):
    """Supply elided compiler constants without storing them on every row."""

    def __missing__(self, key):
        if key not in CONSTANT_PROP_DEFAULTS:
            raise KeyError(key)
        default = CONSTANT_PROP_DEFAULTS[key]
        return list(default) if isinstance(default, list) else default


def _query_threads() -> int:
    """Return the bounded Kùzu read parallelism for materialization/query scans."""
    raw = os.environ.get("LACHESIS_KUZU_QUERY_THREADS", "")
    if raw:
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError("LACHESIS_KUZU_QUERY_THREADS must be an integer") from exc
        if value < 1:
            raise ValueError("LACHESIS_KUZU_QUERY_THREADS must be positive")
        return value
    return max(1, min(os.cpu_count() or 1, 8))

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
            encode_document(edge.get("properties") or {}))


def _sort_materialized_edges(edges: list[dict]) -> None:
    """Sort materialized edges without encoding properties for unique triples.

    The canonical order includes encoded properties only to make duplicate
    ``(kind, source, target)`` triples deterministic.  On large graphs almost every
    triple is unique, so putting the protobuf encoding in the primary sort key pays
    for every edge for a tie-break that almost never runs.  Sort by the triple first,
    then sort only collision groups by the same property key.
    """
    edges.sort(key=lambda edge: (
        edge.get("kind") or "", edge.get("source") or "", edge.get("target") or "",
    ))
    start = 0
    while start < len(edges):
        first = edges[start]
        triple = (first.get("kind") or "", first.get("source") or "",
                  first.get("target") or "")
        end = start + 1
        while end < len(edges):
            edge = edges[end]
            if (edge.get("kind") or "", edge.get("source") or "",
                    edge.get("target") or "") != triple:
                break
            end += 1
        if end - start > 1:
            edges[start:end] = sorted(
                edges[start:end],
                key=lambda edge: encode_document(edge.get("properties") or {}),
            )
        start = end


def _overlay_edge_key(edge: dict) -> str:
    from lachesis.nav.overlay import edge_key
    return edge_key(edge)


def _inflate(props_blob: bytes, zdict: bytes) -> bytes:
    """Undo ``kuzu_store.PropsCodec.blob``.

    ``zdict`` is the store's shared preset dictionary, from its manifest. zlib only
    consults it when the stream says it needs one, so the wrong dictionary is not a
    silent corruption: a stream written without one inflates regardless, and a stream
    written with a different one raises rather than returning plausible bytes.
    """
    if not zdict:
        return zlib.decompress(props_blob)
    obj = zlib.decompressobj(zlib.MAX_WBITS, zdict)
    return obj.decompress(props_blob) + obj.flush()


def _restore(
    props_blob: Optional[bytes], zdict: bytes, *, restore_defaults: bool = True,
) -> dict:
    """Inflate a stored ``props`` blob back into a properties dict.

    The blob is deflated protobuf metadata (see ``kuzu_store.PropsCodec``)."""
    if props_blob:
        try:
            props = decode_document(_inflate(props_blob, zdict))
        except (zlib.error, ValueError, TypeError) as exc:
            # A legacy/corrupt property tail must not prevent navigation over the
            # rest of a readable graph. Preserve the failure as an explicit unknown.
            props = {"_decode_error": str(exc)}
    else:
        props = {}
    if not restore_defaults:
        return _LazyDefaultProps(props)
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

# Field order of the promoted-scalar node header, stored positionally in
# ``_header_by_id`` (see ``KuzuGraphIndex._build_maps`` / ``_header``). This order is
# the dict insertion order readers used to see, so header serialization stays stable.
_HEADER_FIELDS = ("file", "absolute_file", "start_line", "end_line",
                  "start_offset", "end_offset", "owner_function_id", "function_id")


def _restore_node_props(columns, props_blob: Optional[bytes],
                        zdict: bytes, prefixes: Sequence[str], *,
                        restore_defaults: bool = True) -> dict:
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
    props_type = dict if restore_defaults else _LazyDefaultProps
    properties = props_type(
        {name: (decode_id(value, prefixes) if i in _CODED_AT else value)
         for i, (name, value) in enumerate(zip(_MERGED_COLUMNS, columns))
         if value is not None}
    )
    properties.update(_restore(props_blob, zdict, restore_defaults=restore_defaults))
    return properties


def materialize_subgraph(index: "KuzuGraphIndex", keep, *, restore_defaults: bool = True) -> dict:
    """The canonical ``{nodes, edges}`` dict restricted to the nodes ``keep`` holds.

    An edge survives only if *both* its endpoints do. A subgraph with an edge pointing
    out of itself is not a smaller graph, it is a broken one: the overlays that fold
    over this look their endpoints up in the node map, and a dangling target reads as a
    node with no kind rather than as a node that was left out.

    Still one columnar scan per table, exactly as the whole-graph case -- the saving
    here is not in what the store reads but in what stays on the heap afterwards, which
    is the entire point of folding a cone instead of a repo.
    """
    return _materialize(index, keep, restore_defaults=restore_defaults)


def materialize_graph(index: "KuzuGraphIndex", *, restore_defaults: bool = True,
                     sort_output: bool = True) -> dict:
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
    return _materialize(index, None, restore_defaults=restore_defaults,
                        sort_output=sort_output)


def _materialize(index: "KuzuGraphIndex", keep, *, restore_defaults: bool = True,
                 sort_output: bool = True) -> dict:
    """Both of the above. ``keep`` is a container of surviving ids, or ``None`` for all.

    One body rather than two because a subgraph that restored props even slightly
    differently from the whole graph would enrich differently, and the difference would
    surface as a dataflow edge that appears only when the cone is small -- which is
    indistinguishable from the semantic loss cone-scoping is *expected* to have, and so
    would hide inside it forever.
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
        if keep is not None and nid not in keep:
            continue
        nodes.append({"id": nid, "kind": kind, "label": label,
                      "properties": _restore_node_props(
                          row[3:-1], row[-1], index._props_dict, index._id_prefixes,
                          restore_defaults=restore_defaults)})
    prefixes = index._id_prefixes
    edges = []
    for kind in HOT_REL_KINDS:
        res = index._conn.execute(
            f"MATCH (a:Node)-[e:{kind}]->(b:Node) RETURN a.id, b.id, e.props"
        )
        while res.has_next():
            src, tgt, props = res.get_next()
            src, tgt = decode_id(src, prefixes), decode_id(tgt, prefixes)
            if keep is not None and (src not in keep or tgt not in keep):
                continue
            edges.append({"source": src, "target": tgt, "kind": kind,
                          "properties": _restore(
                              props, index._props_dict, restore_defaults=restore_defaults)})
    res = index._conn.execute(
        "MATCH (a:Node)-[e:EDGE]->(b:Node) RETURN a.id, b.id, e.kind, e.props"
    )
    while res.has_next():
        src, tgt, kind, props = res.get_next()
        src, tgt = decode_id(src, prefixes), decode_id(tgt, prefixes)
        if keep is not None and (src not in keep or tgt not in keep):
            continue
        edges.append({"source": src, "target": tgt, "kind": kind,
                      "properties": _restore(
                          props, index._props_dict, restore_defaults=restore_defaults)})
    # Kùzu does not promise a scan order, and two edges can share
    # ``(kind, source, target)`` while differing in props, so the tie-break folds the
    # props in: materializing the same store twice must give byte-identical output, or
    # a downstream enrich is not reproducible.
    deferred = deferred_edges(index, restore_defaults=restore_defaults)
    # Ordinary stores have neither deferred edges nor an overlay. Avoid allocating a
    # second set of every node id in that common case; it is needed only when one of
    # the following edge sources must be checked for resident endpoints.
    overlay = getattr(index, "_overlay", None)
    resident = ({node["id"] for node in nodes}
                if deferred or (overlay is not None and overlay.derived_edges)
                else None)
    # ``keep`` can contain an id named by a deferred edge even though no Node row for
    # that id exists in this store. Filtering against ``keep`` alone therefore admits
    # the very dangling edge a materialized subgraph promises never to contain.
    if resident is not None:
        deferred = [e for e in deferred
                    if e["source"] in resident and e["target"] in resident]
    edges.extend(deferred)

    # A core-only store keeps additive dataflow facts in a sidecar overlay.  The
    # normal navigation accessors graft those records as needed, but whole-graph
    # materialization must expose the same canonical view as an eagerly enriched
    # Kùzu store (used by enrichment/parity callers).  Previously the lazy path
    # silently returned only base rows, dropping every derived node/edge from the
    # comparison while leaving ordinary navigation apparently healthy.
    if overlay is not None:
        if overlay.node_props:
            for position, node in enumerate(nodes):
                extra = overlay.node_props.get(node["id"])
                if extra:
                    properties = dict(node.get("properties") or {})
                    properties.update(extra)
                    nodes[position] = {**node, "properties": properties}
        if overlay.edge_props:
            for position, edge in enumerate(edges):
                extra = overlay.edge_props.get(edge_key(edge))
                if extra:
                    properties = dict(edge.get("properties") or {})
                    properties.update(extra)
                    edges[position] = {**edge, "properties": properties}
        nodes.extend(
            node for node in overlay.derived_nodes
            if keep is None or node.get("id") in keep
        )
        resident = {node["id"] for node in nodes}
        edges.extend(
            edge for edge in overlay.derived_edges
            if (keep is None or
                (edge.get("source") in resident and edge.get("target") in resident))
        )
    if sort_output:
        _sort_materialized_edges(edges)
        nodes.sort(key=lambda n: n["id"])
    return {"nodes": nodes, "edges": edges}


def deferred_edges(index: "KuzuGraphIndex", *, restore_defaults: bool = True) -> list:
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
                    "properties": _restore(
                        props, index._props_dict, restore_defaults=restore_defaults)})
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

    def __init__(self, db_dir: str, *, defer_maps: bool = False) -> None:
        if kuzu is None:
            raise RuntimeError(
                "kuzu is not installed; the Kùzu index needs Python 3.10+ with `kuzu`."
            )
        # Kùzu defaults its buffer pool to ~80% of system RAM, so the open-time
        # `MATCH (n:Node)` scan (and every later page touch) can cache node pages up
        # to that ceiling -- an O(nodes) page cache that, at kernel scale, dwarfs the
        # Python navigation maps. This read-only index builds its own resident maps
        # and then serves node/edge lookups through bounded caches, so a large page
        # cache buys little. `LACHESIS_KUZU_BPS` (bytes) caps it; unset keeps Kùzu's
        # default. Measured before making it a non-env default.
        _bps = os.environ.get("LACHESIS_KUZU_BPS")
        if _bps:
            self._db = kuzu.Database(
                db_file(db_dir), read_only=True, buffer_pool_size=int(_bps))
        else:
            self._db = kuzu.Database(db_file(db_dir), read_only=True)
        # Capping the pool is only safe if the open-scan is *paged*: a single
        # `MATCH (n:Node)` materializes its whole result in the pool (O(nodes)),
        # so under a cap it overflows with "buffer pool is full". `_build_maps`
        # instead walks half-open storage-offset windows (`offset(id(n))`), each
        # of which materializes only its window -- bounded working set, no global
        # ORDER BY (which would force a full sort/materialize) and no SKIP rescan
        # (which is O(nodes^2)). `LACHESIS_KUZU_BATCH` sets the window size; if a
        # pool cap is set without one, page at a safe default so the cap holds;
        # with neither set the scan stays monolithic (unchanged default path).
        _batch = os.environ.get("LACHESIS_KUZU_BATCH")
        if _batch:
            self._scan_batch = int(_batch)
        elif _bps:
            self._scan_batch = 100_000
        else:
            self._scan_batch = 0
        self._conn = kuzu.Connection(self._db)
        self._db_dir = db_dir
        set_threads = getattr(self._conn, "set_max_threads_for_exec", None)
        if set_threads is not None:
            set_threads(_query_threads())
        # Read once at open, not per blob: it is a fixed 32 KB and every `props` in the
        # store needs it. ``GraphStore.load`` has already checked the format stamp in
        # this same manifest, so a store whose dictionary this reader could not use has
        # been rejected before here.
        manifest = read_store_manifest(db_dir)
        self._store_manifest = manifest
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
        # Prepared statements, by query text. `Connection.execute` on a raw string
        # prepares it first, every single time, and preparing is not the cheap half:
        # profiling `callees` on a 222k-node store showed 22,887 executions of four
        # distinct query strings costing 4.8s in `kuzu.prepare` against 4.4s in
        # `kuzu.execute`. The query set here is closed and tiny -- these are fixed
        # strings with bound parameters, never interpolated user input -- so caching
        # them is bounded by the number of literals in this file.
        self._prepared: dict = {}
        # Memoized unions of `by_kind` buckets, keyed by the frozen kind set. Callers
        # that narrow ownership by kind ask the same two or three questions over and
        # over, and each answer is a set union over buckets that do not move.
        self._kind_ids: dict = {}
        # What `graft` has already merged, so overlapping cone folds are additive
        # rather than duplicative. Nodes and edges separately because a node can be
        # grafted once and then referenced by edges from several later folds.
        self._grafted_nodes: set = set()
        self._grafted_edges: set = set()
        self._overlay = None
        self._derived_out: dict = {}
        self._derived_in: dict = {}
        self._overlay_argument_edges: dict = {}
        self._ids = []
        # Columnar backend (prototype, env-gated LACHESIS_COLUMNAR=1): replace the
        # three str-keyed value dicts with int-coded parallel columns held in
        # sorted-nid order, plus one sorted key array (`_scan_ids`) that a lookup
        # bisects to reach the row. Same byte-identical returns; the dicts below are
        # simply not populated when this is on, so their per-entry container overhead
        # (the dominant resident cost at kernel scale) disappears, and there is no
        # nid->row dict at all -- the sorted key array carries the mapping.
        self._columnar = os.environ.get("LACHESIS_COLUMNAR", "1") != "0"
        # Sorted array of the scanned nids, aligned to the columns (column row i is
        # `_scan_ids[i]`). Kept independent of `_ids` on purpose: overlay/graft append
        # derived nids to `_ids` and re-sort it, which would break column alignment, but
        # they never touch `_scan_ids`, so a derived nid simply misses the bisect (None).
        self._scan_ids: list = []
        self._kind_col = array("i")
        self._kind_vocab: list = []
        self._label_col = array("i")
        self._label_vocab: list = []
        # Header string columns share one vocab (paths + function ids); -1 == None.
        self._hstr_vocab: list = []
        self._h_file = array("i")
        self._h_absfile = array("i")
        self._h_owner = array("i")
        self._h_fn = array("i")
        # Header int columns; -1 sentinel == None (lines >= 1, offsets >= 0).
        self._h_sl = array("i")
        self._h_el = array("i")
        self._h_so = array("i")
        self._h_eo = array("i")
        self._kind_by_id = {}
        self._label_by_id = {}
        self._header_by_id = {}
        self.nodes = _NodeMap(self)
        self.outgoing = _Adjacency(self, reverse=False)
        self.incoming = _Adjacency(self, reverse=True)
        self._maps_deferred = defer_maps
        if defer_maps:
            # Ephemeral whole-graph queries only scan the store into a canonical
            # graph for enrichment; they never use navigation buckets.  Keep the
            # public attributes initialized for the shared accessor surface while
            # avoiding four graph-sized bucket maps and their sort pass.
            self.by_kind = defaultdict(list)
            self._init_by_label()
            self.by_file = defaultdict(list)
            self.by_owner = defaultdict(list)
        else:
            self._build_maps()

    # -- load-time light maps (one columnar scan, no props) -----------------

    def _build_maps(self) -> None:
        self.by_kind: dict = defaultdict(list)
        self._init_by_label()
        self.by_file: dict = defaultdict(list)
        self.by_owner: dict = defaultdict(list)
        self._ids: list[str] = []
        if self._columnar:
            # Re-entrant (ensure_maps re-runs this after a deferred build): reset the
            # columns so a rebuild does not append onto stale rows.
            self._scan_ids = []
            self._kind_col = array("i"); self._kind_vocab = []
            self._label_col = array("i"); self._label_vocab = []
            self._hstr_vocab = []
            self._h_file = array("i"); self._h_absfile = array("i")
            self._h_owner = array("i"); self._h_fn = array("i")
            self._h_sl = array("i"); self._h_el = array("i")
            self._h_so = array("i"); self._h_eo = array("i")
        # Decoded here and nowhere below: every map this builds is keyed by, and holds,
        # the real id, so the coding stops at this loop and the rest of the index — and
        # every nav tool above it — never sees a coded value.
        _SELECT = (
            "n.id, n.kind, n.label, n.file, n.absolute_file, "
            "n.start_line, n.end_line, n.start_offset, n.end_offset, "
            "n.owner_function_id, n.function_id"
        )
        # Kùzu hands back a fresh str object per cell, so the same kind/file/owner
        # spelled on 850k nodes arrives as 850k copies. These columns are low
        # cardinality (13 kinds, ~2.4k files, ~9k owners over ~850k nodes), so
        # collapsing equal spellings to one shared object is a large, value-preserving
        # cut to the resident maps -- ~355 MB on suricata. `pool.setdefault(s, s)`
        # returns the first object seen for a spelling and keeps only that one alive;
        # the transient pool is dropped when the scan ends.
        pool: dict = {}

        def _dedup(value):
            return value if value is None else pool.setdefault(value, value)

        # Int-coding for the columnar backend: each distinct (already pooled) value is
        # assigned a dense code the first time it is seen; the column stores the code,
        # the vocab recovers the value. None -> -1. The code dicts are transient (build
        # only); the vocabs stay resident to decode on lookup.
        kcode: dict = {}
        lcode: dict = {}
        hcode: dict = {}
        columnar = self._columnar

        def _code(value, code, vocab):
            if value is None:
                return -1
            c = code.get(value)
            if c is None:
                c = len(vocab)
                code[value] = c
                vocab.append(value)
            return c

        def _ingest(row) -> None:
            (nid, kind, label, file, abs_file, start_line, end_line,
             start_offset, end_offset, owner, fn) = row
            nid = decode_id(nid, self._id_prefixes)
            kind = _dedup(kind)
            label = _dedup(label)
            file = _dedup(file)
            abs_file = _dedup(abs_file)
            owner = _dedup(owner)
            fn = _dedup(fn)
            self._ids.append(nid)
            if columnar:
                # Int-coded parallel columns replace the three str-keyed value dicts.
                # Filled in scan order here, then reordered to sorted-nid order once the
                # scan is done (see below), so a lookup can bisect `_scan_ids` for the
                # row instead of holding a nid->row dict.
                self._kind_col.append(_code(kind, kcode, self._kind_vocab))
                self._label_col.append(_code(label, lcode, self._label_vocab))
                self._h_file.append(_code(file, hcode, self._hstr_vocab))
                self._h_absfile.append(_code(abs_file, hcode, self._hstr_vocab))
                self._h_owner.append(_code(owner, hcode, self._hstr_vocab))
                self._h_fn.append(_code(fn, hcode, self._hstr_vocab))
                self._h_sl.append(start_line if start_line is not None else -1)
                self._h_el.append(end_line if end_line is not None else -1)
                self._h_so.append(start_offset if start_offset is not None else -1)
                self._h_eo.append(end_offset if end_offset is not None else -1)
            else:
                self._kind_by_id[nid] = kind
                self._label_by_id[nid] = label
                # Stored as a positional tuple rather than an 8-key dict: over ~850k
                # nodes the dict container alone cost ~262 MB (272 B/node) against
                # ~88 MB for the tuple (104 B/node). `_header` rebuilds the dict, in
                # this exact field order, only for nodes a reader actually projects.
                self._header_by_id[nid] = (file, abs_file, start_line, end_line,
                                           start_offset, end_offset, owner, fn)
            self.by_kind[kind].append(nid)
            if not columnar:
                # Columnar defers `by_label` entirely: every base label already lives
                # in `_label_col`/`_label_vocab`, so the inverted map is rebuilt on
                # demand (see the `by_label` property) instead of held resident through
                # the memory-critical build. In dict mode it is populated eagerly here.
                self._bl_store[label].append(nid)
            path = abs_file or file
            if path:
                self.by_file[path].append(nid)
            owner_key = owner or fn
            if owner_key:
                self.by_owner[owner_key].append(nid)

        batch = self._scan_batch
        if batch:
            # Paged scan: storage offsets are dense 0..N-1 for a build-once, read-only
            # store, so half-open [lo, lo+batch) windows partition every node exactly
            # once. `ORDER BY` is deliberately absent (it forces a global sort that
            # materializes all rows and defeats the pool cap); the final maps are
            # sorted below, so per-window order does not affect the result. The first
            # empty window is past the last offset, which ends the walk. Every window
            # keyed and held on the real id exactly as the monolithic path.
            lo = 0
            while True:
                res = self._conn.execute(
                    "MATCH (n:Node) "
                    "WHERE offset(id(n)) >= $lo AND offset(id(n)) < $hi "
                    f"RETURN {_SELECT}",
                    {"lo": lo, "hi": lo + batch},
                )
                got = 0
                while res.has_next():
                    _ingest(res.get_next())
                    got += 1
                if got == 0:
                    break
                lo += batch
        else:
            res = self._conn.execute(f"MATCH (n:Node) RETURN {_SELECT}")
            while res.has_next():
                _ingest(res.get_next())
        if self._columnar:
            # Reorder the scan-order columns into sorted-nid order so a lookup can
            # `bisect_left(_scan_ids, nid)` for the row rather than carry a nid->row
            # dict (which cost ~63 B/node -- a hash table plus a boxed int per node).
            # `order` is the argsort of the scanned nids; it is transient and dropped
            # here, leaving only `_scan_ids` (pointers to nid strings already resident
            # in `_ids`, ~9 B/node) as new resident state. `_scan_ids` is built here
            # and never mutated again, so it stays column-aligned across overlay/graft.
            order = sorted(range(len(self._ids)), key=self._ids.__getitem__)
            self._scan_ids = [self._ids[p] for p in order]

            def _reorder(col):
                return array("i", (col[p] for p in order))

            self._kind_col = _reorder(self._kind_col)
            self._label_col = _reorder(self._label_col)
            self._h_file = _reorder(self._h_file)
            self._h_absfile = _reorder(self._h_absfile)
            self._h_owner = _reorder(self._h_owner)
            self._h_fn = _reorder(self._h_fn)
            self._h_sl = _reorder(self._h_sl)
            self._h_el = _reorder(self._h_el)
            self._h_so = _reorder(self._h_so)
            self._h_eo = _reorder(self._h_eo)
            del order
        # The scan used to arrive in id order from `ORDER BY n.id`, which every bucket
        # inherited by construction; the stored id is coded now and that order is not
        # the real one, so sort what the order was doing for us. Buckets included: a
        # tool that lists a file's nodes should list them the same way twice.
        self._ids.sort()
        # `by_label` is intentionally absent in columnar mode (materialized lazily, and
        # it sorts its own buckets there); sort only the resident dicts.
        resident = (self.by_kind, self.by_file, self.by_owner)
        if self._bl_store is not None:
            resident = (*resident, self._bl_store)
        for buckets in resident:
            for ids in buckets.values():
                ids.sort()

    def _init_by_label(self) -> None:
        """Set up ``by_label`` storage for whichever backend is active.

        Dict mode holds the inverted map resident (``_bl_store``) and populates it
        during the scan. Columnar mode leaves it unbuilt (``_bl_store is None``) and
        collects only overlay/graft-derived (nid, label) pairs in ``_bl_pending``; the
        full map is reconstructed on first access from the label column. This keeps the
        61 MB inverted map (452k tiny per-label lists at ~37 B/node) off the
        memory-critical build path, which never reads it -- only interactive navigation
        does.
        """
        if self._columnar:
            self._bl_store = None
            self._bl_pending: list = []
        else:
            self._bl_store = defaultdict(list)
            self._bl_pending = None

    @property
    def by_label(self) -> dict:
        """Label -> sorted nids. Resident in dict mode; lazily rebuilt in columnar mode.

        Byte-identical to the eagerly built map: base nids grouped from the label column
        (each bucket ascending-nid, as the old sort pass left them), then overlay/graft
        additions appended in arrival order -- exactly what ``attach_overlay``/``graft``
        did to the live dict, which were never re-sorted after append.
        """
        if self._bl_store is None:
            self._bl_store = self._materialize_by_label()
        return self._bl_store

    def _materialize_by_label(self) -> dict:
        d: dict = defaultdict(list)
        vocab, lc = self._label_vocab, self._label_col
        for i, nid in enumerate(self._scan_ids):
            d[vocab[lc[i]]].append(nid)
        for ids in d.values():
            ids.sort()
        for nid, label in self._bl_pending:
            d[label].append(nid)
        return d

    def _bl_add(self, nid, label) -> None:
        """Record a derived node's label for ``by_label`` under either backend."""
        if self._bl_pending is not None:  # columnar: stash; fold into a live map if any
            self._bl_pending.append((nid, label))
            if self._bl_store is not None:
                self._bl_store[label].append(nid)
        else:
            self._bl_store[label].append(nid)

    def _row(self, nid):
        """Column row for a scanned nid via bisect on sorted ``_scan_ids``, else None.

        Derived/overlay nids are never scanned, so they are absent from ``_scan_ids``,
        miss the exact-match check, and read as None -- exactly as they missed the
        ``_row_by_id`` dict this replaced.
        """
        ids = self._scan_ids
        i = bisect_left(ids, nid)
        if i < len(ids) and ids[i] == nid:
            return i
        return None

    def _kind(self, nid):
        """A node's kind, from the dict or the columnar backend (byte-identical)."""
        if self._columnar:
            r = self._row(nid)
            return None if r is None else self._kind_vocab[self._kind_col[r]]
        return self._kind_by_id.get(nid)

    def _label(self, nid):
        """A node's label, from the dict or the columnar backend (byte-identical)."""
        if self._columnar:
            r = self._row(nid)
            return None if r is None else self._label_vocab[self._label_col[r]]
        return self._label_by_id.get(nid)

    def _header(self, nid) -> dict:
        """Rebuild a node's promoted-scalar header dict from its stored tuple.

        The map holds tuples to stay compact (see ``_build_maps``); readers still
        want the ``{field: value}`` shape, in the original insertion order so any
        serialization stays byte-identical. Missing nodes read as an empty dict,
        matching the previous ``_header_by_id.get(nid, {})``.
        """
        if self._columnar:
            r = self._row(nid)
            return {} if r is None else self._header_row(r)
        row = self._header_by_id.get(nid)
        if row is None:
            return {}
        return dict(zip(_HEADER_FIELDS, row))

    def _header_row(self, r) -> dict:
        """Rebuild the header dict from an already-resolved columnar row ``r``.

        Split out of ``_header`` so a projection that has already bisected for the
        row (``_project``) rebuilds the header without bisecting again.
        """
        hv = self._hstr_vocab

        def _s(code):
            return None if code < 0 else hv[code]

        def _i(v):
            return None if v < 0 else v

        return dict(zip(_HEADER_FIELDS, (
            _s(self._h_file[r]), _s(self._h_absfile[r]),
            _i(self._h_sl[r]), _i(self._h_el[r]),
            _i(self._h_so[r]), _i(self._h_eo[r]),
            _s(self._h_owner[r]), _s(self._h_fn[r]))))

    def _project(self, nid) -> dict:
        """``{id, kind, label, properties}`` for one node.

        Byte-identical to building the dict from ``_kind``/``_label``/``_header``
        separately, but in columnar mode it resolves the row once instead of
        bisecting three times -- the shape every header projection returns.
        """
        if self._columnar:
            r = self._row(nid)
            if r is None:
                return {"id": nid, "kind": None, "label": None, "properties": {}}
            return {"id": nid,
                    "kind": self._kind_vocab[self._kind_col[r]],
                    "label": self._label_vocab[self._label_col[r]],
                    "properties": self._header_row(r)}
        return {"id": nid, "kind": self._kind_by_id.get(nid),
                "label": self._label_by_id.get(nid),
                "properties": self._header(nid)}

    def ensure_maps(self) -> None:
        """Build navigation buckets after a deferred whole-graph operation.

        Pass 2 only needs columnar scans plus the compact projection used by the
        catalog binder. Building four navigation maps before materializing a million
        nodes duplicates graph-sized id references during the peak. Deferred callers
        opt into the maps immediately before a pass-3 translator or navigation query
        needs them.
        """
        if not self._maps_deferred:
            return
        overlay = self._overlay
        self._build_maps()
        self._maps_deferred = False
        if overlay is not None:
            # `_build_maps` covers resident Kùzu rows; reattach additive rows after
            # rebuilding so warm sidecars are represented in the same buckets too.
            self.attach_overlay(overlay)

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
        # `by_kind` is about to grow by the overlay's derived nodes, so anything
        # memoized off it describes the index as it was a moment ago.
        self._kind_ids.clear()
        self._derived_out = defaultdict(list)
        self._derived_in = defaultdict(list)
        overlay_argument_edges = defaultdict(list)
        for edge in overlay.derived_edges:
            self._derived_out[edge["source"]].append(edge)
            self._derived_in[edge["target"]].append(edge)
            if edge.get("kind") == "HAS_ARGUMENT":
                overlay_argument_edges[edge["source"]].append(edge)
        self._overlay_argument_edges = overlay_argument_edges
        for node in overlay.derived_nodes:
            nid = node["id"]
            if nid in self._node_cache:
                continue
            self._ids.append(nid)
            self.by_kind[node.get("kind")].append(nid)
            self._bl_add(nid, node.get("label"))
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
        if self._maps_deferred:
            result = self._conn.execute("MATCH (n:Node) RETURN count(n)")
            count = int(result.get_next()[0]) if result.has_next() else 0
            overlay = getattr(self, "_overlay", None)
            return count + len(overlay.derived_nodes) if overlay is not None else count
        return len(self._ids)

    def _all_ids(self):
        return list(self._ids)

    # -- primitives ---------------------------------------------------------

    @timeit
    def _run(self, cypher: str, params: dict):
        """Execute ``cypher``, preparing it at most once per process.

        Only for the parameterized hot-path queries. A one-shot bulk scan gains nothing
        from being cached and would hold a statement alive for no reason, so those keep
        calling ``_conn.execute`` directly.
        """
        statement = self._prepared.get(cypher)
        if statement is None:
            statement = self._prepared[cypher] = self._conn.prepare(cypher)
        return self._conn.execute(statement, params)

    @timeit
    def _node(self, node_id: str) -> Optional[dict]:
        if node_id in self._node_cache:
            return self._node_cache[node_id]
        res = self._run(
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

    @timeit
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
        res = self._run(cypher, {"id": encode_id(node_id, self._id_codes)})
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
        # Not gated on the overlay any more: `graft` fills these from a cone fold, which
        # produces no sidecar. Reading derived edges only when a sidecar happened to be
        # attached was the same condition twice by coincidence, and it stopped being a
        # coincidence the moment a second thing could populate them.
        derived = self._derived_in if reverse else self._derived_out
        if derived:
            edges.extend({"source": e["source"], "target": e["target"],
                          "kind": e["kind"], "properties": dict(e.get("properties") or {})}
                         for e in derived.get(node_id, ()))
        # Most adjacency triples are unique.  Avoid encoding every properties
        # blob just to establish a tie-break that is only needed for duplicate
        # (kind, source, target) edges.
        _sort_materialized_edges(edges)
        cache[node_id] = edges
        return edges

    def graft(self, nodes, edges) -> int:
        """Merge derived nodes and edges into the live index. Returns edges added.

        What a cone fold hands back. `attach_overlay` cannot carry it: an ``Overlay``
        validates every edge kind against ``DERIVED_EDGE_KINDS``, which is the guard
        vocabulary, and the dataflow tier's ``POINTS_TO``/``READS_HEAP``/
        ``VALUE_FLOWS_TO`` are deliberately not in it. Widening that set to let a fold
        through would also let a hand-written sidecar through, and the whole point of
        that check is that a sidecar is untrusted input while a fold is our own output.

        Additive and idempotent. An edge already present is skipped on identity, so
        folding two overlapping cones grafts each shared edge once and the second cone
        costs only what it adds.
        """
        if not self._derived_out:
            self._derived_out = defaultdict(list)
            self._derived_in = defaultdict(list)
        for node in nodes:
            nid = node["id"]
            if nid in self._node_cache and self._node_cache[nid] is not None:
                continue
            self._node_cache[nid] = node
            if nid not in self._grafted_nodes:
                self._grafted_nodes.add(nid)
                self._ids.append(nid)
                self.by_kind[node.get("kind")].append(nid)
                self._bl_add(nid, node.get("label"))
                props = node.get("properties") or {}
                path = props.get("absolute_file") or props.get("file")
                if path:
                    self.by_file[path].append(nid)
                owner = props.get("owner_function_id") or props.get("function_id")
                if owner:
                    self.by_owner[owner].append(nid)
        added = 0
        for edge in edges:
            key = (edge["source"], edge["target"], edge["kind"],
                   encode_document(edge.get("properties") or {}))
            if key in self._grafted_edges:
                continue
            self._grafted_edges.add(key)
            self._derived_out[edge["source"]].append(edge)
            self._derived_in[edge["target"]].append(edge)
            added += 1
        # The adjacency caches answered these nodes before the graft and would keep
        # answering the old way; the node cache is deliberately *not* cleared, because
        # it is what the loop above just populated.
        self._out_cache.clear()
        self._in_cache.clear()
        self._kind_ids.clear()
        self._ids.sort()
        return added

    def degrees(self) -> dict:
        """``{node_id: outgoing + incoming}`` for every node that has an edge.

        Two aggregate scans instead of two queries per node. `build_index` wants the
        degree of every indexed declaration to break ties between a definition and its
        prototype, and asking edge by edge made `search`'s first call issue ten thousand
        queries to compute a number the store can count in one pass.

        Counted the same way `_edges` counts, deliberately: every relationship type
        through the untyped ``-[e]->`` match, plus the overlay's derived edges when one
        is attached. ``DeferredEdge`` stays out because it is a node table awaiting a
        recompiled endpoint, and `_edges` does not see it either.
        """
        degree: dict = defaultdict(int)
        for column in ("a.id", "b.id"):
            res = self._conn.execute(
                f"MATCH (a:Node)-[e]->(b:Node) RETURN {column}, count(*)")
            while res.has_next():
                coded, count = res.get_next()
                degree[decode_id(coded, self._id_prefixes)] += count
        if self._overlay is not None:
            for derived in (self._derived_out, self._derived_in):
                for node_id, edges in derived.items():
                    degree[node_id] += len(edges)
        return degree

    # -- GraphIndex accessor surface ----------------------------------------

    def _accepted(self, edge: dict, accepted) -> bool:
        return (edge.get("kind") in accepted
                or self.semantic_edge_kind(edge) in accepted)

    @timeit
    def targets(self, source: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self._edges(source, reverse=False):
            if self._accepted(edge, accepted):
                node = self._node(edge["target"])
                if node is not None:
                    yield node

    @timeit
    def sources(self, target: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self._edges(target, reverse=True):
            if self._accepted(edge, accepted):
                node = self._node(edge["source"])
                if node is not None:
                    yield node

    @timeit
    def outgoing_of_kind(self, source: str, *edge_kinds: str) -> tuple:
        accepted = frozenset(edge_kinds)
        return tuple(e for e in self._edges(source, reverse=False)
                     if self._accepted(e, accepted))

    @timeit
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

    @timeit
    def nodes_owned_by(self, owner_id: str, *kinds: str) -> tuple:
        """The nodes a declaration owns, optionally narrowed to some kinds first.

        Narrowing before fetching is the whole point of the parameter. Ownership and
        kind are both already in memory from `_build_maps`, so the intersection costs no
        query, and it is the difference between fetching the four call sites a function
        makes and fetching all six hundred nodes of its body to throw 596 of them away.
        """
        owned = self.by_owner.get(owner_id, ())
        if kinds:
            wanted = self._ids_of_kind(kinds)
            owned = [nid for nid in owned if nid in wanted]
        if len(owned) > 1:
            self._warm_nodes(owned)
        return tuple(self._node(nid) for nid in owned)

    @timeit
    def nodes_owned_headers(self, owner_id: str) -> tuple[dict, ...]:
        """Return cheap body headers without inflating property tails.

        Header properties are promoted scalar values owned by this read-only
        index.  Translation only reads them, so sharing the existing dictionary
        avoids copying one properties mapping for every owned node on every
        function projection.
        """
        owned = self.by_owner.get(owner_id, ())
        return tuple(self._project(nid) for nid in owned)

    def node_headers(self, node_ids) -> tuple[dict, ...]:
        return tuple(self._project(nid) for nid in node_ids)

    @timeit
    def metadata_by_kind(self, kinds) -> dict[str, dict]:
        """Read only the property tails for a small set of node kinds."""
        result = {}
        res = self._conn.execute(
            "MATCH (n:Node) WHERE n.kind IN $kinds RETURN n.id, n.props",
            {"kinds": list(dict.fromkeys(kinds))},
        )
        while res.has_next():
            nid, props = res.get_next()
            result[decode_id(nid, self._id_prefixes)] = _restore(
                props, self._props_dict, restore_defaults=False)
        return result

    def _ids_of_kind(self, kinds) -> frozenset:
        key = frozenset(kinds)
        cached = self._kind_ids.get(key)
        if cached is None:
            cached = self._kind_ids[key] = frozenset(
                nid for kind in key for nid in self.by_kind.get(kind, ()))
        return cached

    @timeit
    def _warm_nodes(self, node_ids) -> None:
        """Fetch a batch of nodes into the node cache with one query.

        A function body is hundreds of nodes and `_node` is one query each, which is how
        `callees` on a large declaration turned into 74,127 round trips. The rows come
        back unordered and are keyed by id on the way into the cache, so this is purely a
        prefetch: `_node` still answers, and answers the same, if this never ran.
        """
        wanted = [nid for nid in node_ids if nid not in self._node_cache]
        if not wanted:
            return
        # Keep Kùzu's IN-list planning bounded.  A single callable warm-up can
        # contain tens of thousands of ids; several moderate batches are faster
        # and use less temporary query memory than one giant parameter list.
        if len(wanted) > 5000:
            for start in range(0, len(wanted), 5000):
                self._warm_nodes(wanted[start:start + 5000])
            return
        coded = [encode_id(nid, self._id_codes) for nid in wanted]
        res = self._run(
            f"MATCH (n:Node) WHERE n.id IN $ids RETURN n.id, n.kind, n.label, "
            f"{_MERGED_SELECT}, n.props", {"ids": coded},
        )
        while res.has_next():
            row = res.get_next()
            node_id = decode_id(row[0], self._id_prefixes)
            kind, label = row[1:3]
            properties = _restore_node_props(row[3:-1], row[-1], self._props_dict,
                                             self._id_prefixes)
            if self._overlay is not None:
                properties.update(self._overlay.node_props.get(node_id) or {})
            self._node_cache[node_id] = {"id": node_id, "kind": kind, "label": label,
                                         "properties": properties}
        # A wanted id with no row is a genuine absence, and caching that is what stops
        # `_node` from re-querying for it one at a time straight after this returns.
        for node_id in wanted:
            self._node_cache.setdefault(node_id, None)

    @timeit
    def _warm_nodes_by_owner(self, owner_ids, kinds=None) -> None:
        """Warm owned flow nodes with one owner/kind columnar scan.

        Passing every node id through a large ``IN`` list makes Kùzu repeatedly
        plan primary-key probes.  ``owner_function_id`` and ``kind`` are
        promoted columns, so one scan over the selected definition owners is
        both smaller and cheaper while producing the identical node cache.
        """
        owners = [owner for owner in owner_ids if owner]
        accepted = list(dict.fromkeys(kinds or ()))
        if not owners:
            return
        kind_clause = " AND n.kind IN $kinds" if accepted else ""
        params = {"owners": owners}
        if accepted:
            params["kinds"] = accepted
        res = self._conn.execute(
            f"MATCH (n:Node) WHERE n.owner_function_id IN $owners"
            f"{kind_clause} RETURN n.id, n.kind, n.label, {_MERGED_SELECT}, n.props",
            params,
        )
        while res.has_next():
            row = res.get_next()
            node_id = decode_id(row[0], self._id_prefixes)
            kind, label = row[1:3]
            properties = _restore_node_props(
                row[3:-1], row[-1], self._props_dict, self._id_prefixes)
            if self._overlay is not None:
                properties.update(self._overlay.node_props.get(node_id) or {})
            self._node_cache[node_id] = {
                "id": node_id, "kind": kind, "label": label,
                "properties": properties,
            }

    @timeit
    def stream_nodes_by_owner(self, owner_ids, callback, kinds=None) -> None:
        """Feed full owned-node records to ``callback`` one owner at a time.

        The query still scans the selected owners once, but unlike ``_warm_nodes_by_owner``
        it does not retain every body in ``_node_cache``. Consumers can analyze and evict the
        current owner's records before the next group arrives.
        """
        owners = [owner for owner in owner_ids if owner]
        accepted = list(dict.fromkeys(kinds or ()))
        if not owners:
            return
        kind_clause = " AND n.kind IN $kinds" if accepted else ""
        params = {"owners": owners}
        if accepted:
            params["kinds"] = accepted
        merged_without_owner = ", ".join(
            f"n.{column}" for column in _MERGED_COLUMNS
            if column != "owner_function_id")
        res = self._conn.execute(
            f"MATCH (n:Node) WHERE n.owner_function_id IN $owners"
            f"{kind_clause} RETURN n.owner_function_id, n.id, n.kind, n.label, "
            f"{merged_without_owner}, n.props ORDER BY n.owner_function_id",
            params,
        )
        current_owner = None
        batch = []

        def flush():
            nonlocal batch, current_owner
            if current_owner is not None and batch:
                callback(current_owner, batch)
            batch = []

        while res.has_next():
            row = res.get_next()
            owner = row[0]
            if owner != current_owner:
                flush()
                current_owner = owner
            node_id = decode_id(row[1], self._id_prefixes)
            kind, label = row[2:4]
            selected = iter(row[4:-1])
            columns = [row[0] if column == "owner_function_id" else next(selected)
                       for column in _MERGED_COLUMNS]
            properties = _restore_node_props(
                columns, row[-1], self._props_dict, self._id_prefixes)
            if self._overlay is not None:
                properties.update(self._overlay.node_props.get(node_id) or {})
            node = {"id": node_id, "kind": kind, "label": label,
                    "properties": properties}
            self._node_cache[node_id] = node
            batch.append(node)
        flush()

    @timeit
    def _node_spans(self, node_ids, batch_size: int = 5000) -> dict[str, dict]:
        """Fetch only source-span columns for a bounded set of node ids.

        Flow guard/region classification needs file offsets, not full node property
        blobs.  Using ``_warm_nodes`` for that job inflates every tail and defeats
        the lazy disk-backed Pass 3 path.
        """
        wanted = tuple(dict.fromkeys(node_ids))
        spans = {}
        for start in range(0, len(wanted), batch_size):
            batch = wanted[start:start + batch_size]
            coded = [encode_id(nid, self._id_codes) for nid in batch]
            res = self._run(
                "MATCH (n:Node) WHERE n.id IN $ids "
                "RETURN n.id, n.file, n.absolute_file, n.start_offset, n.end_offset",
                {"ids": coded},
            )
            while res.has_next():
                nid, file, absolute_file, begin, end = res.get_next()
                spans[decode_id(nid, self._id_prefixes)] = {
                    "file": file, "absolute_file": absolute_file,
                    "start_offset": begin, "end_offset": end,
                }
        return spans

    @timeit
    def _edges_with_target_spans(self, edge_kinds) -> list[tuple[str, str, str, dict]]:
        """Read selected edges and target spans without inflating node properties."""
        accepted = frozenset(edge_kinds)
        rows = []
        # Most high-volume edge kinds use the generic EDGE table and are
        # filtered by semantic_kind below.  Branch relationships are stored as
        # typed Kùzu relations, however, and are not in _HOT_SET; omitting them
        # makes the lazy branch-region index appear empty.
        for kind in accepted & _HOT_SET:
            res = self._conn.execute(
                f"MATCH (a:Node)-[e:{kind}]->(b:Node) "
                "RETURN a.id, b.id, b.file, b.absolute_file, "
                "b.start_offset, b.end_offset"
            )
            while res.has_next():
                src, tgt, file, absolute_file, begin, end = res.get_next()
                rows.append((decode_id(src, self._id_prefixes),
                             decode_id(tgt, self._id_prefixes), kind,
                             {"file": file, "absolute_file": absolute_file,
                              "start_offset": begin, "end_offset": end}))
        for kind in accepted - _HOT_SET:
            try:
                res = self._conn.execute(
                    f"MATCH (a:Node)-[e:{kind}]->(b:Node) "
                    "RETURN a.id, b.id, b.file, b.absolute_file, "
                    "b.start_offset, b.end_offset"
                )
            except RuntimeError:
                # Stores are allowed to omit optional overlay relationships;
                # Kùzu reports a missing typed table as a binder error.
                continue
            while res.has_next():
                src, tgt, file, absolute_file, begin, end = res.get_next()
                rows.append((decode_id(src, self._id_prefixes),
                             decode_id(tgt, self._id_prefixes), kind,
                             {"file": file, "absolute_file": absolute_file,
                              "start_offset": begin, "end_offset": end}))
        res = self._conn.execute(
            "MATCH (a:Node)-[e:EDGE]->(b:Node) "
            "WHERE e.semantic_kind IN $kinds OR e.kind IN $kinds "
            "RETURN a.id, b.id, e.kind, e.semantic_kind, b.file, b.absolute_file, "
            "b.start_offset, b.end_offset", {"kinds": list(accepted)})
        while res.has_next():
            src, tgt, kind, semantic_kind, file, absolute_file, begin, end = res.get_next()
            kind = semantic_kind or kind
            rows.append((decode_id(src, self._id_prefixes),
                         decode_id(tgt, self._id_prefixes), kind,
                         {"file": file, "absolute_file": absolute_file,
                          "start_offset": begin, "end_offset": end}))
        # Enrichment overlays (including branch-region inference) are held as
        # derived adjacency rather than Kùzu rows.  Include them here using the
        # already-indexed target headers, keeping this helper property-light.
        for source, edges in self._derived_out.items():
            for edge in edges:
                kind = edge.get("kind")
                if kind not in accepted:
                    continue
                target = self._header(edge.get("target"))
                rows.append((source, edge.get("target"), kind, {
                    "file": target.get("file"),
                    "absolute_file": target.get("absolute_file"),
                    "start_offset": target.get("start_offset"),
                    "end_offset": target.get("end_offset"),
                }))
        return rows

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

    @timeit
    def incoming_edges_for_targets(self, targets, edge_kind: str) -> tuple[dict, ...]:
        """Return one value-flow batch for many target ids.

        Candidate evidence walks backwards from catalog sinks.  Issuing one Kùzu
        traversal per sink/value made the structural Pass 2 bind pay thousands of
        query plans.  This keeps the same edge shape while using bounded primary-key
        batches; derived overlay edges are appended so the result remains identical
        after the dataflow sidecar is attached.
        """
        wanted = tuple(dict.fromkeys(value for value in targets if value))
        if not wanted:
            return ()
        result = []
        for start in range(0, len(wanted), 5000):
            batch = wanted[start:start + 5000]
            coded = [encode_id(value, self._id_codes) for value in batch]
            if edge_kind in _HOT_SET:
                # Hot relations have their own typed Kùzu table, so querying
                # EDGE here misses the base value-flow rows entirely.  The
                # typed relation also avoids a semantic_kind predicate and is
                # the indexed representation used by the normal adjacency
                # path.
                query = (
                    f"MATCH (a:Node)-[e:{edge_kind}]->(b:Node) "
                    "WHERE b.id IN $ids "
                    "RETURN a.id, b.id, e.props"
                )
                res = self._conn.execute(query, {"ids": coded})
                while res.has_next():
                    source, target, props = res.get_next()
                    result.append({
                        "source": decode_id(source, self._id_prefixes),
                        "target": decode_id(target, self._id_prefixes),
                        "kind": edge_kind,
                        "properties": _restore(props, self._props_dict),
                    })
                continue
            query = (
                "MATCH (a:Node)-[e:EDGE]->(b:Node) "
                "WHERE e.semantic_kind = $kind AND b.id IN $ids "
                "RETURN a.id, b.id, e.kind, e.props"
            )
            res = self._conn.execute(query, {"kind": edge_kind, "ids": coded})
            while res.has_next():
                source, target, kind, props = res.get_next()
                result.append({
                    "source": decode_id(source, self._id_prefixes),
                    "target": decode_id(target, self._id_prefixes),
                    "kind": kind or edge_kind,
                    "properties": _restore(props, self._props_dict),
                })
        if self._overlay is not None:
            result.extend(
                dict(edge) for edge in self._overlay.derived_edges
                if edge.get("kind") == edge_kind
                and edge.get("target") in set(wanted)
            )
        result.sort(key=_EDGE_SORT)
        return tuple(result)

    @timeit
    def argument_edges_by_source(self) -> dict[str, tuple[dict, ...]]:
        """Return the small call-argument relation indexed by call id.

        Flow translation asks for HAS_ARGUMENT adjacency once per call.  On a
        large store that turns a fixed 76k-edge relation into thousands of
        individual Kùzu plans.  This scan reads only the edge properties and
        keeps the same ``{source: ({source,target,kind,properties}, ...)}``
        shape accepted by ``_arg_records``; value-flow edges remain lazy.
        """
        cached = getattr(self, "_argument_edges_cache", None)
        if cached is not None:
            return cached
        indexed = defaultdict(list)
        res = self._conn.execute(
            "MATCH (a:Node)-[e:EDGE]->(b:Node) "
            "WHERE e.semantic_kind = 'HAS_ARGUMENT' OR e.kind = 'HAS_ARGUMENT' "
            "RETURN a.id, b.id, e.kind, e.semantic_kind, e.props"
        )
        while res.has_next():
            source, target, kind, semantic_kind, props = res.get_next()
            source = decode_id(source, self._id_prefixes)
            target = decode_id(target, self._id_prefixes)
            indexed[source].append({
                "source": source, "target": target,
                "kind": semantic_kind or kind or "HAS_ARGUMENT",
                "properties": _restore(props, self._props_dict),
            })
        for source, edges in self._overlay_argument_edges.items():
            indexed[source].extend(dict(edge) for edge in edges)
        for edges in indexed.values():
            _sort_materialized_edges(edges)
        self._argument_edges_cache = {
            source: tuple(edges) for source, edges in indexed.items()
        }
        return self._argument_edges_cache

    @timeit
    def atropos_projection(self) -> dict:
        """Return only the records needed to build Atropos's neutral symbol index.

        Catalog binding needs call/construct/write/argument records, not the full CPG.
        Export that narrow projection directly from Kùzu so a disk-backed Pass 2 can
        avoid scanning the million-node materialized graph just to discover callsites.
        The returned shape is intentionally an ordinary graph fragment: the existing
        canonical adapter remains the compatibility and parity oracle.
        """
        kinds = ["argument", "call", "construct", "write"]
        nodes = {}
        res = self._conn.execute(
            f"MATCH (n:Node) WHERE n.kind IN $kinds "
            f"RETURN n.id, n.kind, n.label, {_MERGED_SELECT}, n.props",
            {"kinds": kinds},
        )
        while res.has_next():
            row = res.get_next()
            nid = decode_id(row[0], self._id_prefixes)
            nodes[nid] = {
                "id": nid, "kind": row[1], "label": row[2],
                "properties": _restore_node_props(
                    row[3:-1], row[-1], self._props_dict, self._id_prefixes),
            }

        edges = []
        for group in self.argument_edges_by_source().values():
            edges.extend(group)

        # The cursor-factory fallback needs only labels of write targets. Fetch
        # those targets in one bounded IN query rather than broadening the scan.
        target_ids = {
            (node.get("properties") or {}).get("target_id")
            for node in nodes.values() if node.get("kind") == "write"
        }
        target_ids.discard(None)
        if target_ids:
            coded = [encode_id(nid, self._id_codes) for nid in target_ids]
            res = self._conn.execute(
                "MATCH (n:Node) WHERE n.id IN $ids RETURN n.id, n.kind, n.label",
                {"ids": coded},
            )
            while res.has_next():
                coded_id, kind, label = res.get_next()
                nid = decode_id(coded_id, self._id_prefixes)
                nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label,
                                       "properties": {}})
        return {"nodes": tuple(nodes.values()), "edges": tuple(edges)}

    @timeit
    def value_targets_by_source(self) -> dict[str, tuple[str, ...]]:
        """Compactly index the hot VALUE_FLOWS_TO relation by source id.

        The flow translator follows only targets for short assignment walks.  Keeping
        the relation as source -> target tuples avoids one Kùzu adjacency plan per
        call while avoiding the much larger edge/property dictionaries used by the
        general graph materializer.
        """
        cached = getattr(self, "_value_targets_cache", None)
        if cached is not None:
            return cached
        indexed = defaultdict(list)
        res = self._conn.execute(
            "MATCH (a:Node)-[e:VALUE_FLOWS_TO]->(b:Node) RETURN a.id, b.id"
        )
        while res.has_next():
            source, target = res.get_next()
            indexed[decode_id(source, self._id_prefixes)].append(
                decode_id(target, self._id_prefixes))
        if self._overlay is not None:
            for edge in self._overlay.derived_edges:
                if edge.get("kind") == "VALUE_FLOWS_TO":
                    indexed[edge["source"]].append(edge["target"])
        self._value_targets_cache = {
            source: tuple(sorted(targets))
            for source, targets in indexed.items()
        }
        return self._value_targets_cache

    @timeit
    def return_value_sources_by_target(self) -> dict[str, tuple[dict, ...]]:
        """Bulk-index return-value source nodes by their function target."""
        cached = getattr(self, "_return_value_sources_cache", None)
        if cached is not None:
            return cached
        indexed = defaultdict(list)
        merged_select = ", ".join(f"a.{column}" for column in _MERGED_COLUMNS)
        res = self._conn.execute(
            "MATCH (a:Node)-[e:EDGE]->(b:Node) "
            "WHERE e.semantic_kind = 'RETURNS_VALUE' OR e.kind = 'RETURNS_VALUE' "
            f"RETURN b.id, a.id, a.kind, a.label, {merged_select}, a.props"
        )
        while res.has_next():
            row = res.get_next()
            target = decode_id(row[0], self._id_prefixes)
            source = decode_id(row[1], self._id_prefixes)
            kind, label = row[2:4]
            properties = _restore_node_props(row[4:-1], row[-1], self._props_dict,
                                             self._id_prefixes)
            indexed[target].append({"id": source, "kind": kind, "label": label,
                                    "properties": properties})
        self._return_value_sources_cache = {
            target: tuple(sorted(nodes, key=lambda node: node["id"]))
            for target, nodes in indexed.items()
        }
        return self._return_value_sources_cache

    @timeit
    def invoke_edges_by_source(self) -> dict[str, tuple[dict, ...]]:
        """Bulk-index the small MAY_INVOKE relation used for indirect dispatch."""
        cached = getattr(self, "_invoke_edges_cache", None)
        if cached is not None:
            return cached
        indexed = defaultdict(list)
        res = self._conn.execute(
            "MATCH (a:Node)-[e:MAY_INVOKE]->(b:Node) "
            "RETURN a.id, b.id, e.props"
        )
        while res.has_next():
            source, target, props = res.get_next()
            source = decode_id(source, self._id_prefixes)
            target = decode_id(target, self._id_prefixes)
            indexed[source].append({"source": source, "target": target,
                                    "kind": "MAY_INVOKE",
                                    "properties": _restore(props, self._props_dict)})
        if self._overlay is not None:
            for edge in self._overlay.derived_edges:
                if edge.get("kind") == "MAY_INVOKE":
                    indexed[edge["source"]].append(dict(edge))
        self._invoke_edges_cache = {
            source: tuple(sorted(edges, key=_EDGE_SORT))
            for source, edges in indexed.items()
        }
        return self._invoke_edges_cache

    @timeit
    def structural_edges(self, kind: str) -> tuple[dict, ...]:
        """Read the minimal fields needed by the object substrate."""
        rows = []
        if kind in _HOT_SET:
            res = self._conn.execute(
                f"MATCH (a:Node)-[e:{kind}]->(b:Node) "
                "RETURN a.id, b.id, e.props"
            )
            while res.has_next():
                source, target, props = res.get_next()
                edge = {"source": decode_id(source, self._id_prefixes),
                        "target": decode_id(target, self._id_prefixes),
                        "kind": kind}
                edge["properties"] = (_restore(props, self._props_dict)
                                      if kind == "AST_CHILD" else {})
                rows.append(edge)
        else:
            res = self._conn.execute(
                "MATCH (a:Node)-[e:EDGE]->(b:Node) "
                "WHERE e.semantic_kind = $kind OR e.kind = $kind "
                "RETURN a.id, b.id, e.kind, e.semantic_kind, e.props",
                {"kind": kind},
            )
            while res.has_next():
                source, target, raw_kind, semantic_kind, props = res.get_next()
                edge = {"source": decode_id(source, self._id_prefixes),
                        "target": decode_id(target, self._id_prefixes),
                        "kind": semantic_kind or raw_kind or kind,
                        "properties": (_restore(props, self._props_dict)
                                       if kind == "AST_CHILD" else {})}
                rows.append(edge)
        if self._overlay is not None:
            rows.extend(dict(edge) for edge in self._overlay.derived_edges
                        if edge.get("kind") == kind)
        return tuple(rows)

    @timeit
    def initializer_edges(self) -> tuple[dict, ...]:
        """Read VALUE_FLOWS_TO edges into the selected function-owned nodes."""
        res = self._conn.execute(
            "MATCH (a:Node)-[e:VALUE_FLOWS_TO]->(b:Node) "
            "RETURN a.id, b.id, e.props"
        )
        rows = []
        while res.has_next():
            source, target, props = res.get_next()
            rows.append({"source": decode_id(source, self._id_prefixes),
                         "target": decode_id(target, self._id_prefixes),
                         "kind": "VALUE_FLOWS_TO",
                         "properties": _restore(props, self._props_dict)})
        return tuple(rows)

    @timeit
    def member_expression_nodes(self) -> tuple[dict, ...]:
        """Columnarly read only expression nodes whose syntax is MemberExpr."""
        cached = getattr(self, "_pass3_member_expression_cache", None)
        if cached is not None:
            return cached
        cached = getattr(self, "_member_expression_cache", None)
        if cached is not None:
            return cached
        merged_select = _MERGED_SELECT
        res = self._conn.execute(
            f"MATCH (n:Node) WHERE n.kind = 'expression' "
            f"RETURN n.id, n.kind, n.label, {merged_select}, n.props"
        )
        members = []
        while res.has_next():
            row = res.get_next()
            node_id = decode_id(row[0], self._id_prefixes)
            properties = _restore_node_props(row[3:-1], row[-1], self._props_dict,
                                             self._id_prefixes)
            if properties.get("syntax_kind") != "MemberExpr":
                continue
            node = {"id": node_id, "kind": row[1], "label": row[2],
                    "properties": properties}
            self._node_cache[node_id] = node
            members.append(node)
        self._member_expression_cache = tuple(members)
        return self._member_expression_cache

    @timeit
    def ast_direct_parents(self, target_kinds) -> dict[str, str]:
        """Return immediate AST parents for the small control-site node set."""
        key = tuple(sorted(set(target_kinds)))
        cache = getattr(self, "_ast_direct_parent_cache", None)
        if cache is None:
            cache = self._ast_direct_parent_cache = {}
        if key in cache:
            return cache[key]
        parents = {}
        res = self._conn.execute(
            "MATCH (a:Node)-[e:EDGE]->(b:Node) "
            "WHERE (e.semantic_kind = 'AST_CHILD' OR e.kind = 'AST_CHILD') "
            "AND b.kind IN $kinds RETURN a.id, b.id",
            {"kinds": list(key)},
        )
        while res.has_next():
            parent, child = res.get_next()
            parent = decode_id(parent, self._id_prefixes)
            child = decode_id(child, self._id_prefixes)
            prior = parents.get(child)
            if prior is None or parent < prior:
                parents[child] = parent
        cache[key] = parents
        return parents

    def flow_edges(self, kinds) -> list:
        return list(self.edges_of_kind(*kinds))

    # -- name indices (v9) --------------------------------------------------

    def _index_rows(self, table: str, columns: tuple, key_column: str,
                    name: Optional[str]) -> dict:
        """Rows of an index table, keyed by name, ids decoded back to real ones.

        One query for the whole table, not one per name. These tables are two orders of
        magnitude smaller than ``Node`` (a few thousand rows on this repo against two
        hundred thousand), and resolution asks about a great many names, so paying once
        beats paying per lookup — and it keeps this the same shape as the in-memory
        answer, which is a whole dict.
        """
        selected = ", ".join(f"r.{column}" for column in columns)
        where, params = "", {}
        if name is not None:
            where, params = f" WHERE r.{key_column} = $name", {"name": name}
        result = self._run(
            f"MATCH (r:{table}){where} RETURN {selected}, r.seq ORDER BY r.seq", params)
        index: dict = {}
        while result.has_next():
            values = result.get_next()
            row = {}
            for column, value in zip(columns, values):
                row[column] = (decode_id(value, self._id_prefixes)
                               if column in _INDEX_ID_COLUMNS and value else value)
            index.setdefault(row[key_column], []).append(row)
        return index

    def decl_index(self, name: Optional[str] = None):
        if name is not None:
            return tuple(self._index_rows(
                "DeclIndex", _DECL_INDEX_COLUMNS, "name", name).get(name, ()))
        return self._index_rows("DeclIndex", _DECL_INDEX_COLUMNS, "name", None)

    def callsite_index(self, name: Optional[str] = None):
        if name is not None:
            return tuple(self._index_rows(
                "CallsiteIndex", _CALLSITE_INDEX_COLUMNS, "callee_name", name
            ).get(name, ()))
        return self._index_rows(
            "CallsiteIndex", _CALLSITE_INDEX_COLUMNS, "callee_name", None)

    def package_inventory(self) -> frozenset:
        names = set()
        for node in self.nodes_of_kind("package"):
            name = (node.get("properties", {}).get("package_name")
                    or node.get("label"))
            if name:
                names.add(name)
        return frozenset(names)
