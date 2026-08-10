"""Read side of the Kùzu store: a drop-in for ``Arachne.core.query.GraphIndex`` backed
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
    dict from the ``props`` JSON blob (promoted columns are query-only duplicates and are
    never read back). Cached.
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
from collections import defaultdict
from typing import Iterable, Optional

from Arachne.core.query import GraphIndex
from Arachne.kuzu_store import (
    CONSTANT_PROP_DEFAULTS,
    HOT_REL_KINDS,
    _HOT_SET,
    db_file,
)

try:  # 3.10+ only
    import kuzu  # type: ignore
except Exception:  # pragma: no cover
    kuzu = None

_EDGE_SORT = lambda e: (e.get("kind") or "", e.get("source") or "", e.get("target") or "")


def _restore(props_json: Optional[str]) -> dict:
    props = json.loads(props_json) if props_json else {}
    for key, default in CONSTANT_PROP_DEFAULTS.items():
        if key not in props:
            props[key] = list(default) if isinstance(default, list) else default
    return props


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
        self._node_cache: dict[str, Optional[dict]] = {}
        self._out_cache: dict[str, list] = {}
        self._in_cache: dict[str, list] = {}
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
        res = self._conn.execute(
            "MATCH (n:Node) RETURN n.id, n.kind, n.label, n.file, n.absolute_file, "
            "n.owner_function_id, n.function_id ORDER BY n.id"
        )
        while res.has_next():
            nid, kind, label, file, abs_file, owner, fn = res.get_next()
            self._ids.append(nid)
            self.by_kind[kind].append(nid)
            self.by_label[label].append(nid)
            path = abs_file or file
            if path:
                self.by_file[path].append(nid)
            owner_key = owner or fn
            if owner_key:
                self.by_owner[owner_key].append(nid)

    def _node_count(self) -> int:
        return len(self._ids)

    def _all_ids(self):
        return list(self._ids)

    # -- primitives ---------------------------------------------------------

    def _node(self, node_id: str) -> Optional[dict]:
        if node_id in self._node_cache:
            return self._node_cache[node_id]
        res = self._conn.execute(
            "MATCH (n:Node {id: $id}) RETURN n.kind, n.label, n.props", {"id": node_id}
        )
        node = None
        if res.has_next():
            kind, label, props = res.get_next()
            node = {"id": node_id, "kind": kind, "label": label,
                    "properties": _restore(props)}
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
        res = self._conn.execute(cypher, {"id": node_id})
        edges = []
        while res.has_next():
            label, other, kind_col, sem_col, props = res.get_next()
            kind = kind_col if label == "EDGE" else label
            src, tgt = (other, node_id) if reverse else (node_id, other)
            edges.append({"source": src, "target": tgt, "kind": kind,
                          "properties": _restore(props)})
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
                edges.append({"source": src, "target": tgt, "kind": kind,
                              "properties": _restore(props)})
        res = self._conn.execute(
            "MATCH (a:Node)-[e:EDGE]->(b:Node) WHERE e.semantic_kind IN $kinds "
            "RETURN a.id, b.id, e.kind, e.props", {"kinds": list(accepted)}
        )
        while res.has_next():
            src, tgt, kind, props = res.get_next()
            edges.append({"source": src, "target": tgt, "kind": kind,
                          "properties": _restore(props)})
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
