"""Deterministic composition of canonical graphs and overlay deltas."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from .contract import ContractError
from .graph_wire import encode_document


@dataclass
class GraphDelta:
    """Facts added by one compiler, runtime model, framework model or overlay."""

    producer_id: str
    nodes: List[dict] = field(default_factory=list)
    edges: List[dict] = field(default_factory=list)


def _edge_key(edge: dict) -> tuple:
    """The identity of an edge for deduplication.

    The property component is deterministic protobuf, matching the graph's internal
    wire format rather than creating a JSON string. ``_EdgeKeys`` is what the two
    composition paths actually use, and computes this key only for edges that need it.
    """
    return (
        edge["kind"], edge["source"], edge["target"],
        encode_document(edge.get("properties", {})),
    )


class _EdgeKeys:
    """The set of edge identities seen so far, serializing properties only on a tie.

    Two edges can only be duplicates if they agree on ``(kind, source, target)``, so
    the properties are what settles a question that the triple has already almost
    always answered. Measured over the 488,261 edges of one real composition: 487,364
    distinct triples, and 1,291 edges (0.264%) sharing a triple with anything at all.
    Keying every edge by a serialized property payload would pay that cost for every
    edge, so the property key is computed only for a colliding triple.

    So the first edge of a triple is remembered as itself, and the properties of that
    first edge are serialized only if a second edge ever arrives on the same triple.
    The predicate is unchanged: an edge is new exactly when no earlier edge had the
    same ``_edge_key``. First occurrence still wins, since acceptance order is
    untouched. Nothing derived is retained for the 99.7% that never collide, which is
    also the point at which the JSON text stopped being the largest thing held live
    across a fold.
    """

    __slots__ = ("_first", "_tied")

    def __init__(self) -> None:
        self._first: dict = {}
        self._tied: dict = {}

    def add(self, edge: dict) -> bool:
        """Record the edge, and say whether it was one we had not seen."""
        triple = (edge["kind"], edge["source"], edge["target"])
        first = self._first.get(triple)
        if first is None:
            self._first[triple] = edge
            return True
        properties = self._tied.get(triple)
        if properties is None:
            # The tie is real, so the first edge finally has to be serialized too.
            properties = {encode_document(first.get("properties", {}))}
            self._tied[triple] = properties
        key = encode_document(edge.get("properties", {}))
        if key in properties:
            return False
        properties.add(key)
        return True


def _dangling(edges: Iterable[dict], known) -> None:
    loose = [
        edge for edge in edges
        if edge["source"] not in known or edge["target"] not in known
    ]
    if loose:
        first = loose[0]
        raise ContractError(
            f"composed graph has {len(loose)} dangling edges; first is "
            f"{first['source']} -> {first['target']}"
        )


def compose(deltas: Iterable[GraphDelta]) -> dict:
    """Union graph deltas while rejecting conflicting stable identities."""
    nodes = {}
    edges = []
    edge_keys = _EdgeKeys()
    for delta in deltas:
        for node in delta.nodes:
            existing = nodes.get(node["id"])
            if existing is not None and existing != node:
                raise ContractError(
                    f"producer {delta.producer_id} conflicts on node {node['id']}"
                )
            nodes[node["id"]] = node
        for edge in delta.edges:
            if edge_keys.add(edge):
                edges.append(edge)

    _dangling(edges, nodes)
    return {
        "nodes": sorted(nodes.values(), key=_NODE_ORDER),
        "edges": sorted(edges, key=_EDGE_ORDER),
    }


def _NODE_ORDER(node: dict):
    return node["id"]


def _EDGE_ORDER(edge: dict):
    return edge["kind"], edge["source"], edge["target"]


class GraphAccumulator:
    """Fold graph deltas incrementally, paying per delta rather than per graph.

    ``compose`` re-keys every edge, re-compares every node and re-checks every endpoint
    each time it is called, so folding N overlays by handing the accumulated graph back
    in as a delta costs O(N x graph). An overlay that contributes one node and five
    edges still pays for a full pass over half a million of them.

    This holds the node map, the edge dedup keys and the edge list live across deltas,
    so a delta costs what the delta is worth. Only the output ordering is still paid per
    view, and only when a view is actually asked for.

    It is not a laxer ``compose``, it is the same composition folded differently. Each
    rule is enforced at the same point and raises the same message. Dangling edges are
    the rule that looks like it cannot be incremental, and it can: a node id is never
    unbound once bound, so an edge whose endpoints resolved against an earlier delta
    cannot come loose against a later one, which leaves the delta's own edges as the
    only ones that can be dangling. The seed is the exception, since a caller may hand
    over a graph whose edges point at nodes only a later delta supplies, so the seed's
    edges wait and are checked with the first delta that arrives.
    """

    def __init__(self, nodes: Iterable[dict] = (), edges: Iterable[dict] = ()) -> None:
        self._nodes: dict = {}
        self._edges: List[dict] = []
        self._edge_keys = _EdgeKeys()
        self._sorted_nodes: Optional[List[dict]] = None
        self._sorted_edges: Optional[List[dict]] = None
        _, self._unchecked = self._absorb(
            GraphDelta("canonical-input", list(nodes), list(edges)),
        )

    def _absorb(self, delta: GraphDelta) -> Tuple[List[dict], List[dict]]:
        """Take in a delta's facts and return the ones this accumulator had not seen.

        The fresh edges are the ones whose endpoints want checking. Both halves are what
        an index following the fold needs, since the whole point of following is to pay
        for the delta rather than for the graph.
        """
        fresh_nodes = []
        for node in delta.nodes:
            existing = self._nodes.get(node["id"])
            if existing is not None and existing != node:
                raise ContractError(
                    f"producer {delta.producer_id} conflicts on node {node['id']}"
                )
            if existing is None:
                self._sorted_nodes = None
                fresh_nodes.append(node)
            self._nodes[node["id"]] = node
        fresh = []
        for edge in delta.edges:
            if self._edge_keys.add(edge):
                fresh.append(edge)
        if fresh:
            self._edges.extend(fresh)
            self._sorted_edges = None
        return fresh_nodes, fresh

    def apply(self, delta: GraphDelta) -> Tuple[List[dict], List[dict]]:
        fresh_nodes, fresh = self._absorb(delta)
        _dangling(self._unchecked + fresh, self._nodes)
        self._unchecked = []
        return fresh_nodes, fresh

    def view(self, *, sorted_output: bool = True) -> dict:
        """Return the accumulated graph, optionally without global sorting.

        The two sorted lists are cached and dropped only by the delta that invalidates
        them, so an overlay whose ``applies`` says no costs nothing, and a delta that
        contributes no node leaves the node ordering alone.  Overlay folds use the
        unsorted form between models: predicates and indexes are order-independent,
        and sorting millions of records after every small delta is pure overhead.  The
        public/default form remains byte-for-byte compatible with ``compose``.
        """
        if not sorted_output:
            return {"nodes": self._nodes.values(), "edges": self._edges}
        if self._sorted_nodes is None:
            self._sorted_nodes = sorted(self._nodes.values(), key=_NODE_ORDER)
        if self._sorted_edges is None:
            self._sorted_edges = sorted(self._edges, key=_EDGE_ORDER)
        return {"nodes": self._sorted_nodes, "edges": self._sorted_edges}

    def result(self) -> dict:
        if self._unchecked:
            _dangling(self._unchecked, self._nodes)
            self._unchecked = []
        return self.view()
