"""Deterministic composition of canonical graphs and overlay deltas."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from .contract import ContractError


@dataclass
class GraphDelta:
    """Facts added by one compiler, runtime model, framework model or overlay."""

    producer_id: str
    nodes: List[dict] = field(default_factory=list)
    edges: List[dict] = field(default_factory=list)


def _edge_key(edge: dict) -> tuple:
    """The identity of an edge for deduplication.

    ``json.dumps`` is not an accident here and is not a placeholder for something
    faster. A nested-tuple key over the same properties was measured at 0.739s against
    0.488s for this, over the same 279,046 edges and producing the same number of
    distinct keys. The C implementation wins; the cost that matters is how often this
    is called, not what it costs once.
    """
    return (
        edge["kind"], edge["source"], edge["target"],
        json.dumps(edge.get("properties", {}), sort_keys=True),
    )


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
    edge_keys = set()
    for delta in deltas:
        for node in delta.nodes:
            existing = nodes.get(node["id"])
            if existing is not None and existing != node:
                raise ContractError(
                    f"producer {delta.producer_id} conflicts on node {node['id']}"
                )
            nodes[node["id"]] = node
        for edge in delta.edges:
            key = _edge_key(edge)
            if key not in edge_keys:
                edge_keys.add(key)
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
        self._edge_keys: set = set()
        self._sorted_nodes: Optional[List[dict]] = None
        self._sorted_edges: Optional[List[dict]] = None
        self._unchecked: List[dict] = self._absorb(
            GraphDelta("canonical-input", list(nodes), list(edges)),
        )

    def _absorb(self, delta: GraphDelta) -> List[dict]:
        """Take in a delta's facts and return the edges whose endpoints want checking."""
        for node in delta.nodes:
            existing = self._nodes.get(node["id"])
            if existing is not None and existing != node:
                raise ContractError(
                    f"producer {delta.producer_id} conflicts on node {node['id']}"
                )
            if existing is None:
                self._sorted_nodes = None
            self._nodes[node["id"]] = node
        fresh = []
        for edge in delta.edges:
            key = _edge_key(edge)
            if key not in self._edge_keys:
                self._edge_keys.add(key)
                fresh.append(edge)
        if fresh:
            self._edges.extend(fresh)
            self._sorted_edges = None
        return fresh

    def apply(self, delta: GraphDelta) -> None:
        fresh = self._absorb(delta)
        _dangling(self._unchecked + fresh, self._nodes)
        self._unchecked = []

    def view(self) -> dict:
        """The graph as ``compose`` would have returned it, sorted the same way.

        The two sorted lists are cached and dropped only by the delta that invalidates
        them, so an overlay whose ``applies`` says no costs nothing, and a delta that
        contributes no node leaves the node ordering alone.
        """
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

