"""Small indexes for overlays and ecosystem models over canonical graphs."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional


def _bucket_order(item: dict) -> tuple:
    """The order every bucket is kept in, node or edge.

    One key serves both because the two field sets do not overlap: a node answers to
    ``id`` and nothing else, an edge to ``kind``/``source``/``target``.
    """
    return (
        item.get("id", ""), item.get("kind", ""),
        item.get("source", ""), item.get("target", ""),
    )


class GraphIndex:
    """Six lookups over a canonical graph, each sorted the first time it is read.

    Population is eager and cheap. Sorting is neither, and it is what dominates: an
    index over the enriched graph spends most of its construction ordering buckets, and
    an overlay reads one or two of the six. The enrich path never reads ``by_label``,
    ``by_file`` or ``by_owner`` at all, yet paid to order them once per overlay, on a
    graph that grows as the overlays run. Sorting on first read charges each caller only
    for what it asks about, and charges it once.

    This is not a weaker guarantee. Every bucket a caller can observe is ordered exactly
    as before, since the only way to reach one is through the property that orders it.
    The buckets are never written to after construction, so a sort can never go stale.
    """

    _COLLECTIONS = ("by_kind", "by_label", "by_file", "by_owner", "outgoing", "incoming")

    def __init__(self, graph: dict) -> None:
        self.nodes = {node["id"]: node for node in graph.get("nodes", [])}
        self._buckets = {name: defaultdict(list) for name in self._COLLECTIONS}
        by_kind = self._buckets["by_kind"]
        by_label = self._buckets["by_label"]
        by_file = self._buckets["by_file"]
        by_owner = self._buckets["by_owner"]
        outgoing = self._buckets["outgoing"]
        incoming = self._buckets["incoming"]
        for node in self.nodes.values():
            by_kind[node.get("kind")].append(node)
            by_label[node.get("label")].append(node)
            properties = node.get("properties", {})
            path = properties.get("absolute_file") or properties.get("file")
            if path:
                by_file[path].append(node)
            owner = properties.get("owner_function_id") or properties.get("function_id")
            if owner:
                by_owner[owner].append(node)
        for edge in graph.get("edges", []):
            outgoing[edge["source"]].append(edge)
            incoming[edge["target"]].append(edge)

    def __getattr__(self, name: str):
        """Order a bucket on its first mention and then get out of the way.

        ``__getattr__`` runs only when normal lookup fails, so binding the ordered
        collection onto the instance here means this is consulted once per collection
        per index. Everything after that is a plain attribute read, which matters
        because ``targets`` and ``outgoing_of_kind`` reach for ``outgoing`` inside loops
        that run millions of times per enrich; a property would tax every one of them.
        """
        if name not in self._COLLECTIONS:
            raise AttributeError(
                f"{type(self).__name__!r} object has no attribute {name!r}"
            )
        collection = self._buckets[name]
        for values in collection.values():
            values.sort(key=_bucket_order)
        setattr(self, name, collection)
        return collection

    def nodes_of_kind(self, *kinds: str) -> Iterable[dict]:
        return (
            node for kind in kinds for node in self.by_kind.get(kind, ())
        )

    def nodes_named(self, label: str) -> tuple[dict, ...]:
        return tuple(self.by_label.get(label, ()))

    def nodes_in_file(self, path: str) -> tuple[dict, ...]:
        return tuple(self.by_file.get(path, ()))

    def nodes_owned_by(self, owner_id: str) -> tuple[dict, ...]:
        return tuple(self.by_owner.get(owner_id, ()))

    @staticmethod
    def semantic_edge_kind(edge: dict) -> str | None:
        """Return the relationship represented by a tier drill edge.

        Frontend snapshots serialize cross-tier structural facts as
        ``EXPANDS_TO`` and retain their canonical relationship in ``via``.
        Overlays should not need to know which tiers happened to contain the
        endpoints, so query matching treats that value as the semantic kind.
        """
        if edge.get("kind") == "EXPANDS_TO":
            return edge.get("properties", {}).get("via") or "EXPANDS_TO"
        return edge.get("kind")

    def edges_of_kind(self, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edges in self.outgoing.values():
            for edge in edges:
                if edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted:
                    yield edge

    def flow_edges(self, kinds) -> list[dict]:
        """All edges whose *semantic* kind is in ``kinds`` — the single adjacency
        source ``Reachability._build`` consumes. Filtering here (instead of inline in
        the BFS) lets a disk-backed index answer it with one query while the JSON index
        keeps today's exact iteration order (``outgoing`` insertion order, inner lists
        pre-sorted), so the value-flow closure is unchanged."""
        accepted = frozenset(kinds)
        return [
            edge
            for edges in self.outgoing.values()
            for edge in edges
            if self.semantic_edge_kind(edge) in accepted
        ]

    def targets(self, source: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self.outgoing.get(source, []):
            if (edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted) \
                    and edge.get("target") in self.nodes:
                yield self.nodes[edge["target"]]

    def sources(self, target: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self.incoming.get(target, []):
            if (edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted) \
                    and edge.get("source") in self.nodes:
                yield self.nodes[edge["source"]]

    def outgoing_of_kind(self, source: str, *edge_kinds: str) -> tuple[dict, ...]:
        accepted = frozenset(edge_kinds)
        return tuple(
            edge for edge in self.outgoing.get(source, ())
            if edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted
        )

    def incoming_of_kind(self, target: str, *edge_kinds: str) -> tuple[dict, ...]:
        accepted = frozenset(edge_kinds)
        return tuple(
            edge for edge in self.incoming.get(target, ())
            if edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted
        )

    def first_target(self, source: str, *edge_kinds: str) -> Optional[dict]:
        return next(iter(self.targets(source, *edge_kinds)), None)

    def package_inventory(self) -> frozenset[str]:
        return frozenset(
            node.get("properties", {}).get("package_name") or node.get("label")
            for node in self.nodes_of_kind("package")
            if node.get("properties", {}).get("package_name") or node.get("label")
        )
