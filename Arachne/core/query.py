"""Small indexes for overlays and ecosystem models over canonical graphs."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional


class GraphIndex:
    def __init__(self, graph: dict) -> None:
        self.nodes = {node["id"]: node for node in graph.get("nodes", [])}
        self.outgoing = defaultdict(list)
        self.incoming = defaultdict(list)
        self.by_kind = defaultdict(list)
        self.by_label = defaultdict(list)
        self.by_file = defaultdict(list)
        self.by_owner = defaultdict(list)
        for node in self.nodes.values():
            self.by_kind[node.get("kind")].append(node)
            self.by_label[node.get("label")].append(node)
            properties = node.get("properties", {})
            path = properties.get("absolute_file") or properties.get("file")
            if path:
                self.by_file[path].append(node)
            owner = properties.get("owner_function_id") or properties.get("function_id")
            if owner:
                self.by_owner[owner].append(node)
        for edge in graph.get("edges", []):
            self.outgoing[edge["source"]].append(edge)
            self.incoming[edge["target"]].append(edge)
        for collection in (
            self.by_kind, self.by_label, self.by_file, self.by_owner,
            self.outgoing, self.incoming,
        ):
            for values in collection.values():
                values.sort(key=lambda item: (
                    item.get("id", ""), item.get("kind", ""),
                    item.get("source", ""), item.get("target", ""),
                ))

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
