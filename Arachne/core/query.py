"""Small indexes for overlays and ecosystem models over canonical graphs."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional


class GraphIndex:
    def __init__(self, graph: dict) -> None:
        self.nodes = {node["id"]: node for node in graph.get("nodes", [])}
        self.outgoing = defaultdict(list)
        self.incoming = defaultdict(list)
        for edge in graph.get("edges", []):
            self.outgoing[edge["source"]].append(edge)
            self.incoming[edge["target"]].append(edge)

    def nodes_of_kind(self, *kinds: str) -> Iterable[dict]:
        accepted = frozenset(kinds)
        return (node for node in self.nodes.values() if node.get("kind") in accepted)

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

    def targets(self, source: str, *edge_kinds: str) -> Iterable[dict]:
        accepted = frozenset(edge_kinds)
        for edge in self.outgoing.get(source, []):
            if (edge.get("kind") in accepted or self.semantic_edge_kind(edge) in accepted) \
                    and edge.get("target") in self.nodes:
                yield self.nodes[edge["target"]]

    def first_target(self, source: str, *edge_kinds: str) -> Optional[dict]:
        return next(iter(self.targets(source, *edge_kinds)), None)

    def package_inventory(self) -> frozenset[str]:
        return frozenset(
            node.get("properties", {}).get("package_name") or node.get("label")
            for node in self.nodes_of_kind("package")
            if node.get("properties", {}).get("package_name") or node.get("label")
        )
