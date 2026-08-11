"""Deterministic composition of canonical graphs and overlay deltas."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterable, List

from .contract import ContractError


@dataclass
class GraphDelta:
    """Facts added by one compiler, runtime model, framework model or overlay."""

    producer_id: str
    nodes: List[dict] = field(default_factory=list)
    edges: List[dict] = field(default_factory=list)


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
            key = (
                edge["kind"], edge["source"], edge["target"],
                json.dumps(edge.get("properties", {}), sort_keys=True),
            )
            if key not in edge_keys:
                edge_keys.add(key)
                edges.append(edge)

    known = set(nodes)
    dangling = [
        edge for edge in edges
        if edge["source"] not in known or edge["target"] not in known
    ]
    if dangling:
        first = dangling[0]
        raise ContractError(
            f"composed graph has {len(dangling)} dangling edges; first is "
            f"{first['source']} -> {first['target']}"
        )
    return {
        "nodes": sorted(nodes.values(), key=lambda node: node["id"]),
        "edges": sorted(
            edges,
            key=lambda edge: (edge["kind"], edge["source"], edge["target"]),
        ),
    }

