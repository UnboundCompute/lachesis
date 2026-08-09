"""Language-neutral overlays over the compiler graph interchange contract."""
from __future__ import annotations

import hashlib
from typing import Dict, List, Tuple

from ..types import CodeGraph, GraphEdge, GraphNode


def stable_id(kind: str, *parts: object) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


def apply_parameter_property_effects(graph: CodeGraph) -> CodeGraph:
    """Instantiate frontend-emitted parameter mutation summaries at calls.

    The frontend owns language syntax and emits ``WRITES_PARAMETER_PROPERTY``.
    This overlay owns context: it creates a caller-specific heap location and
    uses it to resolve later function-valued property calls on the same object.
    """
    nodes: Dict[str, GraphNode] = {node["id"]: node for node in graph["nodes"]}
    edges: List[GraphEdge] = list(graph["edges"])
    edge_keys = {
        (edge["kind"], edge["source"], edge["target"], repr(sorted(edge.get("properties", {}).items())))
        for edge in edges
    }

    def add_edge(kind: str, source: str, target: str, **properties) -> None:
        key = (kind, source, target, repr(sorted(properties.items())))
        if source in nodes and target in nodes and key not in edge_keys:
            edge_keys.add(key)
            edges.append({
                "kind": kind, "source": source, "target": target,
                "properties": properties,
            })

    effects = [edge for edge in edges if edge["kind"] == "WRITES_PARAMETER_PROPERTY"]
    locations: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for effect in effects:
        receiver_position = effect.get("properties", {}).get("receiver_position")
        value_position = effect.get("properties", {}).get("value_position")
        for call in list(nodes.values()):
            properties = call.get("properties", {})
            if call.get("kind") not in {"call", "construct"}:
                continue
            if properties.get("primary_target_id") != effect["source"]:
                continue
            values = properties.get("argument_value_ids", [])
            if not isinstance(receiver_position, int) or not isinstance(value_position, int):
                continue
            if receiver_position >= len(values) or value_position >= len(values):
                continue
            receiver_id, value_id = values[receiver_position], values[value_position]
            if receiver_id not in nodes or value_id not in nodes:
                continue
            location_id = stable_id(
                "context-heap-location", call["id"], receiver_id, effect["target"],
            )
            nodes[location_id] = {
                "id": location_id, "kind": "heap-location",
                "label": f"{nodes[receiver_id]['label']}.{nodes[effect['target']]['label']}",
                "properties": {
                    "receiver_value_id": receiver_id,
                    "property_id": effect["target"], "callsite": call["id"],
                    "context_sensitive": True,
                },
            }
            locations[(receiver_id, effect["target"])] = (location_id, value_id)
            add_edge("APPLIES_EFFECT", call["id"], location_id, summary=effect["source"])
            add_edge("POINTS_TO", receiver_id, location_id, context=call["id"])
            add_edge("WRITES_HEAP", value_id, location_id, callsite=call["id"])

    for call in list(nodes.values()):
        if call.get("kind") != "call":
            continue
        properties = call.get("properties", {})
        key = (properties.get("receiver_value_id"), properties.get("receiver_member_id"))
        if key not in locations:
            continue
        location_id, target_id = locations[key]
        if nodes.get(target_id, {}).get("kind") != "function":
            continue
        add_edge("READS_HEAP", location_id, call["id"])
        add_edge(
            "MAY_INVOKE", call["id"], target_id,
            resolution="interprocedural-property-effect", heap_location_id=location_id,
        )
        properties["resolution"] = "effect-resolved-function-pointer"
        properties["candidate_target_ids"] = [target_id]

    return {
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges, key=lambda item: (item["kind"], item["source"], item["target"])),
    }
