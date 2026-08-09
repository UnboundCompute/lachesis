"""Instantiate compiler-emitted mutation summaries at canonical call sites."""
from __future__ import annotations

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference",
        "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


class ParameterPropertyEffects:
    overlay_id = "parameter-property-effects"

    def applies(self, graph: dict) -> bool:
        return any(
            edge.get("kind") == "WRITES_PARAMETER_PROPERTY"
            for edge in graph.get("edges", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        locations: dict[tuple[str, str], tuple[str, str]] = {}
        effects = [
            edge for edge in graph.get("edges", [])
            if edge.get("kind") == "WRITES_PARAMETER_PROPERTY"
        ]

        for effect in effects:
            effect_properties = effect.get("properties", {})
            receiver_position = effect_properties.get("receiver_position")
            value_position = effect_properties.get("value_position")
            if not isinstance(receiver_position, int) or not isinstance(value_position, int):
                continue
            for call in index.nodes_of_kind("call", "construct"):
                call_properties = call.get("properties", {})
                if call_properties.get("primary_target_id") != effect["source"]:
                    continue
                values = call_properties.get("argument_value_ids", [])
                if receiver_position >= len(values) or value_position >= len(values):
                    continue
                receiver_id, value_id = values[receiver_position], values[value_position]
                if receiver_id not in index.nodes or value_id not in index.nodes:
                    continue
                property_id = effect["target"]
                evidence = [call["id"], effect["source"], property_id, receiver_id, value_id]
                location_id = stable_id(
                    "core", self.overlay_id, "heap-location",
                    call["id"], receiver_id, property_id,
                )
                fact = _fact(evidence)
                nodes.append({
                    "id": location_id,
                    "kind": "heap-location",
                    "label": (
                        f"{index.nodes[receiver_id]['label']}."
                        f"{index.nodes.get(property_id, {}).get('label', property_id)}"
                    ),
                    "properties": {
                        **fact,
                        "receiver_value_id": receiver_id,
                        "property_id": property_id,
                        "callsite_id": call["id"],
                        "context_sensitive": True,
                    },
                })
                locations[(receiver_id, property_id)] = (location_id, value_id)
                edges.extend([
                    {
                        "kind": "APPLIES_EFFECT", "source": call["id"],
                        "target": location_id,
                        "properties": {**fact, "summary_function_id": effect["source"]},
                    },
                    {
                        "kind": "POINTS_TO", "source": receiver_id,
                        "target": location_id,
                        "properties": {**fact, "callsite_id": call["id"]},
                    },
                    {
                        "kind": "WRITES_HEAP", "source": value_id,
                        "target": location_id,
                        "properties": {**fact, "callsite_id": call["id"]},
                    },
                ])

        for call in index.nodes_of_kind("call"):
            properties = call.get("properties", {})
            key = (
                properties.get("receiver_value_id"),
                properties.get("receiver_member_id"),
            )
            if key not in locations:
                continue
            location_id, target_id = locations[key]
            if index.nodes.get(target_id, {}).get("kind") not in {
                "function", "method", "constructor",
            }:
                continue
            evidence = [call["id"], location_id, target_id]
            fact = _fact(evidence)
            edges.extend([
                {
                    "kind": "READS_HEAP", "source": location_id,
                    "target": call["id"], "properties": fact,
                },
                {
                    "kind": "MAY_INVOKE", "source": call["id"],
                    "target": target_id,
                    "properties": {
                        **fact,
                        "resolution": "interprocedural-property-effect",
                        "heap_location_id": location_id,
                    },
                },
            ])

        return GraphDelta(self.overlay_id, nodes, edges)


def apply_parameter_property_effects(graph: dict) -> dict:
    """Compatibility wrapper around the registered canonical overlay."""
    from .registry import OverlayRegistry

    registry = OverlayRegistry()
    registry.register(ParameterPropertyEffects())
    return registry.enrich(graph)

