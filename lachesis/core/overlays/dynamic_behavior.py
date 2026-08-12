"""Normalize explicit and unresolved runtime behavior into queryable boundaries."""
from __future__ import annotations

from collections import defaultdict

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


def _fact(evidence_ids: list[str], confidence: str = "unresolved") -> dict:
    return {
        "fact_origin": "core-inference", "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


class DynamicBehavior:
    overlay_id = "dynamic-behavior"

    def applies(self, graph: dict) -> bool:
        return any(
            node.get("kind") in {"dynamic-behavior", "call", "construct"}
            for node in graph.get("nodes", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        explicit_by_site: dict[str, list[dict]] = defaultdict(list)
        arguments_by_call: dict[str, list[str]] = defaultdict(list)

        for behavior in index.nodes_of_kind("dynamic-behavior"):
            site_id = behavior.get("properties", {}).get("site_id")
            if not site_id:
                site = index.first_target(behavior["id"], "DYNAMIC_BEHAVIOR_AT")
                site_id = site and site["id"]
            if site_id:
                explicit_by_site[site_id].append(behavior)
        for argument in index.nodes_of_kind("argument"):
            callsite = argument.get("properties", {}).get("callsite_id")
            if callsite:
                arguments_by_call[callsite].append(argument["id"])

        behaviors = list(index.nodes_of_kind("dynamic-behavior"))
        for call in index.nodes_of_kind("call", "construct"):
            resolved = any(
                edge.get("kind") in {"INVOKES", "MAY_INVOKE"}
                for edge in index.outgoing.get(call["id"], [])
            )
            if resolved or explicit_by_site.get(call["id"]):
                continue
            behavior_id = stable_id(
                "core", self.overlay_id, "dynamic-behavior", "unresolved-call", call["id"],
            )
            fact = _fact([call["id"]])
            behavior = {
                "id": behavior_id, "kind": "dynamic-behavior",
                "label": "unresolved-call",
                "properties": {
                    **fact, "behavior_kind": "unresolved-call",
                    "site_id": call["id"],
                    "owner_function_id": call.get("properties", {}).get("owner_function_id"),
                    "resolution": call.get("properties", {}).get("resolution", "unresolved"),
                },
            }
            nodes.append(behavior)
            behaviors.append(behavior)
            explicit_by_site[call["id"]].append(behavior)
            edges.append({
                "kind": "DYNAMIC_BEHAVIOR_AT", "source": behavior_id,
                "target": call["id"], "properties": fact,
            })

        for behavior in behaviors:
            properties = behavior.get("properties", {})
            site_id = properties.get("site_id")
            if not site_id:
                site = index.first_target(behavior["id"], "DYNAMIC_BEHAVIOR_AT")
                site_id = site and site["id"]
            evidence = [behavior["id"], *([site_id] if site_id else [])]
            boundary_id = stable_id(
                "core", self.overlay_id, "boundary", behavior["id"],
            )
            fact = _fact(evidence, properties.get("confidence", "unresolved"))
            nodes.append({
                "id": boundary_id, "kind": "boundary",
                "label": f"dynamic:{properties.get('behavior_kind', behavior.get('label'))}",
                "properties": {
                    **fact, "boundary_kind": "dynamic-runtime",
                    "behavior_id": behavior["id"], "site_id": site_id,
                },
            })
            edges.append({
                "kind": "EVIDENCED_BY", "source": boundary_id,
                "target": behavior["id"], "properties": fact,
            })
            inputs = list(arguments_by_call.get(site_id, []))
            inputs.extend(
                value_id for value_id in (
                    properties.get("key_value_id"), properties.get("target_id"),
                ) if value_id
            )
            for input_id in dict.fromkeys(inputs):
                if input_id not in index.nodes:
                    continue
                edges.append({
                    "kind": "DYNAMIC_INPUT", "source": input_id,
                    "target": behavior["id"],
                    "properties": {**fact, "boundary_id": boundary_id},
                })
        return GraphDelta(self.overlay_id, nodes, edges)

