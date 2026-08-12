"""Context-specific argument, parameter, and return bindings."""
from __future__ import annotations

from collections import defaultdict

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


def _fact(evidence_ids: list[str], confidence: str = "exact") -> dict:
    return {
        "fact_origin": "core-inference",
        "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


class InterproceduralContexts:
    """Keep each call/target binding distinct while stitching value flow."""

    overlay_id = "interprocedural-contexts"

    def applies(self, graph: dict) -> bool:
        return any(node.get("kind") == "call" for node in graph.get("nodes", []))

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        arguments_by_call: dict[str, list[dict]] = defaultdict(list)
        parameter_definitions: dict[str, list[str]] = defaultdict(list)
        returns_by_function: dict[str, list[str]] = defaultdict(list)
        bindings_by_call: dict[str, list[dict]] = defaultdict(list)

        for argument in index.nodes_of_kind("argument"):
            callsite_id = argument.get("properties", {}).get("callsite_id")
            if callsite_id:
                arguments_by_call[callsite_id].append(argument)
        for parameter in index.nodes_of_kind("parameter"):
            for definition in index.targets(parameter["id"], "DEFINES"):
                if definition.get("properties", {}).get("origin") == "parameter":
                    parameter_definitions[parameter["id"]].append(definition["id"])
        for edge in graph.get("edges", []):
            if edge.get("kind") == "RETURNS_VALUE":
                returns_by_function[edge["target"]].append(edge["source"])
            elif edge.get("kind") == "ARGUMENT_BINDS_PARAMETER":
                argument = index.nodes.get(edge["source"])
                callsite_id = argument and argument.get("properties", {}).get("callsite_id")
                if callsite_id:
                    bindings_by_call[callsite_id].append(edge)

        for call in index.nodes_of_kind("call", "construct"):
            call_id = call["id"]
            targets = list(dict.fromkeys(
                edge["target"]
                for edge in index.outgoing.get(call_id, [])
                if edge.get("kind") in {"INVOKES", "MAY_INVOKE"}
                and edge.get("target") in index.nodes
            ))
            contextual_targets = targets or [None]
            for target_id in contextual_targets:
                context_id = stable_id(
                    "core", self.overlay_id, "call-context",
                    call_id, target_id or "unresolved",
                )
                evidence = [call_id, *([target_id] if target_id else [])]
                fact = _fact(evidence, "exact" if target_id else "unresolved")
                nodes.append({
                    "id": context_id,
                    "kind": "call-context",
                    "label": f"context:{call.get('label', call_id)}",
                    "properties": {
                        **fact,
                        "callsite_id": call_id,
                        "caller_function_id": call.get("properties", {}).get("owner_function_id"),
                        "callee_function_id": target_id,
                        "resolution": call.get("properties", {}).get("resolution", "unresolved"),
                    },
                })
                edges.append({
                    "kind": "HAS_CALL_CONTEXT", "source": call_id,
                    "target": context_id, "properties": fact,
                })
                if target_id:
                    edges.append({
                        "kind": "CONTEXT_CALLS", "source": context_id,
                        "target": target_id, "properties": fact,
                    })

                for binding in bindings_by_call.get(call_id, []):
                    parameter_id = binding["target"]
                    parameter = index.nodes.get(parameter_id)
                    if not parameter:
                        continue
                    owner = parameter.get("properties", {}).get("owner_function_id")
                    if target_id and owner != target_id:
                        continue
                    argument_id = binding["source"]
                    position = binding.get("properties", {}).get("position")
                    binding_id = stable_id(
                        "core", self.overlay_id, "context-parameter",
                        context_id, argument_id, parameter_id,
                    )
                    binding_evidence = [call_id, argument_id, parameter_id]
                    binding_fact = _fact(binding_evidence)
                    nodes.append({
                        "id": binding_id,
                        "kind": "context-parameter",
                        "label": f"{call.get('label', 'call')} → {parameter.get('label', 'parameter')}",
                        "properties": {
                            **binding_fact,
                            "context_id": context_id,
                            "callsite_id": call_id,
                            "argument_id": argument_id,
                            "parameter_id": parameter_id,
                            "target_function_id": target_id,
                            "position": position,
                        },
                    })
                    edges.extend([
                        {
                            "kind": "BINDS_PARAMETER", "source": argument_id,
                            "target": binding_id,
                            "properties": {**binding_fact, "position": position},
                        },
                        {
                            "kind": "CONTEXTUALIZES", "source": binding_id,
                            "target": parameter_id, "properties": binding_fact,
                        },
                        {
                            "kind": "VALUE_FLOWS_TO", "source": argument_id,
                            "target": binding_id,
                            "properties": {**binding_fact, "reason": "context-argument"},
                        },
                    ])
                    for definition_id in parameter_definitions.get(parameter_id, []):
                        edges.append({
                            "kind": "VALUE_FLOWS_TO", "source": binding_id,
                            "target": definition_id,
                            "properties": {
                                **binding_fact,
                                "reason": "context-parameter",
                                "context_id": context_id,
                            },
                        })

                call_value_id = call.get("properties", {}).get("value_id")
                if not call_value_id or call_value_id not in index.nodes:
                    continue
                return_id = stable_id(
                    "core", self.overlay_id, "context-return", context_id, call_value_id,
                )
                return_evidence = [call_id, call_value_id, *returns_by_function.get(target_id, [])]
                return_fact = _fact(return_evidence, "exact" if target_id else "unresolved")
                nodes.append({
                    "id": return_id,
                    "kind": "context-return",
                    "label": f"return:{call.get('label', call_id)}",
                    "properties": {
                        **return_fact,
                        "context_id": context_id,
                        "callsite_id": call_id,
                        "callee_function_id": target_id,
                        "call_value_id": call_value_id,
                    },
                })
                edges.append({
                    "kind": "CONTEXT_RETURNS", "source": context_id,
                    "target": return_id, "properties": return_fact,
                })
                for source_return_id in returns_by_function.get(target_id, []):
                    edges.append({
                        "kind": "VALUE_FLOWS_TO", "source": source_return_id,
                        "target": return_id,
                        "properties": {
                            **return_fact,
                            "reason": "context-return",
                            "context_id": context_id,
                        },
                    })
                edges.append({
                    "kind": "VALUE_FLOWS_TO", "source": return_id,
                    "target": call_value_id,
                    "properties": {
                        **return_fact,
                        "reason": "context-call-result",
                        "context_id": context_id,
                    },
                })

        return GraphDelta(self.overlay_id, nodes, edges)
