"""Canonical route registration model with no source-text parsing."""
from __future__ import annotations

from ...core.composition import GraphDelta
from ...core.identities import stable_id
from ...core.query import GraphIndex


ROUTE_METHODS = frozenset({
    "get", "post", "put", "delete", "patch", "options", "head", "all", "use",
})


def _literal_value(argument: dict) -> str | None:
    label = str(argument.get("label", ""))
    if len(label) < 2 or label[0] not in {'"', "'", "`"} or label[-1] != label[0]:
        return None
    if label[0] == "`" and "${" in label:
        return None
    return label[1:-1]


def _handler_target(index: GraphIndex, argument: dict) -> dict | None:
    for syntax in index.targets(argument["id"], "EXPANDS_TO", "EVIDENCED_BY"):
        for target in index.targets(syntax["id"], "REFERS_TO"):
            if target.get("kind") in {"function", "method"}:
                return target
    return None


class GenericRouteModel:
    model_id = "generic-web-routes"
    supported_languages = (
        "typescript", "javascript", "python", "java", "go", "csharp", "ruby",
    )
    required_capabilities = ("calls", "direct_data_flow")

    def applies(self, graph: dict, package_inventory: frozenset[str]) -> bool:
        del package_inventory
        return any(
            node.get("kind") == "call"
            and node.get("properties", {}).get("method_name", "").lower() in ROUTE_METHODS
            for node in graph.get("nodes", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        parameters_by_function = {}
        for parameter in index.nodes_of_kind("parameter"):
            owner_id = parameter.get("properties", {}).get("owner_function_id")
            if owner_id:
                parameters_by_function.setdefault(owner_id, []).append(parameter)
        arguments_by_call = {}
        for argument in index.nodes_of_kind("argument"):
            callsite_id = argument.get("properties", {}).get("callsite_id")
            if callsite_id:
                arguments_by_call.setdefault(callsite_id, []).append(argument)

        for call in index.nodes_of_kind("call"):
            properties = call.get("properties", {})
            method = str(properties.get("method_name") or "").lower()
            if method not in ROUTE_METHODS:
                continue
            arguments = sorted(
                arguments_by_call.get(call["id"], []),
                key=lambda item: item.get("properties", {}).get("position", -1),
            )
            path = _literal_value(arguments[0]) if arguments else None
            if method != "use" and path is None:
                continue
            handler_argument = arguments[-1] if arguments else None
            if handler_argument is arguments[0] and method != "use":
                handler_argument = None
            handler = _handler_target(index, handler_argument) if handler_argument else None
            evidence_ids = [call["id"], *(arg["id"] for arg in arguments)]
            route_id = stable_id(
                "framework-model", self.model_id, "route", call["id"], path or "*",
            )
            fact = {
                "fact_origin": "framework-model",
                "confidence": "high" if handler else "conservative",
                "evidence_ids": evidence_ids,
            }
            nodes.append({
                "id": route_id, "kind": "route",
                "label": f"{method.upper()} {path or '*'}",
                "properties": {
                    **fact,
                    "model_id": self.model_id,
                    "method": method,
                    "path": path,
                    "callsite_id": call["id"],
                    "receiver_expression": properties.get("receiver_expression"),
                    "handler_id": handler.get("id") if handler else None,
                },
            })
            edges.append({
                "kind": "EVIDENCED_BY", "source": route_id, "target": call["id"],
                "properties": dict(fact),
            })
            if handler:
                edges.append({
                    "kind": "ROUTE_HANDLED_BY", "source": route_id,
                    "target": handler["id"], "properties": dict(fact),
                })
                edges.append({
                    "kind": "ENTRY_POINT_OF", "source": route_id,
                    "target": handler["id"], "properties": dict(fact),
                })
                parameters = sorted(
                    parameters_by_function.get(handler["id"], []),
                    key=lambda item: item.get("properties", {}).get(
                        "parameter_position", 0,
                    ),
                )
                if parameters:
                    request_parameter = parameters[0]
                    source_id = stable_id(
                        "framework-model", self.model_id, "source",
                        route_id, request_parameter["id"],
                    )
                    source_fact = {
                        "fact_origin": "framework-model",
                        "confidence": "conservative",
                        "evidence_ids": [
                            route_id, call["id"], handler["id"],
                            request_parameter["id"],
                        ],
                    }
                    nodes.append({
                        "id": source_id,
                        "kind": "source",
                        "label": f"route input:{request_parameter.get('label', 'parameter')}",
                        "properties": {
                            **source_fact,
                            "model_id": self.model_id,
                            "value_id": request_parameter["id"],
                            "source_kind": "route-handler-parameter",
                            "route_id": route_id,
                            "function_id": handler["id"],
                        },
                    })
                    edges.append({
                        "kind": "TAINT_SOURCE", "source": source_id,
                        "target": request_parameter["id"],
                        "properties": dict(source_fact),
                    })
        return GraphDelta(self.model_id, nodes, edges)
