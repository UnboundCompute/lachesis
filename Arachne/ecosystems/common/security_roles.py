"""Portable entry-parameter and sensitive-call security role policies."""
from __future__ import annotations

from ...core.composition import GraphDelta
from ...core.identities import stable_id
from ...core.query import GraphIndex


SENSITIVE_CALLS = {
    "eval": "dynamic-code",
    "Function": "dynamic-code",
    "fetch": "network",
    "exec": "process",
    "execFile": "process",
    "spawn": "process",
    "writeFile": "filesystem-write",
    "writeFileSync": "filesystem-write",
    "query": "database",
    "execute": "database",
    "findById": "database",
    "findOne": "database",
    "send": "response",
    "json": "response",
    "redirect": "response",
}


def _last_name(value: str) -> str:
    normalized = value.split("?.")[-1]
    if "." in normalized:
        normalized = normalized.rsplit(".", 1)[-1]
    if "[" in normalized:
        normalized = normalized.rsplit("[", 1)[-1]
    return normalized.strip("'\"`] ")


class GenericSecurityRoleModel:
    """Tag public inputs and mechanically named sensitive operations."""

    model_id = "generic-security-roles"
    supported_languages = (
        "typescript", "javascript", "python", "java", "go", "csharp",
        "ruby", "c", "cpp",
    )
    required_capabilities = ("calls", "direct_data_flow")

    def applies(self, graph: dict, package_inventory: frozenset[str]) -> bool:
        del package_inventory
        return any(
            node.get("kind") in {"function", "method", "call", "construct"}
            for node in graph.get("nodes", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        exported = {
            edge["target"] for edge in index.edges_of_kind("EXPORTS")
            if index.nodes.get(edge["target"], {}).get("kind")
                in {"function", "method", "constructor"}
        }
        for parameter in index.nodes_of_kind("parameter"):
            owner_id = parameter.get("properties", {}).get("owner_function_id")
            if owner_id not in exported:
                continue
            source_id = stable_id(
                "runtime-model", self.model_id, "source", parameter["id"],
            )
            evidence = [owner_id, parameter["id"]]
            fact = {
                "fact_origin": "runtime-model",
                "confidence": "conservative",
                "evidence_ids": evidence,
            }
            nodes.append({
                "id": source_id,
                "kind": "source",
                "label": f"public parameter:{parameter.get('label', parameter['id'])}",
                "properties": {
                    **fact,
                    "model_id": self.model_id,
                    "value_id": parameter["id"],
                    "source_kind": "exported-parameter",
                    "function_id": owner_id,
                },
            })
            edges.append({
                "kind": "TAINT_SOURCE", "source": source_id,
                "target": parameter["id"], "properties": fact,
            })

        for call in index.nodes_of_kind("call", "construct"):
            properties = call.get("properties", {})
            name = properties.get("method_name") or _last_name(
                str(properties.get("callee") or call.get("label", ""))
            )
            subtype = SENSITIVE_CALLS.get(name)
            if not subtype:
                continue
            value_id = properties.get("value_id") or call["id"]
            if value_id not in index.nodes:
                value_id = call["id"]
            sink_id = stable_id(
                "runtime-model", self.model_id, "sink", call["id"], subtype,
            )
            evidence = [call["id"], value_id]
            fact = {
                "fact_origin": "runtime-model",
                "confidence": "high",
                "evidence_ids": list(dict.fromkeys(evidence)),
            }
            nodes.append({
                "id": sink_id,
                "kind": "sink",
                "label": f"{subtype}:{call.get('label', name)}",
                "properties": {
                    **fact,
                    "model_id": self.model_id,
                    "value_id": value_id,
                    "sink_kind": subtype,
                    "callsite_id": call["id"],
                },
            })
            edges.append({
                "kind": "TAINT_SINK", "source": sink_id,
                "target": value_id, "properties": fact,
            })

        return GraphDelta(self.model_id, nodes, edges)

