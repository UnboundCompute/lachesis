"""Evidence-backed transitive taint propagation over canonical value facts."""
from __future__ import annotations

from collections import defaultdict, deque

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


FLOW_EDGE_KINDS = frozenset({
    "DEFINES", "VALUE_FLOWS_TO", "READS_FROM", "PROPERTY_READ",
    "ALIASES", "ALIASES_VALUE",
    "PHI_INPUT", "BRANCH_READS_FROM", "BRANCH_PREVIOUS",
    "POINTS_TO", "WRITES_HEAP", "READS_HEAP",
})


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference",
        "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


def _roles(node: dict, role_name: str) -> list[dict]:
    return [
        role for role in node.get("properties", {}).get("roles", [])
        if role.get("role", "").lower() == role_name
    ]


class TaintPropagation:
    """Materialize source-to-sink witnesses without reading source text."""

    overlay_id = "taint-propagation"

    def applies(self, graph: dict) -> bool:
        return any(
            node.get("kind") == "source" or _roles(node, "source")
            for node in graph.get("nodes", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        adjacency: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)
        flow_evidence: dict[tuple[str, str], list[str]] = {}

        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            if kind not in FLOW_EDGE_KINDS:
                continue
            source, target = edge["source"], edge["target"]
            if not source.startswith("v2:") or not target.startswith("v2:"):
                continue
            adjacency[source].append((
                target, kind or "VALUE_FLOWS_TO", edge.get("properties", {}),
            ))
            flow_evidence[(source, target)] = [source, target]

        arguments_by_call: dict[str, list[str]] = defaultdict(list)
        for argument in index.nodes_of_kind("argument"):
            callsite_id = argument.get("properties", {}).get("callsite_id")
            if callsite_id:
                arguments_by_call[callsite_id].append(argument["id"])

        source_records = []
        sink_records = []
        for role_node in graph.get("nodes", []):
            if not role_node["id"].startswith("v2:") or role_node.get("kind") not in {
                "source", "sink",
            }:
                continue
            value_id = role_node.get("properties", {}).get("value_id")
            value = index.nodes.get(value_id)
            if not value:
                continue
            if role_node["kind"] == "source":
                source_records.append((role_node, value))
            else:
                sink_records.append((role_node, value))
        for value in graph.get("nodes", []):
            if not value["id"].startswith("v2:"):
                continue
            for role in _roles(value, "source"):
                source_id = stable_id(
                    "core", self.overlay_id, "source",
                    value["id"], role.get("subtype", "untrusted"),
                )
                fact = _fact([value["id"]], role.get("confidence", "high"))
                source = {
                    "id": source_id,
                    "kind": "source",
                    "label": f"source:{value.get('label', value['id'])}",
                    "properties": {
                        **fact,
                        "value_id": value["id"],
                        "source_kind": role.get("subtype", "untrusted"),
                    },
                }
                nodes.append(source)
                source_records.append((source, value))
                edges.append({
                    "kind": "TAINT_SOURCE", "source": source_id,
                    "target": value["id"], "properties": fact,
                })
            for role in _roles(value, "sink"):
                sink_id = stable_id(
                    "core", self.overlay_id, "sink",
                    value["id"], role.get("subtype", "sensitive-operation"),
                )
                fact = _fact([value["id"]], role.get("confidence", "high"))
                sink = {
                    "id": sink_id,
                    "kind": "sink",
                    "label": f"sink:{value.get('label', value['id'])}",
                    "properties": {
                        **fact,
                        "value_id": value["id"],
                        "sink_kind": role.get("subtype", "sensitive-operation"),
                        "callsite_id": value.get("properties", {}).get("callsite_id"),
                    },
                }
                nodes.append(sink)
                sink_records.append((sink, value))
                edges.append({
                    "kind": "TAINT_SINK", "source": sink_id,
                    "target": value["id"], "properties": fact,
                })

        for _sink, sink_value in sink_records:
            callsite_id = sink_value.get("properties", {}).get("callsite_id")
            for argument_id in arguments_by_call.get(callsite_id, []):
                adjacency[argument_id].append((
                    sink_value["id"], "SINK_ARGUMENT", {},
                ))
                flow_evidence[(argument_id, sink_value["id"])] = [
                    argument_id, callsite_id, sink_value["id"],
                ]

        emitted_flows: set[tuple[str, str, str | None]] = set()
        sinks_by_value = {value["id"]: sink for sink, value in sink_records}
        for source, source_value in source_records:
            initial_state = (source_value["id"], ())
            queue = deque([initial_state])
            predecessor: dict[
                tuple[str, tuple[str, ...]],
                tuple[tuple[str, tuple[str, ...]], str],
            ] = {}
            seen = {initial_state}
            reached_sinks: dict[str, tuple[str, tuple[str, ...]]] = {}
            while queue:
                current_state = queue.popleft()
                current, contexts = current_state
                if current in sinks_by_value and current not in reached_sinks:
                    reached_sinks[current] = current_state
                for target, transition, properties in adjacency.get(current, []):
                    next_contexts = contexts
                    reason = properties.get("reason")
                    context_id = properties.get("context_id")
                    if reason == "context-parameter":
                        if not context_id or len(contexts) >= 12:
                            continue
                        next_contexts = (*contexts, context_id)
                    elif reason == "context-return":
                        if not context_id or not contexts or contexts[-1] != context_id:
                            continue
                        next_contexts = contexts[:-1]
                    target_state = (target, next_contexts)
                    if target_state not in seen:
                        seen.add(target_state)
                        predecessor[target_state] = (current_state, transition)
                        queue.append(target_state)
                    key = (current, target, context_id)
                    if key in emitted_flows:
                        continue
                    emitted_flows.add(key)
                    evidence = flow_evidence.get(key, [current, target])
                    edges.append({
                        "kind": "TAINT_FLOWS_TO", "source": current,
                        "target": target,
                        "properties": {
                            **_fact(evidence, "high"),
                            "transition": transition,
                            "context_id": context_id,
                        },
                    })

            for sink_value_id, sink_state in sorted(reached_sinks.items()):
                witness = [sink_state[0]]
                context_trace = [list(sink_state[1])]
                current_state = sink_state
                while current_state != initial_state and current_state in predecessor:
                    current_state = predecessor[current_state][0]
                    witness.append(current_state[0])
                    context_trace.append(list(current_state[1]))
                if current_state != initial_state:
                    continue
                witness.reverse()
                context_trace.reverse()
                sink = sinks_by_value[sink_value_id]
                reach_id = stable_id(
                    "core", self.overlay_id, "taint-reach", source["id"], sink["id"],
                )
                fact = _fact(witness, source["properties"]["confidence"])
                nodes.append({
                    "id": reach_id,
                    "kind": "taint-reach",
                    "label": f"{source['label']} → {sink['label']}",
                    "properties": {
                        **fact,
                        "source_id": source["id"],
                        "sink_id": sink["id"],
                        "source_value_id": source_value["id"],
                        "sink_value_id": sink_value_id,
                        "witness_ids": witness,
                        "context_trace": context_trace,
                    },
                })
                edges.extend([
                    {
                        "kind": "TAINT_REACHES", "source": source["id"],
                        "target": reach_id, "properties": fact,
                    },
                    {
                        "kind": "TAINT_REACHES", "source": reach_id,
                        "target": sink["id"], "properties": fact,
                    },
                ])

        return GraphDelta(self.overlay_id, nodes, edges)
