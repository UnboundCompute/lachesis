"""Security-first and general-purpose queries for LLM reasoning."""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Optional

from ..core.query import GraphIndex
from ..projections import build_layered_graph
from ..projections.security import classify_sinks, detect_guards
from .budget import DEFAULT_BUDGET_TOKENS, fit_sections


FUNCTION_KINDS = frozenset({"function", "method", "constructor"})
CALL_KINDS = frozenset({"call", "construct"})
CONTROL_KINDS = frozenset({
    "cfg-entry", "cfg-block", "cfg-condition", "cfg-merge", "cfg-exit",
    "phi", "unreachable-region",
})
VALUE_HISTORY_EDGES = frozenset({
    "DEFINES", "READS_FROM", "WRITES_TO", "VALUE_FLOWS_TO", "ALIASES",
    "ALIASES_VALUE", "POINTS_TO", "PREVIOUS_VERSION", "PROPERTY_READ",
    "PHI_INPUT", "PHI_FOR_SYMBOL", "BRANCH_READS_FROM", "BRANCH_PREVIOUS",
    "WRITES_HEAP", "READS_HEAP", "CONTEXTUALIZES", "BINDS_PARAMETER",
    "ARGUMENT_BINDS_PARAMETER", "CONTEXT_RETURNS", "ALLOCATES",
})


def _location(node: dict) -> Optional[dict]:
    properties = node.get("properties", {})
    # Surface the repo-relative `file` as the portable location. `absolute_file`
    # can point into a temporary build/staging copy (e.g. an MCP stage dir), which
    # is non-portable — keep it as a separate field so a slice never leaks a temp
    # path as its primary location while still preserving the absolute for callers
    # that legitimately need it.
    relative = properties.get("file")
    absolute = properties.get("absolute_file")
    path = relative or absolute
    if not path:
        return None
    return {
        key: value for key, value in {
            "file": path, "absolute_file": absolute if absolute != path else None,
            "start_line": properties.get("start_line"),
            "start_column": properties.get("start_column"),
            "end_line": properties.get("end_line"),
            "end_column": properties.get("end_column"),
        }.items() if value is not None
    }


def _unresolved_reason(node: dict) -> Optional[str]:
    properties = node.get("properties", {})
    if node.get("kind") == "diagnostic":
        return "compiler-diagnostic"
    if node.get("kind") == "boundary":
        return properties.get("boundary_kind") or "runtime-boundary"
    if node.get("kind") == "dynamic-behavior":
        return properties.get("behavior_kind") or "dynamic-runtime"
    if properties.get("missing_model"):
        return "missing-model"
    resolution = properties.get("resolution")
    if resolution in {"unresolved", "dynamic-or-unresolved", "external"}:
        return "unresolved-call" if node.get("kind") in CALL_KINDS else resolution
    if properties.get("confidence") == "unresolved":
        return "unresolved-fact"
    return None


class ReasoningQuery:
    """Return compact JSON-ready answers with expandable canonical evidence."""

    def __init__(
        self, graph: dict, layered: Optional[dict] = None,
        default_budget_tokens: int = DEFAULT_BUDGET_TOKENS,
        project_metadata: Optional[dict] = None,
    ) -> None:
        self.graph = graph
        self.index = GraphIndex(graph)
        self.layered = layered or build_layered_graph(graph, project_metadata)
        self.node_index = self.layered["node_index"]
        self.default_budget_tokens = default_budget_tokens
        self.layered_nodes = {
            node["id"]: node
            for payload in self.layered["tiers"].values()
            for node in payload["nodes"]
        }
        self.layered_outgoing = defaultdict(list)
        self.layered_incoming = defaultdict(list)
        for payload in self.layered["tiers"].values():
            for collection in ("edges", "expands_to", "links"):
                for edge in payload[collection]:
                    self.layered_outgoing[edge["source"]].append(edge)
                    self.layered_incoming[edge["target"]].append(edge)
        for adjacency in (self.layered_outgoing, self.layered_incoming):
            for edges in adjacency.values():
                edges.sort(key=lambda item: item["id"])

    def _budget(self, budget_tokens: Optional[int]) -> int:
        return budget_tokens or self.default_budget_tokens

    def _node(self, node_id: str) -> dict:
        try:
            return self.index.nodes[node_id]
        except KeyError as error:
            raise KeyError(f"unknown canonical node id: {node_id}") from error

    def _suggest_nodes(self, node: dict, expected: frozenset[str]) -> list[str]:
        """Concrete node ids of an expected kind related to a wrong-kind node."""
        node_id = node["id"]
        kind = node.get("kind")
        if "taint-reach" in expected:
            related, any_reach = [], []
            for reach in self.index.nodes_of_kind("taint-reach"):
                any_reach.append(reach["id"])
                properties = reach.get("properties", {})
                anchors = {
                    properties.get("source_id"), properties.get("sink_id"),
                    properties.get("source_value_id"), properties.get("sink_value_id"),
                }
                if node_id in anchors or node_id in properties.get("witness_ids", []):
                    related.append(reach["id"])
            return sorted(related) or sorted(any_reach)
        if expected & CALL_KINDS and kind in FUNCTION_KINDS:
            return sorted(
                owned["id"] for owned in self.index.nodes_owned_by(node_id)
                if owned["kind"] in CALL_KINDS
            )
        if expected & FUNCTION_KINDS:
            owner = node.get("properties", {}).get("owner_function_id")
            if owner and owner in self.index.nodes:
                return [owner]
        return []

    def _kind_mismatch(
        self, node: dict, expected: frozenset[str], action: str,
    ) -> ValueError:
        """A wrong-node-kind error that names the valid kind and suggests nodes."""
        expected_text = " or ".join(sorted(expected))
        message = (
            f"node is a '{node.get('kind')}', but {action} expects a "
            f"{expected_text} node: {node['id']}"
        )
        suggestions = self._suggest_nodes(node, expected)
        if suggestions:
            listed = ", ".join(suggestions[:5])
            message += f". Try a {expected_text} node instead — e.g. {listed}"
        else:
            message += (
                f". No related {expected_text} node exists; run 'overview' to see "
                f"available anchors"
            )
        return ValueError(message)

    def _record(self, node_or_id: dict | str, include_excerpt: bool = False) -> dict:
        node = self._node(node_or_id) if isinstance(node_or_id, str) else node_or_id
        properties = node.get("properties", {})
        record = {
            "id": node["id"], "kind": node["kind"], "label": node.get("label", node["id"]),
            "locator": self.node_index.get(node["id"]), "location": _location(node),
            "origin": properties.get("fact_origin", "unknown"),
            "confidence": properties.get("confidence", "unresolved"),
        }
        reason = _unresolved_reason(node)
        if reason:
            record["unresolved_reason"] = reason
        if include_excerpt:
            excerpt = self._source_excerpt(node["id"])
            if excerpt:
                record["source_excerpt"] = excerpt
        return record

    def _edge_record(self, edge: dict) -> dict:
        return {
            "kind": GraphIndex.semantic_edge_kind(edge),
            "source": edge["source"], "target": edge["target"],
            "confidence": edge.get("properties", {}).get("confidence", "exact"),
            "context_id": edge.get("properties", {}).get("context_id"),
            "reason": edge.get("properties", {}).get("reason"),
            "evidence_ids": edge.get("properties", {}).get("evidence_ids", []),
        }

    def _source_excerpt(self, node_id: str) -> Optional[dict]:
        candidates = []
        frontier, visited = [node_id], {node_id}
        for _depth in range(2):
            following = []
            for current in frontier:
                for edge in [
                    *self.index.outgoing.get(current, []),
                    *self.index.incoming.get(current, []),
                ]:
                    if GraphIndex.semantic_edge_kind(edge) != "EVIDENCED_BY":
                        continue
                    other_id = edge["target"] if edge["source"] == current else edge["source"]
                    if other_id in visited:
                        continue
                    visited.add(other_id)
                    other = self.index.nodes.get(other_id)
                    if not other:
                        continue
                    if other["kind"] == "source-span":
                        candidates.append(other)
                    else:
                        following.append(other_id)
            frontier = following
        if not candidates:
            node = self.index.nodes.get(node_id, {})
            evidence_ids = node.get("properties", {}).get("evidence_ids", [])
            candidates.extend(
                self.index.nodes[evidence_id] for evidence_id in evidence_ids
                if evidence_id in self.index.nodes
                and self.index.nodes[evidence_id]["kind"] == "source-span"
            )
        if not candidates:
            return None
        proof = sorted(candidates, key=lambda item: item["id"])[0]
        text = str(proof.get("properties", {}).get("text") or proof.get("label", ""))
        return {
            "proof_id": proof["id"], "location": _location(proof),
            "text": text[:1200], "truncated": len(text) > 1200,
        }

    def _evidence(self, node_ids: list[str]) -> list[dict]:
        evidence_ids = []
        for node_id in node_ids:
            node = self.index.nodes.get(node_id)
            if not node:
                continue
            evidence_ids.append(node_id)
            evidence_ids.extend(node.get("properties", {}).get("evidence_ids", []))
        result, seen = [], set()
        for evidence_id in evidence_ids:
            if evidence_id in seen or evidence_id not in self.index.nodes:
                continue
            seen.add(evidence_id)
            result.append(self._record(evidence_id, include_excerpt=True))
        return result

    def _unresolved_records(self, node_ids: list[str]) -> list[dict]:
        return [
            {**self._record(node_id), "reason": _unresolved_reason(self.index.nodes[node_id])}
            for node_id in node_ids if node_id in self.index.nodes
            and _unresolved_reason(self.index.nodes[node_id])
        ]

    def _slice(
        self, query_type: str, focus_id: Optional[str], summary: dict,
        sections: list[tuple[str, list[dict]]], budget_tokens: Optional[int],
    ) -> dict:
        base = {
            "schema_version": 1, "query": query_type,
            "focus": self._record(focus_id, include_excerpt=True) if focus_id else None,
            "summary": summary,
        }
        return fit_sections(base, sections, self._budget(budget_tokens))

    def overview(self) -> dict:
        return {
            "schema_version": 2, "query": "overview",
            "manifest": self.layered["manifest"],
        }

    def locate(self, node_id: str) -> dict:
        node = self._node(node_id)
        return {
            "schema_version": 1, "query": "locate", "node": self._record(node, True),
            "layered": self.layered_nodes.get(node_id),
        }

    def find_entity(
        self, name: str, kind: Optional[str] = None, file: Optional[str] = None,
    ) -> dict:
        matches = []
        for node in self.index.nodes_named(name):
            if kind and node["kind"] != kind:
                continue
            location = _location(node) or {}
            if file and not str(location.get("file", "")).endswith(file):
                continue
            matches.append(self._record(node))
        return {
            "schema_version": 1, "query": "find-entity",
            "criteria": {"name": name, "kind": kind, "file": file},
            "status": "not-found" if not matches else "exact" if len(matches) == 1 else "ambiguous",
            "matches": matches,
        }

    def expand(
        self, node_id: str, depth: int = 1, budget_tokens: Optional[int] = None,
    ) -> dict:
        self._node(node_id)
        depth = max(0, min(depth, 8))
        queue = deque([(node_id, 0)])
        seen = {node_id}
        nodes, relationships = [], []
        while queue:
            current, level = queue.popleft()
            if level >= depth:
                continue
            for edge in self.layered_outgoing.get(current, []):
                relationships.append({
                    "id": edge["id"], "kind": edge.get("relationship") or edge["kind"],
                    "source": edge["source"], "target": edge["target"],
                    "target_locator": self.node_index.get(edge["target"]),
                })
                target = edge["target"]
                if target in seen or target not in self.index.nodes:
                    continue
                seen.add(target)
                nodes.append(self._record(target))
                queue.append((target, level + 1))
        return self._slice(
            "expand", node_id, {"depth": depth, "node_count": len(nodes)},
            [("relationships", relationships), ("nodes", nodes),
             ("unresolved", self._unresolved_records(list(seen)))], budget_tokens,
        )

    def function_slice(
        self, function_id: str, budget_tokens: Optional[int] = None,
    ) -> dict:
        function = self._node(function_id)
        if function["kind"] not in FUNCTION_KINDS:
            raise self._kind_mismatch(function, FUNCTION_KINDS, "function")
        owned = sorted(self.index.nodes_owned_by(function_id), key=lambda node: (
            node.get("properties", {}).get("start_offset", 1 << 60), node["id"],
        ))
        parameters = [node for node in owned if node["kind"] == "parameter"]
        calls = [node for node in owned if node["kind"] in CALL_KINDS]
        body = [
            node for node in owned
            if node["kind"] in {"statement", "expression", "identifier", "scope", *CONTROL_KINDS}
        ]
        effects = [
            node for node in owned
            if node["kind"] in {"function-effect", "module-state", "heap-location", "async-event"}
        ]
        call_edges = []
        target_ids = []
        for call in calls:
            for edge in self.index.outgoing.get(call["id"], []):
                if GraphIndex.semantic_edge_kind(edge) in {"INVOKES", "MAY_INVOKE"}:
                    call_edges.append(self._edge_record(edge))
                    target_ids.append(edge["target"])
        owner_ids = [node["id"] for node in owned]
        return self._slice(
            "function", function_id, {
                "parameter_count": len(parameters), "call_count": len(calls),
                "body_node_count": len(body), "effect_count": len(effects),
            }, [
                ("parameters", [self._record(node) for node in parameters]),
                ("calls", [self._record(node, True) for node in calls]),
                ("call_targets", call_edges),
                ("control_and_body", [self._record(node, node["kind"] == "statement") for node in body]),
                ("effects", [self._record(node) for node in effects]),
                ("evidence", self._evidence([function_id, *owner_ids, *target_ids])),
                ("unresolved", self._unresolved_records(owner_ids)),
            ], budget_tokens,
        )

    def value_history(
        self, value_id: str, budget_tokens: Optional[int] = None,
    ) -> dict:
        self._node(value_id)
        queue = deque([value_id])
        seen = {value_id}
        history, transitions = [], []
        while queue and len(seen) < 250:
            current = queue.popleft()
            edges = [
                *self.index.incoming.get(current, []),
                *self.index.outgoing.get(current, []),
            ]
            for edge in edges:
                semantic = GraphIndex.semantic_edge_kind(edge)
                if semantic not in VALUE_HISTORY_EDGES:
                    continue
                other = edge["source"] if edge["target"] == current else edge["target"]
                if other not in self.index.nodes:
                    continue
                transitions.append(self._edge_record(edge))
                if other in seen:
                    continue
                seen.add(other)
                history.append({
                    **self._record(other, True),
                    "via": self._edge_record(edge),
                })
                queue.append(other)
        return self._slice(
            "value-history", value_id,
            {"related_value_count": len(history), "transition_count": len(transitions)},
            [("history", history), ("transitions", transitions),
             ("evidence", self._evidence(list(seen))),
             ("unresolved", self._unresolved_records(list(seen)))], budget_tokens,
        )

    def explain_call(
        self, call_id: str, budget_tokens: Optional[int] = None,
    ) -> dict:
        call = self._node(call_id)
        if call["kind"] not in CALL_KINDS:
            raise self._kind_mismatch(call, CALL_KINDS, "call")
        arguments = sorted(self.index.targets(call_id, "HAS_ARGUMENT"), key=lambda node: (
            node.get("properties", {}).get("position", 1 << 30), node["id"],
        ))
        targets = list({
            node["id"]: node for node in self.index.targets(
                call_id, "INVOKES", "MAY_INVOKE",
            )
        }.values())
        contexts = list({
            node["id"]: node for node in self.index.targets(call_id, "HAS_CALL_CONTEXT")
        }.values())
        context_ids = [node["id"] for node in contexts]
        bindings = [
            node for node in self.index.nodes_of_kind("context-parameter", "context-return")
            if node.get("properties", {}).get("context_id") in context_ids
        ]
        effect_edges = [
            edge for edge in [
                *self.index.outgoing.get(call_id, []), *self.index.incoming.get(call_id, []),
            ] if GraphIndex.semantic_edge_kind(edge) in {"APPLIES_EFFECT", "MUTATES"}
        ]
        properties = call.get("properties", {})
        return self._slice(
            "call", call_id, {
                "resolution": properties.get("resolution", "unresolved"),
                "receiver_type": properties.get("receiver_type_facts") or properties.get("receiver_type"),
                "target_count": len(targets), "context_count": len(contexts),
            }, [
                ("arguments", [self._record(node, True) for node in arguments]),
                ("targets", [self._record(node) for node in targets]),
                ("contexts", [self._record(node) for node in contexts]),
                ("bindings", [self._record(node) for node in bindings]),
                ("effects", [self._edge_record(edge) for edge in effect_edges]),
                ("evidence", self._evidence([call_id, *[n["id"] for n in targets + contexts + bindings]])),
                ("unresolved", self._unresolved_records([call_id, *context_ids])),
            ], budget_tokens,
        )

    def security_path(
        self, reach_id: str, budget_tokens: Optional[int] = None,
    ) -> dict:
        reach = self._node(reach_id)
        if reach["kind"] != "taint-reach":
            raise self._kind_mismatch(
                reach, frozenset({"taint-reach"}), "security-path",
            )
        properties = reach.get("properties", {})
        witness_ids = properties.get("witness_ids", [])
        steps = []
        contexts = []
        for position, node_id in enumerate(witness_ids):
            record = {"position": position, **self._record(node_id, True)}
            if position:
                previous = witness_ids[position - 1]
                edges = [
                    edge for edge in self.index.outgoing.get(previous, [])
                    if edge.get("target") == node_id
                ]
                if edges:
                    record["transition"] = self._edge_record(edges[0])
                    context_id = edges[0].get("properties", {}).get("context_id")
                    if context_id:
                        contexts.append(context_id)
            steps.append(record)
        sink = self.index.nodes.get(properties.get("sink_id"))
        call_id = sink and sink.get("properties", {}).get("callsite_id")
        call = self.index.nodes.get(call_id) if call_id else None
        guard = None
        if call:
            owner = call.get("properties", {}).get("owner_function_id")
            guard = next((
                verdict for verdict in detect_guards(self.graph, classify_sinks(self.graph))
                if verdict["handler_id"] == owner and call_id in verdict["sink_call_ids"]
            ), None)
        return self._slice(
            "security-path", reach_id, {
                "source_id": properties.get("source_id"), "sink_id": properties.get("sink_id"),
                "step_count": len(steps), "context_ids": list(dict.fromkeys(contexts)),
                "guard": guard,
            }, [
                ("path", steps),
                ("contexts", [self._record(node_id) for node_id in dict.fromkeys(contexts)
                              if node_id in self.index.nodes]),
                ("evidence", self._evidence([reach_id, *witness_ids])),
                ("unresolved", self._unresolved_records(witness_ids)),
            ], budget_tokens,
        )

    def handler_security_slice(
        self, function_id: str, budget_tokens: Optional[int] = None,
    ) -> dict:
        function = self._node(function_id)
        if function["kind"] not in FUNCTION_KINDS:
            raise self._kind_mismatch(function, FUNCTION_KINDS, "handler-security")
        owned = {node["id"] for node in self.index.nodes_owned_by(function_id)}
        reaches = []
        for reach in self.index.nodes_of_kind("taint-reach"):
            properties = reach.get("properties", {})
            source = self.index.nodes.get(properties.get("source_id"), {})
            source_function = source.get("properties", {}).get("function_id")
            witnesses = set(properties.get("witness_ids", []))
            if source_function == function_id or witnesses.intersection(owned):
                reaches.append(reach)
        verdicts = [
            verdict for verdict in detect_guards(self.graph, classify_sinks(self.graph))
            if verdict["handler_id"] == function_id
        ]
        path_records = [{
            "id": reach["id"], "label": reach["label"],
            "source_id": reach.get("properties", {}).get("source_id"),
            "sink_id": reach.get("properties", {}).get("sink_id"),
            "step_count": len(reach.get("properties", {}).get("witness_ids", [])),
            "continuation": {"operation": "security-path", "node_id": reach["id"]},
        } for reach in reaches]
        return self._slice(
            "handler-security", function_id,
            {"path_count": len(reaches), "guard_verdicts": verdicts},
            [("security_paths", path_records),
             ("calls", [self._record(node, True) for node in self.index.nodes_owned_by(function_id)
                        if node["kind"] in CALL_KINDS]),
             ("evidence", self._evidence([function_id, *list(owned)])),
             ("unresolved", self._unresolved_records(list(owned)))], budget_tokens,
        )

    def unresolved_frontier(
        self, node_id: Optional[str] = None, budget_tokens: Optional[int] = None,
    ) -> dict:
        if node_id:
            focus = self._node(node_id)
            owner = focus.get("properties", {}).get("owner_function_id") \
                or focus.get("properties", {}).get("function_id")
            candidates = {node_id}
            if owner:
                candidates.update(node["id"] for node in self.index.nodes_owned_by(owner))
            for edge in [
                *self.index.outgoing.get(node_id, []), *self.index.incoming.get(node_id, []),
            ]:
                candidates.update((edge["source"], edge["target"]))
        else:
            candidates = set(self.index.nodes)
        unresolved = self._unresolved_records(sorted(candidates))
        counts = defaultdict(int)
        for record in unresolved:
            counts[record["reason"]] += 1
        return self._slice(
            "unresolved", node_id, {"count": len(unresolved), "by_reason": dict(sorted(counts.items()))},
            [("unresolved", unresolved)], budget_tokens,
        )
