"""Candidate expansion for canonical callable and type relationships."""
from __future__ import annotations

from collections import defaultdict

from ...indices import last_name as _last_name
from ..composition import GraphDelta
from ..query import GraphIndex


IDENTITY_REASONS = frozenset({
    "initializer", "assignment", "write", "read", "read-value",
    "argument-value", "call-result", "context-call-result",
    "branch-reaching-definition", "phi-input",
})


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference", "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


class DynamicDispatch:
    """Expand compiler seeds through overrides, aliases and callback bindings."""

    overlay_id = "dynamic-dispatch"

    def applies(self, graph: dict, index: GraphIndex | None = None) -> bool:
        index = GraphIndex(graph) if index is None else index
        return index.has_kind("call")

    def enrich(self, graph: dict, index: GraphIndex | None = None) -> GraphDelta:
        index = GraphIndex(graph) if index is None else index
        edges = []
        emitted: set[tuple[str, str, str]] = set()
        implementations: dict[str, set[str]] = defaultdict(set)
        callable_targets: dict[str, set[str]] = defaultdict(set)
        identity_edges: list[tuple[str, str]] = []
        ast_children: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        references: dict[str, set[str]] = defaultdict(set)
        read_by_evidence: dict[str, list[str]] = defaultdict(list)

        def add_edge(kind: str, source: str, target: str, evidence: list[str], **properties) -> None:
            if not source or not target or source == target:
                return
            key = (kind, source, target)
            if key in emitted:
                return
            emitted.add(key)
            edges.append({
                "kind": kind, "source": source, "target": target,
                "properties": {**_fact(evidence), **properties},
            })

        callable_kinds = {"function", "method", "constructor"}
        for callable_node in index.nodes_of_kind(*callable_kinds):
            callable_targets[callable_node["id"]].add(callable_node["id"])

        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            if kind in {"OVERRIDES", "IMPLEMENTS_MEMBER", "IMPLEMENTED_BY"}:
                source = index.nodes.get(edge["source"])
                target = index.nodes.get(edge["target"])
                if source and target and source.get("kind") in callable_kinds \
                        and target.get("kind") in callable_kinds:
                    if kind == "IMPLEMENTED_BY":
                        implementations[source["id"]].add(target["id"])
                    else:
                        implementations[target["id"]].add(source["id"])
            elif kind == "FUNCTION_VALUE":
                callable_targets[edge["target"]].add(edge["source"])
            elif kind in {"ALIASES", "ALIASES_VALUE", "READS_FROM", "PHI_INPUT"}:
                identity_edges.append((edge["source"], edge["target"]))
            elif kind == "VALUE_FLOWS_TO" and edge.get("properties", {}).get(
                "reason"
            ) in IDENTITY_REASONS:
                identity_edges.append((edge["source"], edge["target"]))
            elif kind == "DEFINES":
                identity_edges.append((edge["target"], edge["source"]))
            elif kind == "AST_CHILD":
                ast_children[edge["source"]].append((edge["target"], edge.get("properties", {})))
            elif kind == "REFERS_TO":
                references[edge["source"]].add(edge["target"])
            elif kind == "READ_EVIDENCED_BY":
                read_by_evidence[edge["target"]].append(edge["source"])

        changed = True
        while changed:
            changed = False
            for source, target in identity_edges:
                before = len(callable_targets[target])
                callable_targets[target].update(callable_targets.get(source, set()))
                changed |= len(callable_targets[target]) != before

        # Override and implementation relationships are transitively closed so
        # a call resolved to an interface/base declaration keeps every concrete
        # runtime candidate explicit.
        changed = True
        while changed:
            changed = False
            for base, direct in list(implementations.items()):
                expanded = set(direct)
                for implementation in direct:
                    expanded.update(implementations.get(implementation, set()))
                before = len(implementations[base])
                implementations[base].update(expanded)
                changed |= len(implementations[base]) != before

        def descendant_references(root_id: str) -> set[str]:
            result: set[str] = set()
            queue = [root_id]
            seen = set(queue)
            while queue:
                current = queue.pop()
                result.update(references.get(current, set()))
                for read_id in read_by_evidence.get(current, []):
                    result.add(read_id)
                for child, _properties in ast_children.get(current, []):
                    if child not in seen:
                        seen.add(child)
                        queue.append(child)
            return result

        bindings_by_parameter: dict[str, list[str]] = defaultdict(list)
        callbacks_by_argument: dict[str, set[str]] = defaultdict(set)
        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            if kind == "ARGUMENT_BINDS_PARAMETER":
                bindings_by_parameter[edge["target"]].append(edge["source"])
            elif kind == "PASSES_CALLBACK":
                callbacks_by_argument[edge["source"]].add(edge["target"])

        for call in index.nodes_of_kind("call", "construct"):
            call_id = call["id"]
            direct_targets = {
                edge["target"] for edge in index.outgoing.get(call_id, [])
                if edge.get("kind") in {"INVOKES", "MAY_INVOKE"}
            }
            for target_id in sorted(direct_targets):
                for implementation_id in sorted(implementations.get(target_id, set())):
                    add_edge(
                        "MAY_INVOKE", call_id, implementation_id,
                        [call_id, target_id, implementation_id],
                        reason="override-or-interface-implementation",
                        declaration_target_id=target_id,
                    )

            callee_roots = [
                target for target, properties in ast_children.get(call_id, [])
                if properties.get("role") == "CALLEE"
            ]
            referenced_values = set().union(*(
                descendant_references(root) for root in callee_roots
            )) if callee_roots else set()
            for referenced_id in sorted(referenced_values):
                for target_id in sorted(callable_targets.get(referenced_id, set())):
                    add_edge(
                        "MAY_INVOKE", call_id, target_id,
                        [call_id, referenced_id, target_id],
                        reason="function-valued-reference",
                    )
                referenced = index.nodes.get(referenced_id, {})
                if referenced.get("kind") != "parameter":
                    continue
                for argument_id in bindings_by_parameter.get(referenced_id, []):
                    targets = set(callbacks_by_argument.get(argument_id, set()))
                    targets.update(callable_targets.get(argument_id, set()))
                    for target_id in sorted(targets):
                        add_edge(
                            "MAY_INVOKE", call_id, target_id,
                            [call_id, referenced_id, argument_id, target_id],
                            reason="contextual-callback-binding",
                            argument_id=argument_id,
                        )

            receiver_id = call.get("properties", {}).get("receiver_value_id")
            for target_id in sorted(callable_targets.get(receiver_id, set())):
                add_edge(
                    "MAY_INVOKE", call_id, target_id,
                    [call_id, receiver_id, target_id],
                    reason="callable-receiver",
                )

        # Name-fallback resolution. A call the compiler and the passes above left
        # entirely unresolved (no INVOKES/MAY_INVOKE, no primary target) otherwise
        # projects `call_targets: None` — the projection is faithful, the graph is
        # just missing the edge for the common cross-module / dynamically-referenced
        # case. If exactly one project callable shares the callee's last name we
        # emit a low-confidence MAY_INVOKE; several matches are emitted as
        # low-confidence polymorphic candidates. Never overrides a real resolution.
        callables_by_name: dict[str, list[str]] = defaultdict(list)
        for callable_node in index.nodes_of_kind(*callable_kinds):
            properties = callable_node.get("properties", {})
            name = properties.get("name") or _last_name(
                str(callable_node.get("label", ""))
            )
            if name:
                callables_by_name[name].append(callable_node["id"])

        resolved_call_ids = {source for _kind, source, _target in emitted}
        for call in index.nodes_of_kind("call", "construct"):
            call_id = call["id"]
            properties = call.get("properties", {})
            if properties.get("primary_target_id"):
                continue
            if any(
                edge.get("kind") in {"INVOKES", "MAY_INVOKE"}
                for edge in index.outgoing.get(call_id, [])
            ):
                continue
            if call_id in resolved_call_ids:
                continue
            name = properties.get("method_name") or _last_name(
                str(properties.get("callee") or call.get("label", ""))
            )
            candidates = sorted(
                target for target in callables_by_name.get(name, [])
                if target != call_id
            )
            if not candidates:
                continue
            reason = "name-fallback" if len(candidates) == 1 \
                else "name-fallback-polymorphic"
            for target_id in candidates:
                add_edge(
                    "MAY_INVOKE", call_id, target_id,
                    [call_id, target_id], confidence="low", reason=reason,
                )

        return GraphDelta(self.overlay_id, [], edges)
