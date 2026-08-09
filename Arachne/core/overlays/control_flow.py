"""Language-neutral control-flow graph construction from canonical AST facts."""
from __future__ import annotations

from collections import defaultdict, deque

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


LOOP_KINDS = frozenset({"for", "for-each", "while", "do-while"})
TERMINAL_KINDS = frozenset({"return", "throw"})
BRANCHING_KINDS = frozenset({"if", "switch", *LOOP_KINDS})
CONTAINER_KINDS = frozenset({"try", *BRANCHING_KINDS})


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference",
        "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


class ControlFlow:
    """Build explicit entry/condition/merge/exit nodes for every function."""

    overlay_id = "control-flow"

    def applies(self, graph: dict) -> bool:
        return any(
            node.get("kind") in {"function", "method", "constructor"}
            for node in graph.get("nodes", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        emitted: set[tuple[str, str, str]] = set()
        ast_children: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
        ast_parent: dict[str, str] = {}
        sequential: dict[str, list[str]] = defaultdict(list)
        contained: dict[str, list[str]] = defaultdict(list)
        direct_control: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)

        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            if kind == "AST_CHILD":
                child = index.nodes.get(edge["target"])
                if child:
                    ast_children[edge["source"]].append((child, edge.get("properties", {})))
                    ast_parent[edge["target"]] = edge["source"]
            elif kind == "EXECUTES_BEFORE":
                sequential[edge["source"]].append(edge["target"])
            elif kind == "CONTAINS_BODY":
                contained[edge["source"]].append(edge["target"])
            elif kind in {
                "CONDITION", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_TRUE",
                "LOOP_BACK", "SWITCH_CASE", "EXCEPTION_BRANCH", "TRY_BODY",
                "RUNS_FINALLY", "BREAKS_TO", "CONTINUES_TO",
                "ITERATES", "SHORT_CIRCUIT_LEFT", "SHORT_CIRCUIT_RIGHT",
            }:
                direct_control[edge["source"]].append((
                    kind, edge["target"], edge.get("properties", {}),
                ))

        def position(node_id: str) -> tuple[int, int]:
            properties = index.nodes.get(node_id, {}).get("properties", {})
            return (
                properties.get("start_offset", 1 << 60),
                properties.get("end_offset", 1 << 60),
            )

        def add_edge(
            kind: str, source: str, target: str, evidence: list[str], **properties,
        ) -> None:
            if not source or not target or source == target:
                return
            key = (kind, source, target)
            if key in emitted:
                return
            emitted.add(key)
            edges.append({
                "kind": kind,
                "source": source,
                "target": target,
                "properties": {**_fact(evidence), **properties},
            })

        def statement_children(node_id: str, owner_id: str) -> list[str]:
            result = [
                child["id"] for child, _properties in ast_children.get(node_id, [])
                if child.get("kind") == "statement"
                and child.get("properties", {}).get("owner_function_id") == owner_id
            ]
            return sorted(dict.fromkeys(result), key=position)

        def branch_end(node_id: str, owner_id: str) -> str:
            children = statement_children(node_id, owner_id)
            return branch_end(children[-1], owner_id) if children else node_id

        def same_owner_successors(node_id: str, owner_id: str) -> list[str]:
            return sorted((
                target for target in sequential.get(node_id, [])
                if index.nodes.get(target, {}).get("properties", {}).get(
                    "owner_function_id"
                ) == owner_id
            ), key=position)

        for function in index.nodes_of_kind("function", "method", "constructor"):
            function_id = function["id"]
            owned_statements = [
                node for node in index.nodes_of_kind("statement")
                if node.get("properties", {}).get("owner_function_id") == function_id
            ]
            entry_id = stable_id(
                "core", self.overlay_id, "cfg-entry", function_id,
            )
            exit_id = stable_id(
                "core", self.overlay_id, "cfg-exit", function_id,
            )
            function_fact = _fact([function_id], "exact")
            nodes.extend([
                {
                    "id": entry_id, "kind": "cfg-entry",
                    "label": f"entry:{function.get('label', function_id)}",
                    "properties": {**function_fact, "function_id": function_id},
                },
                {
                    "id": exit_id, "kind": "cfg-exit",
                    "label": f"exit:{function.get('label', function_id)}",
                    "properties": {**function_fact, "function_id": function_id},
                },
            ])
            top_level = sorted(
                (
                    node_id for node_id in contained.get(function_id, [])
                    if index.nodes.get(node_id, {}).get("kind") == "statement"
                    and index.nodes[node_id].get("properties", {}).get("owner_function_id")
                        == function_id
                ),
                key=position,
            )
            if top_level:
                add_edge("CFG_NEXT", entry_id, top_level[0], [function_id, top_level[0]])
            else:
                add_edge("CFG_NEXT", entry_id, exit_id, [function_id])

            # Blocks execute their first statement and their children execute in
            # source order. Frontends may additionally provide exact sequence
            # edges; both forms collapse through the deduplication above.
            for statement in owned_statements:
                statement_id = statement["id"]
                children = statement_children(statement_id, function_id)
                if children:
                    add_edge("CFG_NEXT", statement_id, children[0], [statement_id, children[0]])
                    for left, right in zip(children, children[1:]):
                        left_kind = index.nodes[left].get("properties", {}).get("control_kind")
                        if left_kind not in TERMINAL_KINDS | CONTAINER_KINDS:
                            add_edge("CFG_NEXT", left, right, [left, right])

            merge_by_container: dict[str, str] = {}
            condition_by_container: dict[str, str] = {}
            exception_target_by_region: dict[str, str] = {}
            for statement in owned_statements:
                statement_id = statement["id"]
                control_kind = statement.get("properties", {}).get("control_kind")
                if control_kind not in BRANCHING_KINDS:
                    continue
                condition_targets = [
                    target for kind, target, _properties
                    in direct_control.get(statement_id, []) if kind == "CONDITION"
                ]
                if not condition_targets:
                    condition_targets = [
                        child["id"] for child, properties in ast_children.get(statement_id, [])
                        if properties.get("role") in {"CONDITION", "ITERABLE"}
                    ]
                condition_target = condition_targets[0] if condition_targets else statement_id
                condition_id = stable_id(
                    "core", self.overlay_id, "cfg-condition",
                    function_id, statement_id, condition_target,
                )
                merge_id = stable_id(
                    "core", self.overlay_id, "cfg-merge", function_id, statement_id,
                )
                evidence = [statement_id, condition_target]
                nodes.extend([
                    {
                        "id": condition_id, "kind": "cfg-condition",
                        "label": f"condition:{statement.get('label', statement_id)}",
                        "properties": {
                            **_fact(evidence), "function_id": function_id,
                            "body_id": condition_target, "control_kind": control_kind,
                        },
                    },
                    {
                        "id": merge_id, "kind": "cfg-merge",
                        "label": f"merge:{statement.get('label', statement_id)}",
                        "properties": {
                            **_fact(evidence), "function_id": function_id,
                            "container_id": statement_id,
                        },
                    },
                ])
                condition_by_container[statement_id] = condition_id
                merge_by_container[statement_id] = merge_id
                add_edge("CFG_NEXT", statement_id, condition_id, evidence)

                branch_edges = [
                    (kind, target, properties)
                    for kind, target, properties in direct_control.get(condition_target, [])
                    if kind in {
                        "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_TRUE",
                        "SWITCH_CASE", "ITERATES",
                    }
                ]
                if not branch_edges:
                    for child, properties in ast_children.get(statement_id, []):
                        role = properties.get("role")
                        if role in {"TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BODY"}:
                            branch_edges.append((
                                "LOOP_TRUE" if role == "LOOP_BODY" else role,
                                child["id"], properties,
                            ))
                has_false = False
                for edge_kind, target, properties in branch_edges:
                    cfg_kind = "TRUE_BRANCH" if edge_kind in {
                        "TRUE_BRANCH", "LOOP_TRUE", "ITERATES",
                    } else edge_kind
                    if cfg_kind == "FALSE_BRANCH":
                        has_false = True
                    add_edge(cfg_kind, condition_id, target, [*evidence, target], **{
                        key: value for key, value in properties.items()
                        if key not in {"fact_origin", "confidence", "evidence_ids"}
                    })
                    end = branch_end(target, function_id)
                    end_kind = index.nodes.get(end, {}).get("properties", {}).get("control_kind")
                    if control_kind in LOOP_KINDS and cfg_kind == "TRUE_BRANCH":
                        if end_kind not in TERMINAL_KINDS | {"break", "continue"}:
                            add_edge("LOOP_BACK", end, condition_id, [end, condition_target])
                    elif end_kind not in TERMINAL_KINDS | {"break", "continue"}:
                        add_edge("MERGES_AT", end, merge_id, [end, statement_id])
                if control_kind in {"if", *LOOP_KINDS} and not has_false:
                    add_edge("FALSE_BRANCH", condition_id, merge_id, evidence)

                successors = same_owner_successors(statement_id, function_id)
                add_edge(
                    "CFG_NEXT", merge_id, successors[0] if successors else exit_id,
                    [statement_id, *(successors[:1] or [function_id])],
                )

            # Exception regions are not boolean conditions. Preserve their
            # normal, exceptional and finally continuations explicitly.
            for statement in owned_statements:
                statement_id = statement["id"]
                if statement.get("properties", {}).get("control_kind") != "try":
                    continue
                merge_id = stable_id(
                    "core", self.overlay_id, "cfg-merge", function_id, statement_id,
                )
                evidence = [statement_id]
                nodes.append({
                    "id": merge_id, "kind": "cfg-merge",
                    "label": f"merge:{statement.get('label', statement_id)}",
                    "properties": {
                        **_fact(evidence), "function_id": function_id,
                        "container_id": statement_id,
                    },
                })
                merge_by_container[statement_id] = merge_id
                try_targets = [
                    target for kind, target, _properties
                    in direct_control.get(statement_id, []) if kind == "TRY_BODY"
                ]
                if not try_targets:
                    try_targets = [
                        child["id"] for child, properties
                        in ast_children.get(statement_id, [])
                        if properties.get("role") == "TRY_BODY"
                    ]
                if not try_targets:
                    continue
                try_body = try_targets[0]
                catch_targets = [
                    target for kind, target, _properties
                    in direct_control.get(try_body, []) if kind == "EXCEPTION_BRANCH"
                ]
                finally_targets = [
                    target for source in (try_body, *catch_targets)
                    for kind, target, _properties in direct_control.get(source, [])
                    if kind == "RUNS_FINALLY"
                ]
                finally_target = finally_targets[0] if finally_targets else None
                add_edge("CFG_NEXT", statement_id, try_body, [statement_id, try_body])
                normal_target = finally_target or merge_id
                try_end = branch_end(try_body, function_id)
                if index.nodes.get(try_end, {}).get("properties", {}).get(
                    "control_kind"
                ) not in TERMINAL_KINDS:
                    add_edge("CFG_NEXT", try_end, normal_target, [try_end, normal_target])
                for catch_target in catch_targets:
                    add_edge(
                        "EXCEPTION_BRANCH", try_body, catch_target,
                        [try_body, catch_target],
                    )
                    exception_target_by_region[try_body] = catch_target
                    catch_end = branch_end(catch_target, function_id)
                    add_edge(
                        "CFG_NEXT", catch_end, finally_target or merge_id,
                        [catch_end, finally_target or merge_id],
                    )
                if not catch_targets:
                    exception_target_by_region[try_body] = finally_target or exit_id
                if finally_target:
                    finally_end = branch_end(finally_target, function_id)
                    add_edge("RUNS_FINALLY", try_end, finally_target, [try_end, finally_target])
                    add_edge("CFG_NEXT", finally_end, merge_id, [finally_end, merge_id])
                successors = same_owner_successors(statement_id, function_id)
                add_edge(
                    "CFG_NEXT", merge_id, successors[0] if successors else exit_id,
                    [statement_id, *(successors[:1] or [function_id])],
                )

            for statement in owned_statements:
                statement_id = statement["id"]
                control_kind = statement.get("properties", {}).get("control_kind")
                if control_kind in TERMINAL_KINDS:
                    target = exit_id
                    if control_kind == "throw":
                        current = statement_id
                        while current in ast_parent:
                            current = ast_parent[current]
                            if current in exception_target_by_region:
                                target = exception_target_by_region[current]
                                break
                    add_edge("CFG_NEXT", statement_id, target, [statement_id, target])
                    continue
                if control_kind in {"break", "continue"}:
                    transfers = direct_control.get(statement_id, [])
                    for kind, target, _properties in transfers:
                        if kind == "BREAKS_TO" and target in merge_by_container:
                            add_edge("CFG_NEXT", statement_id, merge_by_container[target], [statement_id, target])
                        elif kind == "CONTINUES_TO" and target in condition_by_container:
                            add_edge("CFG_NEXT", statement_id, condition_by_container[target], [statement_id, target])
                    continue
                if control_kind in CONTAINER_KINDS:
                    continue
                for successor in same_owner_successors(statement_id, function_id):
                    add_edge("CFG_NEXT", statement_id, successor, [statement_id, successor])

            if top_level:
                last = top_level[-1]
                last_kind = index.nodes[last].get("properties", {}).get("control_kind")
                if last_kind not in TERMINAL_KINDS | CONTAINER_KINDS:
                    add_edge("CFG_NEXT", branch_end(last, function_id), exit_id, [last, function_id])

            cfg_adjacency: dict[str, list[str]] = defaultdict(list)
            for edge in edges:
                if edge["kind"] in {
                    "CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK",
                    "SWITCH_CASE", "EXCEPTION_BRANCH", "RUNS_FINALLY", "MERGES_AT",
                }:
                    cfg_adjacency[edge["source"]].append(edge["target"])
            reachable = {entry_id}
            queue = deque([entry_id])
            while queue:
                current = queue.popleft()
                for target in cfg_adjacency.get(current, []):
                    if target not in reachable:
                        reachable.add(target)
                        queue.append(target)
            for statement in owned_statements:
                if statement["id"] in reachable:
                    continue
                unreachable_id = stable_id(
                    "core", self.overlay_id, "unreachable-region",
                    function_id, statement["id"],
                )
                fact = _fact([function_id, statement["id"]], "high")
                nodes.append({
                    "id": unreachable_id,
                    "kind": "unreachable-region",
                    "label": f"unreachable:{statement.get('label', statement['id'])}",
                    "properties": {
                        **fact,
                        "function_id": function_id,
                        "body_id": statement["id"],
                    },
                })
                add_edge("EVIDENCED_BY", unreachable_id, statement["id"], [statement["id"]])

        return GraphDelta(self.overlay_id, nodes, edges)
