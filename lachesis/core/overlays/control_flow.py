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

    def applies(self, graph: dict, index: GraphIndex | None = None) -> bool:
        index = GraphIndex(graph) if index is None else index
        return index.has_kind("function", "method", "constructor")

    def enrich(self, graph: dict, index: GraphIndex | None = None) -> GraphDelta:
        index = GraphIndex(graph) if index is None else index
        nodes = []
        edges = []
        emitted: set[tuple[str, str, str]] = set()
        ast_children: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
        ast_parent: dict[str, str] = {}
        sequential: dict[str, list[str]] = defaultdict(list)
        contained: dict[str, list[str]] = defaultdict(list)
        direct_control: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)
        # These inputs are immutable during one fold. Cache repeated CFG lookups
        # so nested functions do not rebuild and sort the same statement paths.
        statement_children_cache: dict[tuple[str, str], list[str]] = {}
        successor_cache: dict[tuple[str, str], list[str]] = {}
        branch_end_cache: dict[tuple[str, str], str] = {}
        position_cache: dict[str, tuple[int, int]] = {}

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
            cached = position_cache.get(node_id)
            if cached is not None:
                return cached
            properties = index.nodes.get(node_id, {}).get("properties", {})
            result = (
                properties.get("start_offset", 1 << 60),
                properties.get("end_offset", 1 << 60),
            )
            position_cache[node_id] = result
            return result

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
            cache_key = (node_id, owner_id)
            cached = statement_children_cache.get(cache_key)
            if cached is not None:
                return cached
            # A block's direct AST children ARE its statement sequence. Most are
            # `statement` nodes, but an expression-statement (`free(p);`, `use(p);`,
            # `x = f();`) is emitted by the frontends as a bare `call`/`expression`
            # node, not wrapped in a `statement`. Adopt those too when the container is
            # a block, so they enter control flow instead of being orphaned (without
            # this, every bare call-statement has no CFG edge and typestate/reaching
            # analyses never see the free/use). Gate on control_kind=='block' so we
            # never pull a nested sub-expression (e.g. a DeclStmt's initializer call)
            # into statement position.
            in_block = (
                index.nodes.get(node_id, {}).get("properties", {}).get("control_kind")
                == "block"
            )
            result = [
                child["id"] for child, _properties in ast_children.get(node_id, [])
                if child.get("properties", {}).get("owner_function_id") == owner_id
                and (
                    child.get("kind") == "statement"
                    or (in_block and child.get("kind") in ("call", "expression"))
                )
            ]
            result = sorted(dict.fromkeys(result), key=position)
            statement_children_cache[cache_key] = result
            return result

        def branch_end(node_id: str, owner_id: str) -> str:
            cache_key = (node_id, owner_id)
            cached = branch_end_cache.get(cache_key)
            if cached is not None:
                return cached
            # Walk the last-child chain to its deepest statement. Iterative, not
            # recursive: a Suricata function nests statements >1000 deep, which
            # overflowed Python's stack when this descended by recursion. The
            # `seen` guard also makes a malformed cyclic chain terminate instead
            # of spinning, which the recursive form could not have survived either.
            seen: set[str] = set()
            while node_id not in seen:
                seen.add(node_id)
                children = statement_children(node_id, owner_id)
                if not children:
                    break
                node_id = children[-1]
            branch_end_cache[cache_key] = node_id
            return node_id

        def next_in_block(node_id: str, owner_id: str) -> list[str]:
            # The statement immediately following node_id in its enclosing block,
            # by source order. Used as a fallback when the frontend gives no explicit
            # sequence edge -- which happens when the following sibling is a bare
            # call/expression-statement the frontend omitted from EXECUTES_BEFORE.
            # Without this, a container (if/for/...) whose next sibling is such a
            # bare call has its merge routed straight to exit, orphaning the call.
            parent = ast_parent.get(node_id)
            if not parent:
                return []
            siblings = statement_children(parent, owner_id)
            if node_id in siblings:
                position_in_block = siblings.index(node_id)
                return siblings[position_in_block + 1:position_in_block + 2]
            return []

        def same_owner_successors(node_id: str, owner_id: str) -> list[str]:
            cache_key = (node_id, owner_id)
            cached = successor_cache.get(cache_key)
            if cached is not None:
                return cached
            explicit = sorted((
                target for target in sequential.get(node_id, [])
                if index.nodes.get(target, {}).get("properties", {}).get(
                    "owner_function_id"
                ) == owner_id
            ), key=position)
            result = explicit or next_in_block(node_id, owner_id)
            successor_cache[cache_key] = result
            return result

        # Bucket statements by owner ONCE (was O(functions x statements) = O(files^2)).
        statements_by_function: dict[str, list[dict]] = defaultdict(list)
        for statement in index.nodes_of_kind("statement"):
            owner = statement.get("properties", {}).get("owner_function_id")
            if owner:
                statements_by_function[owner].append(statement)

        for function in index.nodes_of_kind("function", "method", "constructor"):
            function_id = function["id"]
            # Edges appended below all belong to THIS function; slicing from here
            # avoids re-scanning the whole accumulated edge list per function.
            function_edge_start = len(edges)
            owned_statements = statements_by_function.get(function_id, [])
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
            for edge in edges[function_edge_start:]:
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
