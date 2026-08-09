"""Structured manual control-flow graph construction."""
import hashlib
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Set, Tuple


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def build_control_flow(info: dict) -> None:
    scopes = {scope["id"]: scope for scope in info["scopes"]}
    statements = {statement["id"]: statement for statement in info["statements"]}
    operations_by_expression = {
        operation["expression_id"]: operation for operation in info["operations"]
    }
    cfg_nodes = []
    cfg_edges = []
    unreachable = []
    try_exception_targets = {}

    def add_node(kind: str, function_id: str, label: str, line: Optional[int] = None, **properties) -> str:
        node_id = stable_id("cfg", info["path_hash"], function_id, kind, label, line, len(cfg_nodes))
        cfg_nodes.append({
            "id": node_id, "kind": kind, "function_id": function_id,
            "label": label, "line": line, "properties": properties,
        })
        return node_id

    def add_edge(kind: str, source: Optional[str], target: Optional[str], **properties):
        if source and target:
            edge = {"kind": kind, "source": source, "target": target, "properties": properties}
            if edge not in cfg_edges:
                cfg_edges.append(edge)

    def controlled_scope(statement: dict, kinds: Set[str]) -> Optional[dict]:
        candidates = [
            scope for scope in scopes.values()
            if scope["kind"] in kinds
            and scope.get("parent_scope_id") == statement["scope_id"]
            and statement["start_offset"] <= scope.get("start_offset", 0) <= statement["end_offset"] + 1
        ]
        return min(candidates, key=lambda scope: scope["start_offset"], default=None)

    def direct_statements(scope_id: str, function_id: str) -> List[dict]:
        # Headerless lexical blocks (for example `case 'x': { ... }`)
        # introduce scope but no executable statement of their own. Flatten
        # those blocks into the surrounding execution sequence while keeping
        # control scopes opaque until their header is evaluated.
        visible_scopes = {scope_id}
        changed = True
        while changed:
            changed = False
            for candidate in scopes.values():
                if (
                    candidate["kind"] == "block"
                    and candidate.get("parent_scope_id") in visible_scopes
                    and candidate["id"] not in visible_scopes
                ):
                    visible_scopes.add(candidate["id"])
                    changed = True
        return sorted(
            (
                statement for statement in statements.values()
                if statement["function_id"] == function_id
                and statement["scope_id"] in visible_scopes
                and not statement.get("parent_statement_id")
            ),
            key=lambda statement: (statement["start_offset"], -statement["end_offset"]),
        )

    def nested_statements(statement_id: str) -> List[dict]:
        return sorted(
            (
                statement for statement in statements.values()
                if statement.get("parent_statement_id") == statement_id
            ),
            key=lambda statement: statement["start_offset"],
        )

    def control_expression(statement: dict) -> Optional[str]:
        candidates = [
            expression for expression in info["expressions"]
            if "condition" in expression.get("roles", [])
            and statement["start_offset"] <= expression["start_offset"]
            and expression["end_offset"] <= statement["end_offset"]
        ]
        expression = min(
            candidates,
            key=lambda item: item["end_offset"] - item["start_offset"],
            default=None,
        )
        if not expression:
            return None
        operation = operations_by_expression.get(expression["id"])
        return operation["id"] if operation else expression["id"]

    def inline_body(statement: dict, test_id: Optional[str], function_id: str) -> Optional[str]:
        nested = nested_statements(statement["id"])
        if nested:
            return nested[0]["id"]
        condition_end = statement["start_offset"]
        for expression in info["expressions"]:
            candidate = operations_by_expression.get(expression["id"])
            candidate_id = candidate["id"] if candidate else expression["id"]
            if candidate_id == test_id:
                condition_end = expression["end_offset"]
                break
        operations = [
            operation for operation in info["operations"]
            if operation.get("function_id") == function_id
            and condition_end <= operation["start_offset"]
            and operation["end_offset"] <= statement["end_offset"]
            and operation["id"] != test_id
        ]
        if operations:
            return max(operations, key=lambda operation: operation["end_offset"])["id"]
        if condition_end < statement["end_offset"] - 1:
            return add_node(
                "inline-body", function_id, f"inline body line {statement['start_line']}",
                statement["start_line"], statement_id=statement["id"],
            )
        return None

    for function in info["functions"]:
        function_id = function["id"]
        entry = add_node("entry", function_id, f"{function['name']} entry", function["start_line"])
        exit_node = add_node("exit", function_id, f"{function['name']} exit", function["end_line"])
        function["cfg_entry_id"] = entry
        function["cfg_exit_id"] = exit_node
        finally_resume_targets = []

        def build_sequence(
            items: List[dict], break_target: Optional[str] = None,
            continue_target: Optional[str] = None,
            exception_target: Optional[str] = None,
            finally_target: Optional[str] = None,
        ) -> Tuple[Optional[str], Set[str]]:
            sequence_entry = None
            previous_exits: Set[str] = set()
            index = 0
            while index < len(items):
                statement = items[index]
                else_statement = None
                catch_statement = None
                finally_statement = None
                consumed = 1
                if statement["kind"] == "if-statement" and index + 1 < len(items):
                    if items[index + 1]["kind"] == "else-statement":
                        else_statement = items[index + 1]
                        consumed = 2
                if statement["kind"] == "try-statement":
                    cursor = index + 1
                    if cursor < len(items) and items[cursor]["kind"] == "catch-statement":
                        catch_statement = items[cursor]
                        cursor += 1
                    if cursor < len(items) and items[cursor]["kind"] == "finally-statement":
                        finally_statement = items[cursor]
                        cursor += 1
                    consumed = cursor - index

                current_entry, current_exits = build_statement(
                    statement, else_statement, catch_statement, finally_statement,
                    break_target, continue_target, exception_target, finally_target,
                )
                if sequence_entry is None:
                    sequence_entry = current_entry
                for previous in previous_exits:
                    add_edge("CFG_NEXT", previous, current_entry)
                previous_exits = current_exits
                index += consumed
            return sequence_entry, previous_exits

        def body_for(
            header: dict, scope_kinds: Set[str], break_target=None,
            continue_target=None, exception_target=None, finally_target=None,
        ) -> Tuple[Optional[str], Set[str], Optional[dict]]:
            scope = controlled_scope(header, scope_kinds)
            if scope:
                body_items = direct_statements(scope["id"], function_id)
                body_entry, body_exits = build_sequence(
                    body_items, break_target, continue_target,
                    exception_target, finally_target,
                )
                return body_entry, body_exits, scope
            inline = nested_statements(header["id"])
            if inline:
                body_entry, body_exits = build_sequence(
                    inline, break_target, continue_target,
                    exception_target, finally_target,
                )
                return body_entry, body_exits, None
            return None, set(), None

        def build_statement(
            statement: dict, else_statement: Optional[dict],
            catch_statement: Optional[dict], finally_statement: Optional[dict],
            break_target: Optional[str], continue_target: Optional[str],
            exception_target: Optional[str], finally_target: Optional[str],
        ) -> Tuple[str, Set[str]]:
            kind = statement["kind"]
            statement_id = statement["id"]

            if kind == "return":
                if finally_target:
                    add_edge("CFG_FINALLY", statement_id, finally_target, completion="return")
                    finally_resume_targets.append(exit_node)
                else:
                    add_edge("CFG_RETURN", statement_id, exit_node)
                return statement_id, set()
            if kind == "throw":
                target = exception_target or finally_target or exit_node
                add_edge("CFG_THROW", statement_id, target)
                return statement_id, set()
            if kind == "break":
                add_edge("CFG_BREAK", statement_id, break_target or exit_node)
                return statement_id, set()
            if kind == "continue":
                add_edge("CFG_CONTINUE", statement_id, continue_target or exit_node)
                return statement_id, set()

            if kind == "if-statement":
                merge = add_node("merge", function_id, f"if merge line {statement['start_line']}", statement["end_line"])
                test = control_expression(statement) or statement_id
                if test != statement_id:
                    add_edge("CFG_EVALUATES", statement_id, test)
                body_entry, body_exits, _scope = body_for(
                    statement, {"if"}, break_target, continue_target,
                    exception_target, finally_target,
                )
                inline_entry = None
                if body_entry is None:
                    inline_entry = inline_body(statement, test, function_id)
                    body_entry = inline_entry
                add_edge("CFG_TRUE", test, body_entry or merge)
                for body_exit in body_exits or ({inline_entry} if inline_entry else set()):
                    add_edge("CFG_NEXT", body_exit, merge)

                if else_statement:
                    inline_else = None
                    else_test = control_expression(else_statement)
                    else_entry, else_exits, _else_scope = body_for(
                        else_statement,
                        {"else", "if"} if else_test else {"else"},
                        break_target, continue_target,
                        exception_target, finally_target,
                    )
                    if else_test:
                        add_edge("CFG_FALSE", test, else_statement["id"])
                        add_edge("CFG_EVALUATES", else_statement["id"], else_test)
                        inline_else = else_entry or inline_body(
                            else_statement, else_test, function_id
                        )
                        add_edge("CFG_TRUE", else_test, inline_else or merge)
                        add_edge("CFG_FALSE", else_test, merge)
                        else_entry = else_statement["id"]
                        if inline_else and not else_exits:
                            else_exits = {inline_else}
                    else:
                        inline_else = None
                        if else_entry is None:
                            inline_else = inline_body(
                            else_statement, None, function_id
                            )
                            else_entry = inline_else
                        add_edge("CFG_FALSE", test, else_statement["id"])
                        if else_entry and else_entry != else_statement["id"]:
                            add_edge("CFG_NEXT", else_statement["id"], else_entry)
                        elif not else_entry:
                            else_entry = else_statement["id"]
                    for else_exit in else_exits or (
                        {inline_else} if inline_else
                        else {else_entry} if else_entry == else_statement["id"]
                        else set()
                    ):
                        add_edge("CFG_NEXT", else_exit, merge)
                else:
                    add_edge("CFG_FALSE", test, merge)
                return statement_id, {merge}

            if kind in {"for-statement", "while-statement", "do-statement"}:
                merge = add_node("loop-merge", function_id, f"loop exit line {statement['start_line']}", statement["end_line"])
                test = control_expression(statement) or statement_id
                if test != statement_id:
                    add_edge("CFG_EVALUATES", statement_id, test)
                body_entry, body_exits, _scope = body_for(
                    statement, {"for", "while", "do"}, merge, test,
                    exception_target, finally_target,
                )
                body_entry = body_entry or inline_body(statement, test, function_id)
                add_edge("CFG_TRUE", test, body_entry or test)
                add_edge("CFG_FALSE", test, merge)
                for body_exit in body_exits or ({body_entry} if body_entry else set()):
                    add_edge("CFG_BACK", body_exit, test)
                return statement_id, {merge}

            if kind == "switch-statement":
                merge = add_node("switch-merge", function_id, f"switch merge line {statement['start_line']}", statement["end_line"])
                test = control_expression(statement) or statement_id
                if test != statement_id:
                    add_edge("CFG_EVALUATES", statement_id, test)
                switch_scope = controlled_scope(statement, {"switch"})
                switch_items = direct_statements(switch_scope["id"], function_id) if switch_scope else []
                cases = [item for item in switch_items if item["kind"] in {"case-statement", "default-statement"}]
                has_default = False
                for case_index, case in enumerate(cases):
                    has_default |= case["kind"] == "default-statement"
                    add_edge(
                        "CFG_DEFAULT" if case["kind"] == "default-statement" else "CFG_CASE",
                        test, case["id"], label=case["text"].rstrip(":").strip(),
                    )
                    case_start = switch_items.index(case)
                    case_end = (
                        switch_items.index(cases[case_index + 1])
                        if case_index + 1 < len(cases) else len(switch_items)
                    )
                    segment = switch_items[case_start:case_end]
                    segment_entry, segment_exits = build_sequence(
                        segment, merge, continue_target, exception_target, finally_target
                    )
                    for segment_exit in segment_exits:
                        next_case = cases[case_index + 1]["id"] if case_index + 1 < len(cases) else merge
                        add_edge("CFG_FALLTHROUGH", segment_exit, next_case)
                if not has_default:
                    add_edge("CFG_NO_MATCH", test, merge)
                return statement_id, {merge}

            if kind == "try-statement":
                merge = add_node("try-merge", function_id, f"try merge line {statement['start_line']}", statement["end_line"])
                finally_entry = None
                finally_exits: Set[str] = set()
                if finally_statement:
                    finally_body_entry, finally_exits, _ = body_for(
                        finally_statement, {"finally"}, break_target, continue_target,
                        exception_target, None,
                    )
                    finally_entry = finally_statement["id"]
                    if finally_body_entry:
                        add_edge("CFG_NEXT", finally_entry, finally_body_entry)
                    else:
                        finally_exits = {finally_entry}
                catch_entry = None
                catch_exits: Set[str] = set()
                if catch_statement:
                    catch_body_entry, catch_exits, catch_scope = body_for(
                        catch_statement, {"catch"}, break_target, continue_target,
                        finally_entry or exception_target, finally_entry,
                    )
                    catch_entry = catch_statement["id"]
                    if catch_body_entry:
                        add_edge("CFG_NEXT", catch_entry, catch_body_entry)
                    else:
                        catch_exits = {catch_entry}
                try_entry, try_exits, try_scope = body_for(
                    statement, {"try"}, break_target, continue_target,
                    catch_entry or finally_entry or exception_target,
                    finally_entry,
                )
                try_entry = try_entry or statement_id
                add_edge("CFG_NEXT", statement_id, try_entry)
                if try_scope:
                    try_exception_targets[try_scope["id"]] = catch_entry or finally_entry or exception_target or exit_node
                normal_exits = set(try_exits) | set(catch_exits)
                if finally_entry:
                    for normal_exit in normal_exits:
                        add_edge("CFG_FINALLY", normal_exit, finally_entry, completion="normal")
                    for final_exit in finally_exits or {finally_entry}:
                        add_edge("CFG_NEXT", final_exit, merge, completion="normal")
                        for resume in finally_resume_targets:
                            add_edge("CFG_RETURN", final_exit, resume, completion="return")
                else:
                    for normal_exit in normal_exits:
                        add_edge("CFG_NEXT", normal_exit, merge)
                return statement_id, {merge} if normal_exits or finally_entry else set()

            # Ordinary statement; expression operations remain connected via
            # CFG_EVALUATES but the statement is the sequencing unit.
            contained_operations = [
                operation for operation in info["operations"]
                if statement["start_offset"] <= operation["start_offset"]
                and operation["end_offset"] <= statement["end_offset"]
            ]
            roots = [
                operation for operation in contained_operations
                if not any(
                    item["source"] == operation["id"]
                    for item in info["operation_inputs"]
                    if item["target"] in {candidate["id"] for candidate in contained_operations}
                )
            ]
            for operation in roots:
                add_edge("CFG_EVALUATES", statement_id, operation["id"])
            return statement_id, {statement_id}

        function_scope_id = function.get("scope_id")
        function_items = direct_statements(function_scope_id, function_id)
        body_entry, body_exits = build_sequence(function_items)
        add_edge("CFG_ENTRY", entry, body_entry or exit_node)
        for body_exit in body_exits:
            add_edge("CFG_EXIT", body_exit, exit_node)

        # Calls in a try region may transfer control to its handler.
        for call in info["function_calls"]:
            if call.get("caller_function_id") != function_id:
                continue
            scope_id = call.get("scope_id")
            while scope_id:
                if scope_id in try_exception_targets:
                    attachment = next(
                        (
                            item for item in info["body_attachments"]
                            if item["entity_kind"] == "CALL"
                            and item["entity_id"] == call["id"]
                        ),
                        None,
                    )
                    add_edge(
                        "CFG_EXCEPTION",
                        (attachment or {}).get("statement_id") or call["id"],
                        try_exception_targets[scope_id], reason="call-may-throw",
                        call_id=call["id"],
                    )
                    break
                scope_id = scopes[scope_id].get("parent_scope_id")

        # Mark statements disconnected by terminal control transfer.
        adjacency = defaultdict(list)
        for edge in cfg_edges:
            if edge["kind"] != "CFG_UNREACHABLE":
                adjacency[edge["source"]].append(edge["target"])
        reachable = {entry}
        queue = deque([entry])
        while queue:
            source = queue.popleft()
            for target in adjacency[source]:
                if target not in reachable:
                    reachable.add(target)
                    queue.append(target)
        for statement in statements.values():
            if statement["function_id"] == function_id and statement["id"] not in reachable:
                unreachable.append({
                    "statement_id": statement["id"], "function_id": function_id,
                    "reason": "no-control-flow-predecessor",
                })
                add_edge("CFG_UNREACHABLE", entry, statement["id"])

    # Expression-local branching for lazy operations.
    operation_inputs = defaultdict(dict)
    for item in info["operation_inputs"]:
        operation_inputs[item["target"]][item["role"]] = item["source"]
    for operation in info["operations"]:
        inputs = operation_inputs[operation["id"]]
        if operation["kind"] == "logical":
            left = inputs.get("LEFT_OPERAND")
            right = inputs.get("RIGHT_OPERAND")
            condition = {
                "&&": "truthy", "||": "falsy", "??": "nullish",
            }.get(operation.get("operator"), "conditional")
            add_edge("CFG_EVALUATE_RIGHT", left, right, condition=condition)
            add_edge("CFG_SHORT_CIRCUIT", left, operation["id"], condition=f"not-{condition}")
            add_edge("CFG_OPERATION_RESULT", right, operation["id"])
        elif operation["kind"] == "conditional":
            condition = inputs.get("CONDITION")
            true_value = inputs.get("TRUE_VALUE")
            false_value = inputs.get("FALSE_VALUE")
            add_edge("CFG_TRUE", condition, true_value)
            add_edge("CFG_FALSE", condition, false_value)
            add_edge("CFG_OPERATION_RESULT", true_value, operation["id"])
            add_edge("CFG_OPERATION_RESULT", false_value, operation["id"])
        elif operation["kind"] == "property-access" and operation.get("operator") == "?.":
            receiver = inputs.get("RECEIVER")
            add_edge("CFG_OPTIONAL_PRESENT", receiver, operation["id"])
            add_edge("CFG_OPTIONAL_NULLISH", receiver, operation["id"], short_circuit=True)

    info["cfg_nodes"] = cfg_nodes
    info["cfg_edges"] = cfg_edges
    info["unreachable"] = unreachable
