"""Assemble analyzed file records into a small, explicit code graph."""
import hashlib
from typing import Dict, Iterable

from .types import CodeGraph, FileInfo, GraphEdge, GraphNode

CODE_GRAPH: CodeGraph = {"nodes": [], "edges": []}


def reference_id(kind: str, label: str) -> str:
    digest = hashlib.sha256(f"{kind}:{label}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def build_graph(files: Iterable[FileInfo]) -> CodeGraph:
    file_list = list(files)
    nodes: Dict[str, GraphNode] = {}
    edges = []

    def add_node(node_id: str, kind: str, label: str, **properties) -> str:
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "kind": kind,
                "label": label,
                "properties": properties,
            }
        elif nodes[node_id]["kind"] == "data-context" and kind != "data-context":
            # Cross-file/data-flow registration may create a placeholder before
            # the concrete function or value is visited. Upgrade it in place.
            nodes[node_id] = {
                "id": node_id, "kind": kind, "label": label,
                "properties": properties,
            }
        return node_id

    def add_edge(kind: str, source: str, target: str, **properties) -> None:
        edge: GraphEdge = {
            "kind": kind,
            "source": source,
            "target": target,
            "properties": properties,
        }
        edges.append(edge)

    # Register data entities first so cross-file flow edges never depend on
    # traversal order.
    for info in file_list:
        for member in info["dispatch_members"]:
            add_node(
                member["id"], "dispatch-member", member["name"],
                member_kind=member["kind"], owner_type_id=member["owner_type_id"],
                line=member["line"],
            )
        for candidate in info["dispatch_candidates"]:
            add_node(
                candidate["id"], "dispatch-candidate", candidate["kind"],
                call_id=candidate["call_id"], target_id=candidate["target_id"],
                target_name=candidate.get("target_name"),
                target_file=candidate.get("target_file"),
                target_line=candidate.get("target_line"),
                dispatch_kind=candidate["kind"], confidence=candidate["confidence"],
                **candidate.get("properties", {}),
            )
        for behavior in info["dynamic_behaviors"]:
            add_node(
                behavior["id"], "dynamic-behavior", behavior["kind"],
                behavior_kind=behavior["kind"], line=behavior["line"],
                expression=behavior["expression"], function_id=behavior.get("function_id"),
                **behavior.get("properties", {}),
            )
        for model in info["runtime_models"]:
            add_node(
                model["id"], "runtime-model-application", model["model"],
                call_id=model["call_id"], behaviors=model["behaviors"],
                line=model["line"],
            )
        for async_node in info["async_nodes"]:
            add_node(
                async_node["id"], "async-event", async_node["label"],
                async_kind=async_node["kind"], name=async_node["name"],
            )
        for summary in info["effect_summaries"]:
            add_node(
                summary["id"], "effect-summary", summary["function_name"],
                function_id=summary["function_id"], returns=summary["returns"],
                async_function=summary["async"],
            )
            for effect in summary["effects"]:
                add_node(
                    effect["id"], "function-effect", effect["kind"],
                    effect_kind=effect["kind"], path=effect.get("path", ""),
                    parameter_position=effect.get("parameter_position"),
                    target_symbol_id=effect.get("target_symbol_id"),
                )
        for applied in info["applied_effects"]:
            add_node(
                applied["id"], "applied-effect", applied["kind"],
                call_id=applied["call_id"], context_id=applied["context_id"],
                effect_id=applied["effect_id"], path=applied["path"],
                target_ids=applied["target_ids"],
            )
        for parameter in info["type_parameters"]:
            add_node(
                parameter["id"], "type-parameter", parameter["name"],
                owner_id=parameter["owner_id"], position=parameter["position"],
                constraint=parameter.get("constraint"), default=parameter.get("default"),
            )
        for refinement in info["type_refinements"]:
            add_node(
                refinement["id"], "type-refinement", refinement["narrowed_type"],
                refinement_kind=refinement["kind"], symbol_id=refinement["symbol_id"],
                expression_id=refinement["expression_id"],
                true_branch=refinement["true_branch"], line=refinement["line"],
            )
        for substitution in info["generic_substitutions"]:
            add_node(
                substitution["id"], "generic-substitution", "generic substitution",
                call_id=substitution["call_id"], function_id=substitution["function_id"],
                bindings=substitution["bindings"],
            )
        for overload in info["overloads"]:
            add_node(
                overload["id"], "overload", overload["name"], line=overload["line"],
                signature=overload["signature"],
                implementation_id=overload.get("implementation_id"),
            )
        for compatibility in info["type_compatibilities"]:
            add_node(
                compatibility["id"], "type-compatibility", compatibility["kind"],
                source_type_id=compatibility["source_type_id"],
                target_type_id=compatibility["target_type_id"],
                matched_members=compatibility["matched_members"],
            )
        for source in info["taint_sources"]:
            add_node(
                source["id"], "taint-source", source["label"],
                source_kind=source["kind"], value_id=source["value_id"],
                function_id=source["function_id"], line=source["line"],
                confidence=source["confidence"],
                parent_source_id=source.get("parent_source_id"),
            )
        for tainted_call in info["tainted_calls"]:
            add_node(
                tainted_call["id"], "tainted-call",
                f"{tainted_call['callee']} line {tainted_call['line']}",
                call_id=tainted_call["call_id"],
                source_id=tainted_call["source_id"],
                argument_id=tainted_call["argument_id"],
                context_stack=tainted_call["context_stack"],
                hop_count=tainted_call["hop_count"],
            )
        for source_line in info["source_lines"]:
            add_node(
                source_line["id"], "source-line",
                f"{info['path']}:{source_line['number']}",
                file=info["path"], number=source_line["number"],
                line_kind=source_line["kind"], text=source_line["text"],
                start_offset=source_line["start_offset"],
                end_offset=source_line["end_offset"],
            )
        for token in info["tokens"]:
            add_node(
                token["id"], "token", token["value"],
                token_kind=token["kind"], file=info["path"],
                start_line=token["start_line"], end_line=token["end_line"],
                start_offset=token["start_offset"], end_offset=token["end_offset"],
            )
        for statement in info["statements"]:
            add_node(
                statement["id"], "statement", statement["kind"],
                statement_kind=statement["kind"], file=info["path"],
                text=statement["text"], position=statement["position"],
                scope_id=statement.get("scope_id"),
                start_line=statement["start_line"], end_line=statement["end_line"],
                start_offset=statement["start_offset"],
                end_offset=statement["end_offset"],
            )
        for expression in info["expressions"]:
            add_node(
                expression["id"], "expression", expression["text"],
                expression_kind=expression["kind"], operator=expression.get("operator"),
                file=info["path"], start_line=expression["start_line"],
                end_line=expression["end_line"],
                start_offset=expression["start_offset"],
                end_offset=expression["end_offset"],
            )
        for operation in info["operations"]:
            add_node(
                operation["id"], "operation",
                operation.get("operator") or operation["kind"],
                operation_kind=operation["kind"], operator=operation.get("operator"),
                expression_id=operation["expression_id"], file=info["path"],
                line=operation["line"], text=operation["text"],
                cast_type=operation.get("cast_type"),
            )
        for cfg_node in info["cfg_nodes"]:
            add_node(
                cfg_node["id"], "cfg-node", cfg_node["label"],
                cfg_kind=cfg_node["kind"], function_id=cfg_node["function_id"],
                line=cfg_node.get("line"), **cfg_node.get("properties", {}),
            )
        for phi in info["phi_nodes"]:
            add_node(
                phi["id"], "phi", f"phi {phi['symbol_id']}",
                symbol_id=phi["symbol_id"], function_id=phi["function_id"],
                cfg_node_id=phi["cfg_node_id"], line=phi.get("line"),
                incoming_definition_ids=phi["incoming_definition_ids"],
            )
        for context in info["call_contexts"]:
            add_node(
                context["id"], "call-context", f"call context line {context['line']}",
                call_id=context["call_id"], line=context["line"],
                resolution=context["resolution"],
                caller_function_id=context.get("caller_function_id"),
                callee_function_id=context.get("callee_function_id"),
                callee_function_ids=context.get("callee_function_ids", []),
                dispatch_target_ids=context.get("dispatch_target_ids", []),
                dispatch_status=context.get("dispatch_status"),
            )
            add_node(
                context["return_value_id"], "context-return", "context return",
                context_id=context["id"],
                taint_source_ids=context.get("taint_source_ids", []),
            )
            for binding in context["parameter_bindings"]:
                add_node(
                    binding["id"], "context-parameter",
                    f"parameter {binding['position']}", context_id=context["id"],
                    position=binding["position"], inferred_type=binding.get("inferred_type"),
                    points_to=binding.get("points_to", []),
                    taint_source_ids=binding.get("taint_source_ids", []),
                )
            receiver_binding = context.get("receiver_binding")
            if receiver_binding:
                add_node(
                    receiver_binding["id"], "context-receiver",
                    receiver_binding["expression"], context_id=context["id"],
                    inferred_type=receiver_binding.get("inferred_type"),
                    points_to=receiver_binding.get("points_to", []),
                )
        for dispatch in info["context_dispatches"]:
            add_node(
                dispatch["id"], "context-dispatch", "contextual method dispatch",
                call_id=dispatch["call_id"], receiver_type=dispatch.get("receiver_type"),
                confidence=dispatch["confidence"],
            )
        for heap_object in info["heap_objects"]:
            add_node(
                heap_object["id"], "heap-object",
                heap_object.get("allocated_type") or heap_object["kind"],
                heap_kind=heap_object["kind"],
                allocated_type=heap_object.get("allocated_type"),
                allocation_operation_id=heap_object.get("allocation_operation_id"),
                context_id=heap_object.get("context_id"), line=heap_object.get("line"),
                allocation_template_id=heap_object.get("allocation_template_id"),
            )
        for heap_location in info["heap_locations"]:
            add_node(
                heap_location["id"], "heap-location", heap_location["path"],
                object_id=heap_location["object_id"], path=heap_location["path"],
                taint_source_ids=heap_location.get("taint_source_ids", []),
            )
        for access in info["heap_accesses"]:
            add_node(
                access["id"], "heap-access", f"{access['kind']} {access['path']}",
                access_kind=access["kind"], path=access["path"],
                function_id=access.get("function_id"),
            )
        for effect in info["heap_effects"]:
            add_node(
                effect["id"], "heap-effect", f"{effect['kind']} {effect['path']}",
                effect_kind=effect["kind"], path=effect["path"],
                function_id=effect["function_id"],
            )
        for effect in info["context_heap_effects"]:
            add_node(
                effect["id"], "context-heap-effect",
                f"{effect['kind']} {effect['path']}",
                context_id=effect["context_id"], effect_kind=effect["kind"],
                path=effect["path"],
            )
        for property_info in info["properties"]:
            add_node(
                property_info["id"], "property", property_info["name"],
                base_symbol_id=property_info["base_symbol_id"], path=property_info["path"],
            )
        for definition in info["definitions"]:
            add_node(
                definition["id"], "definition",
                f"{definition['symbol_id']}#{definition['version']}",
                version=definition["version"], definition_kind=definition["kind"],
                origin=definition["origin"], line=definition["line"],
                previous_definition_id=definition["previous_definition_id"],
                branch_previous_definition_ids=definition.get(
                    "branch_previous_definition_ids", []
                ),
                origin_definition_ids=definition.get("origin_definition_ids", []),
                inferred_type=definition.get("inferred_type"),
                taint_source_ids=definition.get("taint_source_ids", []),
            )
        for read in info["reads"]:
            add_node(
                read["id"], "read", read["name"], line=read["line"],
                reaching_definition_ids=read.get("reaching_definition_ids", []),
                taint_source_ids=read.get("taint_source_ids", []),
            )
        for argument in info["arguments"]:
            add_node(
                argument["id"], "argument", argument["expression"],
                position=argument["position"], line=argument["line"],
                taint_source_ids=argument.get("taint_source_ids", []),
            )
        for return_value in info["returns"]:
            add_node(
                return_value["id"], "return-value", return_value["expression"],
                return_kind=return_value["kind"], line=return_value["line"],
                taint_source_ids=return_value.get("taint_source_ids", []),
            )
        for call in info["function_calls"]:
            add_node(
                call["return_value_id"], "call-return", call["callee"],
                call_id=call["id"], line=call["line"],
                taint_source_ids=call.get("taint_source_ids", []),
            )

    files_by_path = {info["path"]: info for info in file_list}
    functions_by_id = {
        function["id"]: function
        for info in file_list
        for function in info["functions"]
    }
    types_by_name = {
        declared_type["name"]: declared_type
        for info in file_list
        for declared_type in info["types"]
    }
    types_by_id = {
        declared_type["id"]: (info, declared_type)
        for info in file_list
        for declared_type in info["types"]
    }

    for info in file_list:
        file_id = add_node(
            info["file_id"], "file", info["path"],
            path_hash=info["path_hash"],
            content_hash=info["content_hash"],
            lines=info["lines"],
            bytes=info["bytes"],
        )

        for scope in info["scopes"]:
            scope_node = add_node(
                scope["id"], "scope", scope["kind"],
                file=info["path"], start_line=scope["start_line"],
                end_line=scope["end_line"],
                start_offset=scope.get("start_offset"),
                end_offset=scope.get("end_offset"),
            )
            add_edge(
                "CONTAINS_SCOPE",
                scope.get("parent_scope_id") or file_id,
                scope_node,
            )

        for symbol in info["symbols"]:
            symbol_node = add_node(
                symbol["id"], "symbol", symbol["name"],
                symbol_kind=symbol["kind"], file=info["path"], line=symbol["line"],
                declared_type=symbol.get("declared_type"),
            )
            add_edge("DECLARES_SYMBOL", symbol["scope_id"], symbol_node)
            if symbol.get("declaration_id"):
                add_edge("SYMBOL_OF", symbol_node, symbol["declaration_id"])
            if symbol.get("duplicate_of"):
                add_edge("DUPLICATES", symbol_node, symbol["duplicate_of"])
            if symbol.get("shadows"):
                add_edge("SHADOWS", symbol_node, symbol["shadows"])

        for property_info in info["properties"]:
            add_edge(
                "PROPERTY_OF", property_info["id"], property_info["base_symbol_id"],
                path=property_info["path"],
            )
        for definition in info["definitions"]:
            add_edge("DEFINES", definition["symbol_id"], definition["id"])
        for read in info["reads"]:
            add_edge("READ_OF", read["id"], read["symbol_id"])
            add_edge("READS_FROM", read["definition_id"], read["id"])
        for argument in info["arguments"]:
            add_edge("HAS_ARGUMENT", argument["call_id"], argument["id"], position=argument["position"])
        for return_value in info["returns"]:
            owner_id = return_value.get("function_id") or file_id
            add_edge(
                "RETURNS_VALUE", owner_id, return_value["id"],
                return_kind=return_value["kind"],
            )
        for call in info["function_calls"]:
            add_edge("HAS_RETURN_VALUE", call["id"], call["return_value_id"])
        for alias in info["aliases"]:
            add_edge("ALIASES", alias["target"], alias["source"], line=alias["line"])
        for flow in info["data_flows"]:
            for endpoint in (flow["source"], flow["target"]):
                if endpoint not in nodes:
                    add_node(endpoint, "data-context", endpoint)
            add_edge(
                flow["kind"], flow["source"], flow["target"],
                **flow.get("properties", {}),
            )

        for declared_type in info["types"]:
            type_node = add_node(
                declared_type["id"], declared_type["kind"], declared_type["name"],
                file=info["path"], start_line=declared_type["start_line"],
                end_line=declared_type["end_line"], exported=declared_type["exported"],
                type_parameter_ids=declared_type.get("type_parameter_ids", []),
                alias_expression=declared_type.get("alias_expression"),
                union_members=declared_type.get("union_members", []),
                conditional=declared_type.get("conditional", False),
                mapped=declared_type.get("mapped", False),
                members=declared_type.get("members", []),
            )
            add_edge("CONTAINS_TYPE", file_id, type_node)
            if declared_type["exported"]:
                add_edge("EXPORTS", file_id, type_node, name=declared_type["name"])
            for relationship, names in (
                ("EXTENDS", declared_type["extends"]),
                ("IMPLEMENTS", declared_type["implements"]),
            ):
                for name in names:
                    target = types_by_name.get(name)
                    target_id = (
                        target["id"] if target
                        else add_node(reference_id("type-ref", name), "type-reference", name)
                    )
                    add_edge(relationship, type_node, target_id)

        for function in info["functions"]:
            function_id = add_node(
                function["id"], "function", function["name"],
                file=info["path"],
                form=function["form"],
                start_line=function["start_line"],
                end_line=function["end_line"],
                return_type=function.get("return_type"),
                type_parameter_ids=function.get("type_parameter_ids", []),
                type_predicate=function.get("type_predicate"),
            )
            owner_id = function.get("owner_function_id") or file_id
            add_edge("CONTAINS", owner_id, function_id)
            if function.get("owner_type_id"):
                add_edge("DECLARES_METHOD", function["owner_type_id"], function_id)
            if function.get("owner_object_symbol_id"):
                add_edge(
                    "DECLARES_METHOD", function["owner_object_symbol_id"], function_id,
                    ownership="object-literal",
                )
            if function.get("scope_id"):
                add_edge("HAS_SCOPE", function_id, function["scope_id"])
            if function.get("cfg_entry_id"):
                add_edge("HAS_CFG_ENTRY", function_id, function["cfg_entry_id"])
            if function.get("cfg_exit_id"):
                add_edge("HAS_CFG_EXIT", function_id, function["cfg_exit_id"])
            for captured_symbol_id in function.get("captures", []):
                add_edge("CAPTURES", function_id, captured_symbol_id)
            if function["name"] in info["exports"]:
                add_edge("EXPORTS", file_id, function_id, name=function["name"])

        for imported in info["imports"]:
            target_path = imported["resolved_path"]
            target_info = files_by_path.get(target_path) if target_path else None
            if target_info:
                target_id = target_info["file_id"]
            else:
                target_id = add_node(
                    reference_id("module", imported["source"]),
                    "module",
                    imported["source"],
                    resolved_path=target_path,
                    source_kind=imported["source_kind"],
                )
            add_edge(
                "IMPORTS", file_id, target_id,
                symbols=imported["symbols"],
                import_kind=imported["import_kind"],
                form=imported["form"],
            )

        for exported in info["export_details"]:
            target_path = exported["resolved_path"]
            if not exported["source"] or not target_path:
                continue
            target_info = files_by_path.get(target_path)
            target_id = (
                target_info["file_id"] if target_info
                else add_node(
                    reference_id("module", exported["source"]),
                    "module", exported["source"], resolved_path=target_path,
                )
            )
            add_edge(
                "RE_EXPORTS", file_id, target_id,
                symbols=exported["symbols"], export_kind=exported["export_kind"],
            )

        for call in info["function_calls"]:
            receiver = call.get("receiver") or {}
            call_id = add_node(
                call["id"], "call", call["callee"],
                file=info["path"], line=call["line"], form=call["form"],
                resolution=call.get("resolution"),
                method_name=call.get("method_name"),
                receiver_expression=receiver.get("expression"),
                receiver_type=receiver.get("type"),
                return_type=call.get("return_type"),
                dispatch_status=call.get("dispatch_status"),
                dispatch_target_ids=call.get("dispatch_target_ids", []),
                computed_key_expression=call.get("computed_key_expression"),
            )
            caller_id = call.get("caller_function_id") or file_id
            add_edge("CONTAINS_CALL", caller_id, call_id)
            if call.get("scope_id"):
                add_edge("IN_SCOPE", call_id, call["scope_id"])

            receiver_value_id = receiver.get("definition_id") or receiver.get("symbol_id")
            if receiver_value_id:
                add_edge(
                    "HAS_RECEIVER", call_id, receiver_value_id,
                    expression=receiver.get("expression"),
                    evidence=receiver.get("evidence"),
                    confidence=receiver.get("confidence"),
                )
            receiver_type_id = receiver.get("type_id")
            if receiver_type_id:
                if receiver_type_id not in nodes:
                    type_pair = types_by_id.get(receiver_type_id)
                    if type_pair:
                        type_info, declared_type = type_pair
                        add_node(
                            receiver_type_id, declared_type["kind"], declared_type["name"],
                            file=type_info["path"],
                            start_line=declared_type["start_line"],
                            end_line=declared_type["end_line"],
                            exported=declared_type["exported"],
                        )
                    else:
                        add_node(
                            receiver_type_id, "receiver-type",
                            receiver.get("type") or receiver_type_id,
                            builtin=receiver.get("kind") == "builtin",
                        )
                add_edge(
                    "RECEIVER_TYPE", call_id, receiver_type_id,
                    evidence=receiver.get("evidence"),
                    confidence=receiver.get("confidence"),
                )

            target_id = call.get("declaration_symbol_id")
            if target_id and target_id in functions_by_id:
                add_edge(
                    "RESOLVES_TO", call_id, target_id,
                    resolution=call.get("resolution"), confidence="high",
                )
                add_edge(
                    "CALLS", caller_id, target_id,
                    callsite=call_id, line=call["line"],
                    resolution=call.get("resolution"), confidence="high",
                )
            elif call.get("resolution") == "language-runtime":
                runtime_id = add_node(
                    reference_id("runtime", f"{call.get('runtime')}:{call['callee']}"),
                    "runtime-symbol", call["callee"], runtime=call.get("runtime"),
                )
                add_edge(
                    "RUNTIME_CALL", call_id, runtime_id,
                    runtime=call.get("runtime"), line=call["line"],
                )
            else:
                unresolved_id = add_node(
                    reference_id("unresolved", call["callee"]),
                    "unresolved-symbol", call["callee"],
                    reason=call.get("resolution", "unresolved"),
                )
                add_edge(
                    "UNRESOLVED_CALL", call_id, unresolved_id,
                    reason=call.get("resolution", "unresolved"),
                    line=call["line"],
                )

        # Lossless source lines and lexical body structure. These are kept
        # separate from control-flow edges, which can be layered on later.
        source_lines = sorted(info["source_lines"], key=lambda item: item["number"])
        lines_by_number = {item["number"]: item for item in source_lines}
        for position, source_line in enumerate(source_lines):
            add_edge("HAS_SOURCE_LINE", file_id, source_line["id"], number=source_line["number"])
            if position + 1 < len(source_lines):
                add_edge(
                    "NEXT_SOURCE_LINE", source_line["id"], source_lines[position + 1]["id"]
                )

        for function in info["functions"]:
            for number in range(function["start_line"], function["end_line"] + 1):
                source_line = lines_by_number.get(number)
                if source_line:
                    add_edge("FUNCTION_CONTAINS_LINE", function["id"], source_line["id"])

        tokens_by_function = {}
        for token in info["tokens"]:
            tokens_by_function.setdefault(token["function_id"], []).append(token)
            source_line = lines_by_number.get(token["start_line"])
            if source_line:
                add_edge("TOKEN_ON_LINE", token["id"], source_line["id"])
            statement_candidates = [
                statement for statement in info["statements"]
                if statement["function_id"] == token["function_id"]
                and statement["start_offset"] <= token["start_offset"]
                and token["end_offset"] <= statement["end_offset"]
            ]
            statement = min(
                statement_candidates,
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            add_edge(
                "STATEMENT_CONTAINS_TOKEN" if statement else "FUNCTION_CONTAINS_TOKEN",
                statement["id"] if statement else token["function_id"], token["id"],
            )
            expression_candidates = [
                expression for expression in info["expressions"]
                if expression["start_offset"] <= token["start_offset"]
                and token["end_offset"] <= expression["end_offset"]
            ]
            expression = min(
                expression_candidates,
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            if expression:
                add_edge("EXPRESSION_CONTAINS_TOKEN", expression["id"], token["id"])
        for function_tokens in tokens_by_function.values():
            function_tokens.sort(key=lambda item: item["start_offset"])
            for left, right in zip(function_tokens, function_tokens[1:]):
                add_edge("NEXT_TOKEN", left["id"], right["id"])

        for statement in info["statements"]:
            owner_id = (
                statement.get("parent_statement_id")
                or statement.get("function_id")
                or file_id
            )
            add_edge(
                "CONTAINS_STATEMENT", owner_id, statement["id"],
                position=statement["position"],
            )
            if statement.get("scope_id"):
                add_edge("STATEMENT_IN_SCOPE", statement["id"], statement["scope_id"])
            if statement.get("next_statement_id"):
                add_edge(
                    "LEXICALLY_NEXT_STATEMENT", statement["id"],
                    statement["next_statement_id"],
                )
            for number in range(statement["start_line"], statement["end_line"] + 1):
                source_line = lines_by_number.get(number)
                if source_line:
                    add_edge("STATEMENT_ON_LINE", statement["id"], source_line["id"])

        expression_child_ids = {
            link["child"] for link in info["expression_links"]
        }
        for expression in info["expressions"]:
            for number in range(expression["start_line"], expression["end_line"] + 1):
                source_line = lines_by_number.get(number)
                if source_line:
                    add_edge("EXPRESSION_ON_LINE", expression["id"], source_line["id"])
            if expression["id"] in expression_child_ids:
                continue
            statement_candidates = [
                statement for statement in info["statements"]
                if statement["start_offset"] <= expression["start_offset"]
                and expression["end_offset"] <= statement["end_offset"]
            ]
            statement = min(
                statement_candidates,
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            owner_id = statement["id"] if statement else expression.get("function_id")
            if owner_id:
                add_edge("HAS_EXPRESSION", owner_id, expression["id"])
        for link in info["expression_links"]:
            add_edge(
                link["role"], link["parent"], link["child"],
                **({"position": link["position"]} if "position" in link else {}),
            )

        calls_by_id = {call["id"]: call for call in info["function_calls"]}
        for operation in info["operations"]:
            add_edge("HAS_OPERATION", operation["expression_id"], operation["id"])
        for operation_input in info["operation_inputs"]:
            properties = {"role": operation_input["role"]}
            if operation_input.get("position") is not None:
                properties["position"] = operation_input["position"]
            add_edge(
                "OPERATION_INPUT", operation_input["source"],
                operation_input["target"], **properties,
            )
        for attachment in info["operation_attachments"]:
            operation_id = attachment["operation_id"]
            entity_id = attachment["entity_id"]
            entity_kind = attachment["entity_kind"]
            if entity_kind == "READ":
                add_edge("READ_VALUE", entity_id, operation_id)
            elif entity_kind == "CALL":
                call = calls_by_id.get(entity_id)
                add_edge("PERFORMS_CALL", operation_id, entity_id)
                if call:
                    add_edge(
                        "PRODUCES_VALUE", operation_id, call["return_value_id"],
                        value_kind="call-return",
                    )
            elif entity_kind == "DEFINITION":
                add_edge("OPERATION_RESULT", operation_id, entity_id)
            elif entity_kind == "ARGUMENT":
                add_edge("OPERATION_RESULT", operation_id, entity_id, value_kind="argument")
            elif entity_kind == "RETURN_VALUE":
                add_edge("OPERATION_RESULT", operation_id, entity_id, value_kind="return")

        returns_by_function = {}
        for returned in info["returns"]:
            returns_by_function.setdefault(returned.get("function_id"), []).append(returned)
        call_returns = {
            call["id"]: call["return_value_id"] for call in info["function_calls"]
        }
        for context in info["call_contexts"]:
            add_edge("HAS_CALL_CONTEXT", context["call_id"], context["id"])
            for target_function_id in (
                context.get("callee_function_ids")
                or [context.get("callee_function_id")]
            ):
                if target_function_id:
                    add_edge("CONTEXT_INVOKES", context["id"], target_function_id)
            for binding in context["parameter_bindings"]:
                add_edge(
                    "BINDS_CONTEXT_PARAMETER", binding["argument_id"], binding["id"],
                    position=binding["position"], context_id=context["id"],
                    argument_position=binding.get("argument_position"),
                    target_function_id=binding.get("target_function_id"),
                )
                if binding.get("parameter_definition_id"):
                    add_edge(
                        "INSTANTIATES_PARAMETER", binding["id"],
                        binding["parameter_definition_id"], context_id=context["id"],
                    )
                for source_id in binding["source_definition_ids"]:
                    add_edge("CONTEXT_VALUE_SOURCE", source_id, binding["id"])
            receiver_binding = context.get("receiver_binding")
            if receiver_binding:
                source_id = receiver_binding.get("definition_id") or receiver_binding.get("symbol_id")
                if source_id:
                    add_edge("BINDS_CONTEXT_RECEIVER", source_id, receiver_binding["id"])
                add_edge("CONTEXT_HAS_RECEIVER", context["id"], receiver_binding["id"])
            add_edge("HAS_CONTEXT_RETURN", context["id"], context["return_value_id"])
            # Return nodes live in the callee file and are globally registered.
            context_targets = set(
                context.get("callee_function_ids")
                or [context.get("callee_function_id")]
            )
            for target_info in file_list:
                for returned in target_info["returns"]:
                    if returned.get("function_id") in context_targets:
                        add_edge("CONTEXT_RETURNS", returned["id"], context["return_value_id"])
            call_return_id = call_returns.get(context["call_id"])
            if call_return_id:
                add_edge("CONTEXT_RESULT", context["return_value_id"], call_return_id)

        for dispatch in info["context_dispatches"]:
            add_edge("CONTEXT_HAS_DISPATCH", dispatch["parent_context_id"], dispatch["id"])
            add_edge("DISPATCHES_CALL", dispatch["id"], dispatch["call_id"])
            add_edge("DISPATCH_RECEIVER", dispatch["receiver_binding_id"], dispatch["id"])
            if dispatch.get("target_function_id"):
                add_edge(
                    "CONTEXT_RESOLVES_TO", dispatch["id"], dispatch["target_function_id"],
                    receiver_type=dispatch.get("receiver_type"),
                    confidence=dispatch["confidence"],
                )

        for heap_object in info["heap_objects"]:
            allocation_id = heap_object.get("allocation_operation_id")
            if allocation_id:
                add_edge("ALLOCATES", allocation_id, heap_object["id"])
            if heap_object.get("context_id"):
                add_edge("CONTEXT_ALLOCATES", heap_object["context_id"], heap_object["id"])
            if heap_object.get("allocation_template_id"):
                add_edge(
                    "INSTANTIATES_HEAP_OBJECT", heap_object["id"],
                    heap_object["allocation_template_id"],
                )
        for heap_location in info["heap_locations"]:
            add_edge("HEAP_LOCATION_OF", heap_location["id"], heap_location["object_id"])
        for points_to in info["points_to"]:
            add_edge("POINTS_TO", points_to["source"], points_to["target"])
        for access in info["heap_accesses"]:
            if access["kind"] in {"initialize", "write", "collection-write"}:
                add_edge("WRITES_HEAP", access["id"], access["location_id"])
                for source_id in access["value_source_ids"]:
                    add_edge("HEAP_WRITE_VALUE", source_id, access["id"])
            else:
                add_edge("READS_HEAP", access["location_id"], access["id"])
            add_edge("HEAP_ACCESS_ENTITY", access["id"], access["entity_id"])
        for effect in info["heap_effects"]:
            add_edge("HAS_HEAP_EFFECT", effect["function_id"], effect["id"])
            add_edge(
                "EFFECT_ON_PARAMETER", effect["id"], effect["parameter_definition_id"]
            )
            add_edge("SUMMARIZES_ACCESS", effect["id"], effect["access_id"])
        for effect in info["context_heap_effects"]:
            add_edge("APPLIES_HEAP_EFFECT", effect["context_id"], effect["id"])
            add_edge("CONTEXT_EFFECT_BINDING", effect["binding_id"], effect["id"])
            add_edge("CONTEXT_EFFECT_LOCATION", effect["id"], effect["location_id"])

        for cfg_edge in info["cfg_edges"]:
            add_edge(
                cfg_edge["kind"], cfg_edge["source"], cfg_edge["target"],
                **cfg_edge.get("properties", {}),
            )
        for phi in info["phi_nodes"]:
            add_edge("PHI_FOR_SYMBOL", phi["symbol_id"], phi["id"])
            add_edge("PHI_AT", phi["id"], phi["cfg_node_id"])
        for flow in info["branch_flows"]:
            add_edge(
                flow["kind"], flow["source"], flow["target"],
                **flow.get("properties", {}),
            )
        for member in info["dispatch_members"]:
            add_edge("DECLARES_DISPATCH_MEMBER", member["owner_type_id"], member["id"])
        for candidate in info["dispatch_candidates"]:
            add_edge(
                "HAS_DISPATCH_CANDIDATE", candidate["call_id"], candidate["id"],
                dispatch_kind=candidate["kind"], confidence=candidate["confidence"],
            )
            add_edge(
                "DISPATCH_CANDIDATE_TARGET", candidate["id"], candidate["target_id"],
                **candidate.get("properties", {}),
            )
        for relation in info["dispatch_relations"]:
            source_id = relation.get("source") or relation.get("source_type_id")
            target_id = relation.get("target") or relation.get("target_type_id")
            if not source_id and relation.get("source_name"):
                source_id = add_node(
                    reference_id("dynamic-type", relation["source_name"]),
                    "dynamic-type-reference", relation["source_name"],
                )
            if not target_id and relation.get("target_name"):
                target_id = add_node(
                    reference_id("dynamic-type", relation["target_name"]),
                    "dynamic-type-reference", relation["target_name"],
                )
            if source_id and target_id:
                add_edge(
                    relation["kind"], source_id, target_id,
                    line=relation.get("line"),
                )
        for behavior in info["dynamic_behaviors"]:
            owner_id = behavior.get("function_id") or file_id
            add_edge("HAS_DYNAMIC_BEHAVIOR", owner_id, behavior["id"])
            if behavior.get("entity_id"):
                add_edge(
                    "DYNAMIC_BEHAVIOR_AT", behavior["id"], behavior["entity_id"]
                )
            for candidate_id in behavior.get("properties", {}).get("candidate_ids", []):
                add_edge("DYNAMIC_MAY_DISPATCH_TO", behavior["id"], candidate_id)
        for model in info["runtime_models"]:
            add_edge("APPLIES_RUNTIME_MODEL", model["call_id"], model["id"])
            add_edge("MODEL_RETURN", model["id"], model["return_value_id"])
            for position in model.get("derives_return_from", []):
                if position < len(model["argument_ids"]):
                    add_edge(
                        "RUNTIME_DERIVES_RETURN",
                        model["argument_ids"][position], model["return_value_id"],
                        model=model["model"], position=position,
                    )
            if model.get("derives_return_from_receiver") and model.get("receiver_definition_id"):
                add_edge(
                    "RUNTIME_DERIVES_RETURN", model["receiver_definition_id"],
                    model["return_value_id"], model=model["model"], receiver=True,
                )
            if "network-request" in model["behaviors"]:
                position = model.get("url_argument", 0)
                if position < len(model["argument_ids"]):
                    add_edge(
                        "NETWORK_REQUEST", model["argument_ids"][position], model["id"]
                    )
            if "mutates-receiver" in model["behaviors"] and model.get("receiver_definition_id"):
                add_edge(
                    "MUTATES_RECEIVER", model["id"], model["receiver_definition_id"],
                    receiver_write=model.get("receiver_write"),
                )
        for edge in info["async_edges"]:
            add_edge(
                edge["kind"], edge["source"], edge["target"],
                **edge.get("properties", {}),
            )
        for summary in info["effect_summaries"]:
            add_edge("HAS_EFFECT_SUMMARY", summary["function_id"], summary["id"])
            for effect in summary["effects"]:
                add_edge("HAS_FUNCTION_EFFECT", summary["id"], effect["id"])
                if effect.get("parameter_symbol_id"):
                    add_edge(
                        "EFFECT_ON_PARAMETER", effect["id"],
                        effect["parameter_symbol_id"], path=effect.get("path", ""),
                    )
                elif effect.get("target_symbol_id"):
                    add_edge(
                        "EFFECT_ON_STATE", effect["id"], effect["target_symbol_id"],
                        path=effect.get("path", ""),
                    )
        for applied in info["applied_effects"]:
            add_edge("APPLIES_EFFECT", applied["context_id"], applied["id"])
            add_edge("APPLIED_FROM_SUMMARY", applied["effect_id"], applied["id"])
            for target_id in applied["target_ids"]:
                add_edge("APPLIED_EFFECT_TARGET", applied["id"], target_id)
        for parameter in info["type_parameters"]:
            add_edge("DECLARES_TYPE_PARAMETER", parameter["owner_id"], parameter["id"])
        for refinement in info["type_refinements"]:
            add_edge(
                "NARROWS_TYPE", refinement["expression_id"], refinement["id"],
                true_branch=refinement["true_branch"],
            )
            add_edge("REFINES_SYMBOL", refinement["id"], refinement["symbol_id"])
        for substitution in info["generic_substitutions"]:
            add_edge(
                "APPLIES_GENERIC_SUBSTITUTION", substitution["call_id"], substitution["id"]
            )
            add_edge(
                "SUBSTITUTES_FOR_FUNCTION", substitution["id"], substitution["function_id"]
            )
        for overload in info["overloads"]:
            if overload.get("implementation_id"):
                add_edge("OVERLOAD_OF", overload["id"], overload["implementation_id"])
        for compatibility in info["type_compatibilities"]:
            add_edge(
                "STRUCTURALLY_COMPATIBLE_WITH",
                compatibility["source_type_id"], compatibility["target_type_id"],
                matched_members=compatibility["matched_members"],
            )
        for source in info["taint_sources"]:
            add_edge(
                "TAINT_SOURCE", source["id"], source["value_id"],
                source_kind=source["kind"], confidence=source["confidence"],
            )
            if source.get("parent_source_id"):
                add_edge(
                    "TAINT_SOURCE_REFINES", source["parent_source_id"], source["id"]
                )
        for flow in info["taint_flows"]:
            properties = dict(flow.get("properties", {}))
            properties.update({
                "transition": flow.get("transition", "local"),
                "context_id": flow.get("context_id"),
            })
            add_edge(flow["kind"], flow["source"], flow["target"], **properties)
        for reach in info["taint_reaches"]:
            add_edge(
                "TAINT_REACHES", reach["source_id"], reach["value_id"],
                hop_count=reach["hop_count"],
                predecessor_id=reach["predecessor_id"], via=reach["via"],
                predecessor_context_stack=reach["predecessor_context_stack"],
                context_stack=reach["context_stack"],
            )
        for tainted_call in info["tainted_calls"]:
            add_edge(
                "TAINTED_CALL_FROM", tainted_call["source_id"], tainted_call["id"]
            )
            add_edge(
                "TAINTED_CALL_AT", tainted_call["id"], tainted_call["call_id"],
                argument_id=tainted_call["argument_id"],
                context_stack=tainted_call["context_stack"],
            )

        attachment_edges = {
            "DEFINITION": "EXPRESSION_DEFINES",
            "READ": "EXPRESSION_READS",
            "CALL": "EXPRESSION_CALL",
            "ARGUMENT": "EXPRESSION_ARGUMENT",
            "RETURN_VALUE": "EXPRESSION_RETURNS",
        }
        statement_attachment_edges = {
            "DEFINITION": "STATEMENT_DEFINES",
            "READ": "STATEMENT_READS",
            "CALL": "STATEMENT_CALLS",
            "ARGUMENT": "STATEMENT_ARGUMENT",
            "RETURN_VALUE": "STATEMENT_RETURNS",
        }
        for attachment in info["body_attachments"]:
            if attachment.get("expression_id"):
                add_edge(
                    attachment_edges[attachment["entity_kind"]],
                    attachment["expression_id"], attachment["entity_id"],
                )
            if attachment.get("statement_id"):
                add_edge(
                    statement_attachment_edges[attachment["entity_kind"]],
                    attachment["statement_id"], attachment["entity_id"],
                )

    graph: CodeGraph = {
        "nodes": sorted(nodes.values(), key=lambda node: node["id"]),
        "edges": edges,
    }
    CODE_GRAPH.clear()
    CODE_GRAPH.update(graph)
    return CODE_GRAPH
