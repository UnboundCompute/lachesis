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
                origin_definition_ids=definition.get("origin_definition_ids", []),
                inferred_type=definition.get("inferred_type"),
            )
        for read in info["reads"]:
            add_node(read["id"], "read", read["name"], line=read["line"])
        for argument in info["arguments"]:
            add_node(
                argument["id"], "argument", argument["expression"],
                position=argument["position"], line=argument["line"],
            )
        for return_value in info["returns"]:
            add_node(
                return_value["id"], "return-value", return_value["expression"],
                return_kind=return_value["kind"], line=return_value["line"],
            )
        for call in info["function_calls"]:
            add_node(
                call["return_value_id"], "call-return", call["callee"],
                call_id=call["id"], line=call["line"],
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
            owner_id = statement.get("parent_statement_id") or statement["function_id"]
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
