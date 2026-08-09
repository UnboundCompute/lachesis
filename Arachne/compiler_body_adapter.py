"""Compatibility body view derived exclusively from compiler frontend facts.

The canonical graph retains the complete frontend AST.  This module projects
that AST into the compact statement/expression records consumed by Arachne's
language-neutral CFG and security overlays; it never tokenizes or parses text.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Iterable, Mapping


def stable_id(kind: str, *parts: object) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


STATEMENT_KINDS = {
    # TypeScript exposes VariableStatement through the reverse enum alias
    # FirstStatement in current compiler releases.
    "FirstStatement": "variable-declaration",
    "VariableStatement": "variable-declaration",
    "ExpressionStatement": "expression-statement",
    "ReturnStatement": "return",
    "ThrowStatement": "throw",
    "BreakStatement": "break",
    "ContinueStatement": "continue",
    "IfStatement": "if-statement",
    "WhileStatement": "while-statement",
    "DoStatement": "do-statement",
    "ForStatement": "for-statement",
    "ForInStatement": "for-statement",
    "ForOfStatement": "for-statement",
    "SwitchStatement": "switch-statement",
    "CaseClause": "case-statement",
    "DefaultClause": "default-statement",
    "TryStatement": "try-statement",
    "DebuggerStatement": "debugger-statement",
    "LabeledStatement": "labeled-statement",
    "WithStatement": "with-statement",
    "EmptyStatement": "empty-statement",
}

EXPRESSION_KINDS = {
    "BinaryExpression": "binary",
    "PrefixUnaryExpression": "unary",
    "PostfixUnaryExpression": "unary",
    "AwaitExpression": "unary",
    "YieldExpression": "unary",
    "ConditionalExpression": "conditional",
    "AsExpression": "cast",
    "TypeAssertionExpression": "cast",
    "NonNullExpression": "cast",
    "SatisfiesExpression": "cast",
    "NewExpression": "constructor",
    "ObjectLiteralExpression": "object-literal",
    "ArrayLiteralExpression": "array-literal",
    "TemplateExpression": "template-literal",
    "NoSubstitutionTemplateLiteral": "template-literal",
    "PropertyAccessExpression": "member-access",
    "ElementAccessExpression": "member-access",
    "CallExpression": "call",
    "Identifier": "identifier",
}

CONTROL_BODY_ROLES = {"TRUE_BRANCH", "LOOP_BODY"}


def _view_id(path_hash: str, compiler_id: str) -> str:
    return stable_id("body-view", path_hash, compiler_id)


def _source_lines(info: dict) -> list[dict]:
    result = []
    offset = 0
    parts = info["text"].splitlines(keepends=True)
    if info["text"] and not parts:
        parts = [info["text"]]
    for number, raw in enumerate(parts, 1):
        text = raw.rstrip("\r\n")
        stripped = text.strip()
        kind = "blank" if not stripped else "comment" if stripped.startswith(("//", "/*", "*")) else "code"
        result.append({
            "id": stable_id("source-line", info["path_hash"], number),
            "number": number, "kind": kind, "text": text,
            "start_offset": offset, "end_offset": offset + len(raw),
        })
        offset += len(raw)
    return result


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _node_record(node: dict, info: dict, kind: str) -> dict:
    properties = node.get("properties", {})
    start = properties["start_offset"]
    end = properties["end_offset"]
    return {
        "id": _view_id(info["path_hash"], node["id"]),
        "compiler_node_id": node["id"], "kind": kind,
        "function_id": properties.get("owner_function_id") or info["file_id"],
        "scope_id": properties.get("scope_id"),
        "start_offset": start, "end_offset": end,
        "start_line": properties["start_line"], "end_line": properties["end_line"],
        "text": info["text"][start:end],
    }


def adapt_compiler_body(
    info: dict, nodes: Mapping[str, dict], edges: Iterable[dict],
) -> None:
    """Populate the legacy body fields from one compiler snapshot."""
    absolute = info["path"]
    body_nodes = {
        node_id: node for node_id, node in nodes.items()
        if node.get("kind") in {"statement", "expression", "identifier", "call", "construct"}
        and node.get("properties", {}).get("absolute_file") == absolute
    }
    ast_edges = [
        edge for edge in edges
        if edge.get("kind") == "AST_CHILD"
        and edge.get("source") in body_nodes and edge.get("target") in body_nodes
    ]
    parents = {edge["target"]: edge for edge in ast_edges}
    children = defaultdict(list)
    else_clauses = []
    for edge in ast_edges:
        children[edge["source"]].append(edge)

    statements = []
    statement_by_compiler = {}
    for compiler_id, node in body_nodes.items():
        properties = node.get("properties", {})
        syntax = properties.get("syntax_kind")
        kind = STATEMENT_KINDS.get(syntax)
        if not kind:
            continue
        record = _node_record(node, info, kind)
        # Control records represent the executable header. Their compiler AST
        # still remains losslessly available in the canonical graph.
        body_starts = [
            body_nodes[edge["target"]]["properties"]["start_offset"]
            for edge in children.get(compiler_id, [])
            if edge.get("properties", {}).get("role") in CONTROL_BODY_ROLES | {"CASE_BODY"}
        ]
        if body_starts:
            record["end_offset"] = min(body_starts)
            record["end_line"] = _line(info["text"], max(record["start_offset"], record["end_offset"] - 1))
            record["text"] = info["text"][record["start_offset"]:record["end_offset"]].rstrip()
        if kind == "for-statement":
            owned_scope = next((
                scope for scope in info["scopes"]
                if scope["kind"] == "for"
                and properties["start_offset"] <= scope["start_offset"]
                and scope["end_offset"] <= properties["end_offset"]
                and scope.get("owner_function_id") == properties.get("owner_function_id")
            ), None)
            if owned_scope:
                record["scope_id"] = owned_scope.get("parent_scope_id")
        statements.append(record)
        statement_by_compiler[compiler_id] = record

    def statement_ancestor(compiler_id: str):
        owner = body_nodes[compiler_id].get("properties", {}).get("owner_function_id")
        edge = parents.get(compiler_id)
        if not edge:
            return None
        ancestor_node = body_nodes[edge["source"]]
        if ancestor_node.get("properties", {}).get("owner_function_id") != owner:
            return None
        candidate = statement_by_compiler.get(edge["source"])
        if candidate and candidate["kind"] in {
            "if-statement", "for-statement", "while-statement", "do-statement",
        }:
            return candidate
        return None

    for compiler_id, statement in statement_by_compiler.items():
        parent = statement_ancestor(compiler_id)
        statement["parent_statement_id"] = parent["id"] if parent else None

    # TypeScript has no standalone ElseStatement node. Project each compiler
    # FALSE_BRANCH relationship into a clause header, including `else if`.
    for edge in ast_edges:
        if edge.get("properties", {}).get("role") != "FALSE_BRANCH":
            continue
        outer = statement_by_compiler.get(edge["source"])
        target_node = body_nodes.get(edge["target"])
        if not outer or outer["kind"] != "if-statement" or not target_node:
            continue
        target_start = target_node["properties"]["start_offset"]
        true_targets = [
            body_nodes[item["target"]]["properties"]["end_offset"]
            for item in children.get(edge["source"], [])
            if item.get("properties", {}).get("role") == "TRUE_BRANCH"
        ]
        search_start = max(outer["end_offset"], max(true_targets, default=outer["end_offset"]))
        start = info["text"].rfind("else", search_start, target_start + 1)
        if start < 0:
            start = target_start
        clause = {
            "id": stable_id("clause-view", info["path_hash"], edge["source"], edge["target"]),
            "compiler_node_id": edge["source"], "kind": "else-statement",
            "function_id": outer["function_id"], "scope_id": outer["scope_id"],
            "start_offset": start, "end_offset": target_start,
            "start_line": _line(info["text"], start),
            "end_line": _line(info["text"], max(start, target_start - 1)),
            "text": info["text"][start:target_start].rstrip(),
            "parent_statement_id": None,
        }
        statements.append(clause)
        else_clauses.append((clause, outer))
        target_statement = statement_by_compiler.get(edge["target"])
        if target_statement:
            target_statement["parent_statement_id"] = clause["id"]
    for clause, outer in else_clauses:
        clause["parent_statement_id"] = outer.get("parent_statement_id")

    # Catch/finally clauses are compiler scopes rather than Statement AST
    # nodes. Project their headers so the CFG overlay can connect the scopes.
    for scope in info["scopes"]:
        if scope["kind"] not in {"catch", "finally"}:
            continue
        keyword = scope["kind"]
        scope_start = scope["start_offset"]
        search_start = max(0, scope_start - 160)
        start = info["text"].rfind(keyword, search_start, scope_start + 1)
        if start < 0:
            start = scope_start
        record = {
            "id": stable_id("clause-view", info["path_hash"], scope["id"]),
            "compiler_node_id": scope["id"], "kind": f"{keyword}-statement",
            "function_id": scope.get("owner_function_id") or info["file_id"],
            "scope_id": scope.get("parent_scope_id"),
            "start_offset": start, "end_offset": scope_start,
            "start_line": _line(info["text"], start),
            "end_line": _line(info["text"], max(start, scope_start - 1)),
            "text": info["text"][start:scope_start].rstrip(),
            "parent_statement_id": None,
        }
        statements.append(record)

    statements.sort(key=lambda item: (item["start_offset"], -item["end_offset"]))
    by_function = defaultdict(list)
    for statement in statements:
        by_function[statement["function_id"]].append(statement)
    for owned in by_function.values():
        for position, statement in enumerate(owned):
            statement["position"] = position
            statement["previous_statement_id"] = owned[position - 1]["id"] if position else None
            statement["next_statement_id"] = owned[position + 1]["id"] if position + 1 < len(owned) else None

    expressions = []
    expression_by_compiler = {}
    for compiler_id, node in body_nodes.items():
        if node["kind"] == "statement":
            continue
        properties = node.get("properties", {})
        syntax = properties.get("syntax_kind", "Expression")
        kind = EXPRESSION_KINDS.get(syntax, "expression")
        record = _node_record(node, info, kind)
        record["operator"] = properties.get("operator")
        if kind == "cast":
            record["cast_type"] = properties.get("type")
        inbound = parents.get(compiler_id)
        inbound_role = inbound.get("properties", {}).get("role") if inbound else None
        record["roles"] = [inbound_role.lower()] if inbound_role else []
        expressions.append(record)
        expression_by_compiler[compiler_id] = record
    expressions.sort(key=lambda item: (item["start_offset"], -item["end_offset"]))

    expression_links = []
    for edge in ast_edges:
        parent = expression_by_compiler.get(edge["source"])
        child = expression_by_compiler.get(edge["target"])
        if not parent or not child:
            continue
        properties = edge.get("properties", {})
        link = {
            "parent": parent["id"], "child": child["id"],
            "role": properties.get("role", "AST_CHILD"),
        }
        if properties.get("position") is not None:
            link["position"] = properties["position"]
        expression_links.append(link)

    attachments = []
    entity_specs = []
    for definition in info["definitions"]:
        start = definition.get("expression_start")
        if start is not None:
            entity_specs.append((definition["id"], "DEFINITION", start, definition.get("expression_end", start + 1)))
    for read in info["reads"]:
        entity_specs.append((read["id"], "READ", read["offset"], read.get("end_offset", read["offset"] + 1)))
    for call in info["function_calls"]:
        entity_specs.append((call["id"], "CALL", call["start_offset"], call["end_offset"]))
    for argument in info["arguments"]:
        entity_specs.append((argument["id"], "ARGUMENT", argument["start_offset"], argument["end_offset"]))
    for returned in info["returns"]:
        entity_specs.append((returned["id"], "RETURN_VALUE", returned["start_offset"], returned["end_offset"]))
    for entity_id, entity_kind, start, end in entity_specs:
        expression = min(
            (item for item in expressions if item["start_offset"] <= start and end <= item["end_offset"]),
            key=lambda item: item["end_offset"] - item["start_offset"], default=None,
        )
        statement = min(
            (item for item in statements if item["start_offset"] <= start < item["end_offset"]),
            key=lambda item: item["end_offset"] - item["start_offset"], default=None,
        )
        attachments.append({
            "entity_id": entity_id, "entity_kind": entity_kind,
            "expression_id": expression["id"] if expression else None,
            "statement_id": statement["id"] if statement else None,
        })

    info["source_lines"] = _source_lines(info)
    info["statements"] = statements
    info["expressions"] = expressions
    info["expression_links"] = expression_links
    info["body_attachments"] = attachments
