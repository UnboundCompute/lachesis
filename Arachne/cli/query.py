#!/usr/bin/env python3
"""Query a canonical Arachne project graph and emit an LLM reasoning slice."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Arachne.reasoning import DEFAULT_BUDGET_TOKENS, ReasoningQuery


def load_graph(path: str) -> tuple[dict, dict]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload.get("nodes"), list) or not isinstance(payload.get("edges"), list):
        raise ValueError("input must contain canonical `nodes` and `edges` arrays")
    frontend_capabilities = {
        item["frontend_id"]: item.get("capabilities", {})
        for item in payload.get("manifest", {}).get("frontends", [])
        if item.get("frontend_id")
    }
    return (
        {"nodes": payload["nodes"], "edges": payload["edges"]},
        {"capabilities": frontend_capabilities},
    )


def resolve_function(
    query: ReasoningQuery, focus: str, file: str | None,
) -> tuple[str | None, dict | None]:
    if focus in query.index.nodes:
        return focus, None
    candidates = []
    for kind in ("function", "method", "constructor"):
        candidates.extend(query.find_entity(focus, kind=kind, file=file)["matches"])
    candidates.sort(key=lambda item: item["id"])
    if len(candidates) == 1:
        return candidates[0]["id"], None
    return None, {
        "schema_version": 1, "query": "resolve-function",
        "criteria": {"name": focus, "file": file},
        "status": "not-found" if not candidates else "ambiguous",
        "matches": candidates,
    }


def render_text(result: dict) -> str:
    lines = [f"# {result.get('query', 'Arachne query')}"]
    focus = result.get("focus") or result.get("node")
    if focus:
        location = focus.get("location") or {}
        suffix = f" at {location.get('file')}:{location.get('start_line')}" \
            if location.get("file") else ""
        lines.append(
            f"Focus: [{focus.get('kind')}] {focus.get('label')} <{focus.get('id')}>{suffix}"
        )
    if result.get("summary"):
        lines.extend(("", "Summary:", json.dumps(result["summary"], indent=2, ensure_ascii=False)))
    if result.get("manifest"):
        manifest = result["manifest"]
        lines.extend((
            "", f"Project: {manifest['project']['id']}",
            f"Languages: {', '.join(manifest['project']['languages']) or 'none'}",
            f"Canonical graph: {manifest['project']['canonical']['node_count']} nodes / "
            f"{manifest['project']['canonical']['edge_count']} edges",
            f"Security paths: {manifest['security']['reachable_path_count']}",
            f"Guard differentials: {manifest['security']['guard_differential_count']}",
        ))
    for name, records in result.get("sections", {}).items():
        lines.extend(("", f"## {name} ({len(records)})"))
        for record in records:
            label = record.get("label") or record.get("kind") or record.get("id")
            lines.append(f"- {label}: {json.dumps(record, ensure_ascii=False, sort_keys=True)}")
    if result.get("budget"):
        lines.extend(("", "Budget: " + json.dumps(result["budget"], sort_keys=True)))
    if result.get("continuations"):
        lines.extend(("", "Continuations:"))
        lines.extend(
            "- " + json.dumps(handle, sort_keys=True)
            for handle in result["continuations"]
        )
    if result.get("matches") is not None:
        lines.append(json.dumps(result, indent=2, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("graph", help="canonical project graph JSON")
    root.add_argument(
        "--budget-tokens", type=int, default=DEFAULT_BUDGET_TOKENS,
        help=f"approximate slice budget (default: {DEFAULT_BUDGET_TOKENS})",
    )
    root.add_argument("--format", choices=("json", "text"), default="json")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("overview")
    locate = commands.add_parser("locate")
    locate.add_argument("node_id")
    expand = commands.add_parser("expand")
    expand.add_argument("node_id")
    expand.add_argument("--depth", type=int, default=1)
    find = commands.add_parser("find-entity")
    find.add_argument("name")
    find.add_argument("--kind")
    find.add_argument("--file")
    function = commands.add_parser("function")
    function.add_argument("focus")
    function.add_argument("--file")
    value = commands.add_parser("value-history")
    value.add_argument("node_id")
    call = commands.add_parser("call")
    call.add_argument("node_id")
    security = commands.add_parser("security-path")
    security.add_argument("node_id")
    handler = commands.add_parser("handler-security")
    handler.add_argument("focus")
    handler.add_argument("--file")
    unresolved = commands.add_parser("unresolved")
    unresolved.add_argument("node_id", nargs="?")
    return root


def execute(args: argparse.Namespace) -> dict:
    graph, metadata = load_graph(args.graph)
    query = ReasoningQuery(
        graph, default_budget_tokens=args.budget_tokens,
        project_metadata=metadata,
    )
    command = args.command
    if command == "overview":
        return query.overview()
    if command == "locate":
        return query.locate(args.node_id)
    if command == "expand":
        return query.expand(args.node_id, args.depth, args.budget_tokens)
    if command == "find-entity":
        return query.find_entity(args.name, args.kind, args.file)
    if command in {"function", "handler-security"}:
        function_id, resolution = resolve_function(query, args.focus, args.file)
        if resolution:
            return resolution
        if command == "function":
            return query.function_slice(function_id, args.budget_tokens)
        return query.handler_security_slice(function_id, args.budget_tokens)
    if command == "value-history":
        return query.value_history(args.node_id, args.budget_tokens)
    if command == "call":
        return query.explain_call(args.node_id, args.budget_tokens)
    if command == "security-path":
        return query.security_path(args.node_id, args.budget_tokens)
    if command == "unresolved":
        return query.unresolved_frontier(args.node_id, args.budget_tokens)
    raise AssertionError(f"unhandled query command: {command}")


def main() -> int:
    args = parser().parse_args()
    try:
        result = execute(args)
    except (KeyError, ValueError, json.JSONDecodeError, OSError) as error:
        print(json.dumps({"error": str(error), "query": args.command}), file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_text(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
