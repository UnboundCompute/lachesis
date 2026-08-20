#!/usr/bin/env python3
"""Exercise the complete comprehension MCP surface without reading target source.

The harness bootstraps from MCP results (hubs, coverage, architecture, and semantic
search), derives every later argument from those results, and talks to the real stdio
JSON-RPC server.  Target source is never opened by the harness.  A surrounding
``bounded_run.py`` invocation supplies the process-tree memory and total wall limits;
``--call-timeout`` independently bounds every MCP request.
"""
from __future__ import annotations

import argparse
import json
from pathlib import PurePosixPath
import select
import subprocess
import sys
import time


EXPECTED_TOOLS = {
    "load_graph", "hubs", "search", "callers", "callees", "read_body",
    "open_file", "open_folder", "unknowns", "coverage_map", "field_history",
    "sibling_compare", "type_explain", "component_boundary", "indirect_targets",
    "architecture_map", "execution_story", "change_context", "tests_for",
    "spec_links", "concept_search", "context_pack", "flow", "reaches",
    "sources_of", "points_to", "aliases",
}
TYPE_KINDS = {"class", "interface", "type", "record", "enum"}


class McpClient:
    def __init__(self, graph: str, timeout: float) -> None:
        self.timeout = timeout
        self.next_id = 1
        self.process = subprocess.Popen(
            [sys.executable, "-m", "lachesis.nav.mcp_server", graph, "", "comprehension"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            text=True, bufsize=1,
        )

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def request(self, method: str, params: dict | None = None) -> dict:
        request_id = self.next_id
        self.next_id += 1
        payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], self.timeout)
        if not ready:
            raise TimeoutError(f"MCP request {method!r} exceeded {self.timeout}s")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"MCP server exited during {method!r}: {self.process.poll()}")
        response = json.loads(line)
        if response.get("id") != request_id:
            raise RuntimeError(f"out-of-order MCP response: {response.get('id')}")
        if "error" in response:
            raise RuntimeError(str(response["error"]))
        return response["result"]

    def call(self, name: str, arguments: dict, *, structured: bool = False):
        args = dict(arguments)
        if structured:
            args["format"] = "json"
        started = time.monotonic()
        result = self.request("tools/call", {"name": name, "arguments": args})
        elapsed = time.monotonic() - started
        text = result["content"][0]["text"]
        if result.get("isError") or text.startswith("error:"):
            raise RuntimeError(f"{name}: {text[:500]}")
        return (json.loads(text) if structured else text), elapsed, len(text.encode())


def _folder_for(file: str, components: list[dict]) -> str:
    component_names = [row.get("component") for row in components if row.get("component")]
    for component in component_names:
        if f"/{component}/" in file or file.startswith(component + "/"):
            return component
    parent = PurePosixPath(file).parent
    return parent.name if parent.name else "."


def _pick_type(client: McpClient, concept: dict, hint: str) -> str:
    for hit in concept.get("results", []):
        if hit.get("kind") in TYPE_KINDS and hit.get("name"):
            return hit["name"]
    searched, _, _ = client.call("search", {"name": hint, "limit": 25}, structured=True)
    for hit in searched.get("hits", []):
        if hit.get("kind") in TYPE_KINDS:
            return hit["name"]
    raise RuntimeError("MCP discovery found no explainable type")


def run(args: argparse.Namespace) -> dict:
    client = McpClient(args.graph, args.call_timeout)
    observations: dict[str, dict] = {}
    pagination: dict[str, dict] = {}

    def observe(name: str, arguments: dict) -> str:
        text, elapsed, size = client.call(name, arguments)
        observations[name] = {
            "elapsed_seconds": round(elapsed, 3), "response_bytes": size,
            "nonempty": bool(text.strip()), "preview": text[:240],
        }
        if size > args.max_response_bytes:
            raise RuntimeError(
                f"{name} returned {size} bytes (limit {args.max_response_bytes})"
            )
        return text

    try:
        client.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}})
        listing = client.request("tools/list")
        listed = {tool["name"] for tool in listing["tools"]}
        missing, unexpected = sorted(EXPECTED_TOOLS - listed), sorted(listed - EXPECTED_TOOLS)
        if missing or unexpected:
            raise RuntimeError(f"comprehension tool mismatch: missing={missing}, extra={unexpected}")

        hubs, _, _ = client.call("hubs", {"n": 12}, structured=True)
        if not hubs.get("ranked"):
            raise RuntimeError("hubs returned no bootstrap symbol")
        hub = hubs["ranked"][0]
        symbol, node_id, file = hub["name"], hub["node_id"], hub["file"]

        coverage, _, _ = client.call(
            "coverage_map", {"component_depth": 1, "limit": 30}, structured=True
        )
        architecture, _, _ = client.call(
            "architecture_map",
            {"component_depth": 2, "max_communities": 12,
             "max_files_per_community": 20}, structured=True,
        )
        if args.skip_concept:
            concept = {"count": 0, "results": [], "status": "held"}
        else:
            concept, _, _ = client.call(
                "concept_search", {"query": args.question, "limit": 30}, structured=True
            )

        def prove_next_page(name: str, first: dict, arguments: dict,
                            page: dict, offset_key: str = "offset") -> None:
            if not page.get("has_more"):
                pagination[name] = {"has_more": False, "total": page.get("total")}
                return
            second_args = dict(arguments)
            second_args[offset_key] = page["next_offset"]
            second, _, _ = client.call(name.split(".", 1)[0], second_args, structured=True)
            pagination[name] = {
                "has_more": True, "first_offset": page["offset"],
                "second_offset": page["next_offset"], "second_page_received": bool(second),
            }

        prove_next_page(
            "coverage_map", coverage, {"component_depth": 1, "limit": 30},
            coverage.get("pages", {}).get("diagnostic_files", {}),
        )
        prove_next_page(
            "architecture_map", architecture,
            {"component_depth": 2, "max_communities": 12,
             "max_files_per_community": 20}, architecture.get("page", {}),
        )
        if architecture.get("communities"):
            prove_next_page(
                "architecture_map.files", architecture,
                {"component_depth": 2, "max_communities": 1,
                 "max_files_per_community": 20},
                architecture["communities"][0].get("files_page", {}),
                offset_key="file_offset",
            )
        if not args.skip_concept:
            prove_next_page(
                "concept_search", concept, {"query": args.question, "limit": 30},
                concept.get("page", {}),
            )
        type_name = _pick_type(client, concept, args.type_hint)
        explained, _, _ = client.call(
            "type_explain", {"type": type_name, "limit": 30}, structured=True
        )
        fields = [field for typ in explained.get("types", []) for field in typ.get("fields", [])]
        field = fields[0] if fields else None

        callees, _, _ = client.call("callees", {"name": symbol, "limit": 20}, structured=True)
        callee_rows = callees.get("callees", [])
        sink = callee_rows[0]["node_id"] if callee_rows else node_id
        components = coverage.get("components", [])
        component_names = [row["component"] for row in components
                           if row.get("component") not in {None, "(unknown)"}]
        source_component = _folder_for(file, components)
        target_component = next((name for name in component_names
                                 if name != source_component), source_component)
        value = field["node_id"] if field else node_id

        # Every listed tool is called through its ordinary compact MCP response path.
        calls = {
            "load_graph": {"path": args.graph, "profile": "comprehension"},
            "hubs": {"n": 12},
            "search": {"name": symbol, "limit": 20},
            "callers": {"name": symbol, "limit": 20},
            "callees": {"name": symbol, "limit": 20},
            "read_body": {"node_id": node_id, "max_chars": 8000},
            "open_file": {"file": file, "limit": 30},
            "open_folder": {"root": source_component, "limit": 30},
            "unknowns": {"function": symbol, "limit": 30},
            "coverage_map": {"component_depth": 1, "limit": 30},
            "sibling_compare": {"symbol": symbol, "limit": 30},
            "type_explain": {"type": type_name, "limit": 30},
            "component_boundary": {"from_component": source_component,
                                   "to_component": target_component, "limit": 30},
            "indirect_targets": {"function": symbol, "limit": 30},
            "architecture_map": {"component_depth": 2, "max_communities": 12,
                                 "max_files_per_community": 20, "limit": 30},
            "execution_story": {"entry": symbol, "max_depth": 4, "max_steps": 60},
            "change_context": {"symbol": symbol, "limit": 12},
            "tests_for": {"symbol": symbol, "limit": 30},
            "spec_links": {"symbol": symbol, "limit": 30},
            "concept_search": {"query": args.question, "limit": 20},
            "context_pack": {"question": args.question, "max_symbols": 6,
                             "max_neighbors": 30},
            "flow": {"seed": symbol, "limit": 30},
            "reaches": {"src": symbol, "sink": sink},
            "sources_of": {"sink": sink, "limit": 30},
            "points_to": {"value": value},
            "aliases": {"value": value},
        }
        if field:
            calls["field_history"] = {"field": field["name"], "owner_type": type_name,
                                      "limit": 30}
        else:
            # Still exercise the tool with an MCP-discovered graph identifier. A clean
            # empty history is preferable to smuggling a source-derived field name in.
            calls["field_history"] = {"field": value, "limit": 30}

        held = {"concept_search"} if args.skip_concept else set()
        for name in sorted(EXPECTED_TOOLS - held):
            observe(name, calls[name])
        return {
            "target": args.label, "graph": args.graph, "question": args.question,
            "tool_count": len(observations), "tools": observations,
            "held_tools": sorted(held),
            "pagination": pagination,
            "bootstrap": {
                "hub": {"name": symbol, "file": file},
                "type": type_name, "field": field and field["name"],
                "components": [source_component, target_component],
                "architecture_counts": architecture.get("counts"),
                "coverage_counts": coverage.get("counts"),
                "concept_count": concept.get("count"),
            },
        }
    finally:
        client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--question", required=True)
    parser.add_argument("--type-hint", required=True)
    parser.add_argument("--call-timeout", type=float, default=180)
    parser.add_argument("--max-response-bytes", type=int, default=100_000)
    parser.add_argument("--skip-concept", action="store_true",
                        help="hold concept_search while testing every deterministic tool")
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    report = run(args)
    with open(args.report, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"target": args.label, "tools": report["tool_count"],
                      "bootstrap": report["bootstrap"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
