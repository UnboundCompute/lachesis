#!/usr/bin/env python3
"""L1 — the file / functional graph for one file.

Everything an agent needs to reason about a single file, in one graph:
  * imports        — outgoing DEPENDS_ON / RE_EXPORTS (to files or external modules)
  * declares       — the functions / methods / classes the file declares
  * intra-file calls — CALLS whose caller AND callee both live in this file
  * cross-file calls — CALLS leaving the file become a **stub jump-ref** node that
                       carries the real target's node_id, so an agent teleports into
                       that file's L1 instead of inlining a foreign body.

Output is a canonical `{nodes, edges, manifest}` graph; every edge carries a
`properties.display` verb so `render_graph.py` labels it in plain language.

  python3 nav/file_graph.py graph.json --file adapter-slack/src/webhook/verify.ts --out l1.json
  python3 nav/file_graph.py graph.json --file-id <file-node-id> --out l1.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tier1_flag.graphlib import GraphLib
from nav import edge_names
from nav.symbol_index import _file_provenance, _is_external

DECL_KINDS = ("function", "method", "class", "interface", "enum", "constructor")
IMPORT_EDGES = ("DEPENDS_ON", "RE_EXPORTS", "RUNTIME_DEPENDS_ON")


def _norm(p: str | None) -> str:
    """Normalize a path for comparison: strip a leading `./` and trailing slash."""
    if not p:
        return ""
    p = p.strip()
    while p.startswith("./"):
        p = p[2:]
    return p.rstrip("/")


def file_node_keys(gl: GraphLib, node: dict) -> set[str]:
    """Every path form a file node answers to: its `file` key, its `absolute_file`,
    and its bare basename — each normalized. A query in any of these forms (an
    absolute handle, a source-relative path, a bare basename) resolves the node, so
    open_file/open_folder no longer depend on which convention a handle arrived in."""
    keys: set[str] = set()
    for raw in (gl.prop(node, "file"), gl.prop(node, "absolute_file")):
        norm = _norm(raw)
        if norm:
            keys.add(norm)
            keys.add(norm.rsplit("/", 1)[-1])
    return keys


def _find_file_node(gl: GraphLib, *, path: str | None, file_id: str | None) -> dict | None:
    if file_id:
        node = gl.nodes.get(file_id)
        return node if node and node.get("kind") == "file" else None
    query = _norm(path)
    if not query:
        return None
    base = query.rsplit("/", 1)[-1]
    # exact file/absolute match wins over a basename-only match, so a bare basename
    # never shadows a full-path hit when both are present in the tree.
    fallback: dict | None = None
    for node in gl.index.nodes_of_kind("file"):
        keys = file_node_keys(gl, node)
        if query in keys:
            return node
        if base in keys:
            fallback = fallback or node
    return fallback


def _edge(source: str, target: str, kind: str, extra: dict | None = None,
          display: str | None = None) -> dict:
    props = {"display": display or edge_names.verb(kind)}
    if extra:
        props.update(extra)
    return {"source": source, "target": target, "kind": kind, "properties": props}


def build_file_graph(gl: GraphLib, file_node: dict, include_external: bool = False) -> dict:
    path = gl.prop(file_node, "file")
    file_id = file_node["id"]
    prov = _file_provenance(gl)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    # the file itself is the root of this view
    nodes[file_id] = {
        "id": file_id, "kind": "file", "label": path.rsplit("/", 1)[-1],
        "properties": {"file": path}, "location": {"start_line": 1},
    }

    # 1. imports (outgoing DEPENDS_ON / RE_EXPORTS) — read the EDGE for the specifier
    for edge in gl.index.outgoing.get(file_id, []):
        if edge.get("kind") not in IMPORT_EDGES:
            continue
        tgt = gl.nodes.get(edge.get("target"))
        if not tgt:
            continue
        specifier = edge.get("properties", {}).get("specifier") or gl.label(tgt)
        nodes.setdefault(tgt["id"], {
            "id": tgt["id"], "kind": tgt.get("kind", "module"),
            "label": gl.label(tgt) or specifier,
            "properties": {"specifier": specifier},
        })
        edges.append(_edge(file_id, tgt["id"], edge["kind"],
                           extra={"specifier": specifier}))

    # 2. declarations owned by this file (complete: grouped on the `file` property)
    my_decls: set[str] = set()
    for kind in DECL_KINDS:
        for decl in gl.index.nodes_of_kind(kind):
            if gl.prop(decl, "file") != path:
                continue
            my_decls.add(decl["id"])
            _, line, _ = gl.loc(decl)
            nodes[decl["id"]] = {
                "id": decl["id"], "kind": decl["kind"], "label": gl.label(decl),
                "properties": {"file": path}, "location": {"start_line": line},
            }
            edges.append(_edge(file_id, decl["id"], "DECLARES"))

    # 3. calls out of each declared function
    stub_count = 0
    for decl_id in my_decls:
        for callee in gl.index.targets(decl_id, "CALLS"):
            callee_file = gl.prop(callee, "file")
            if callee["id"] in my_decls:
                # intra-file: direct edge between two nodes already present
                edges.append(_edge(decl_id, callee["id"], "CALLS"))
            else:
                # skip calls into external stubs (Array.slice, Math.floor, …) — they
                # aren't navigable destinations; keep only in-repo cross-file jumps.
                if not include_external and _is_external(callee_file, prov):
                    continue
                # cross-file: a stub jump-ref carrying the real target id
                stub_id = f"nav:stub:{callee['id']}"
                if stub_id not in nodes:
                    _, cline, _ = gl.loc(callee)
                    nodes[stub_id] = {
                        "id": stub_id, "kind": "stub",
                        "label": f"↪ {gl.label(callee)}",
                        "properties": {
                            "target_node_id": callee["id"],
                            "target_file": callee_file,
                            "target_name": gl.label(callee),
                            "target_line": cline,
                        },
                        "location": {"start_line": cline},
                    }
                    stub_count += 1
                edges.append(_edge(decl_id, stub_id, "JUMP_REF",
                                   extra={"target_node_id": callee["id"]},
                                   display="calls →"))

    manifest = {
        "layer": "L1",
        "view": "file-graph",
        "file": path,
        "file_id": file_id,
        "counts": {
            "nodes": len(nodes), "edges": len(edges),
            "declarations": len(my_decls), "jump_stubs": stub_count,
        },
    }
    return {"manifest": manifest, "nodes": list(nodes.values()), "edges": edges}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="L1 file / functional graph builder")
    p.add_argument("graph")
    p.add_argument("--file", help="target file by repo-relative path")
    p.add_argument("--file-id", help="target file by its file-node id")
    p.add_argument("--out", help="write the L1 graph JSON here (default: stdout)")
    p.add_argument("--include-external", action="store_true",
                   help="also stub calls into dependency / stdlib files")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    if not args.file and not args.file_id:
        print("need --file <path> or --file-id <id>", file=sys.stderr)
        return 2
    gl = GraphLib.load(args.graph)
    file_node = _find_file_node(gl, path=args.file, file_id=args.file_id)
    if not file_node:
        print(f"no file node for {args.file or args.file_id!r}", file=sys.stderr)
        return 2
    graph = build_file_graph(gl, file_node, include_external=args.include_external)
    text = json.dumps(graph, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        c = graph["manifest"]["counts"]
        print(f"L1 {graph['manifest']['file']}: {c['declarations']} decls, "
              f"{c['jump_stubs']} jump-stubs, {c['nodes']} nodes -> {args.out}",
              file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
