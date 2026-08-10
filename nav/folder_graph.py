#!/usr/bin/env python3
"""L0 — the folder graph: folder -> subfolder -> file -> the functions it declares.

The source graph has no folder/directory node kind, so folders are **synthesized**
from file path strings; the file->function containment the graph also lacks a live
edge for is recovered by grouping declaration nodes on their `file` property (the
one mechanism that covers every function/method/class, not just top-level ones).

Output is a canonical `{nodes, edges, manifest}` graph so `render_graph.py` draws
it unchanged — every edge carries a `properties.display` verb (contains / declares)
so it reads like a sentence.

  python3 nav/folder_graph.py graph.json --out l0.json
  python3 nav/folder_graph.py graph.json --root adapter-slack --files-only --out l0.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tier1_flag.graphlib import GraphLib
from nav import edge_names
from nav.file_graph import _norm, file_node_keys
from nav.symbol_index import _file_provenance, _is_external

DECL_KINDS = ("function", "method", "class", "interface", "enum")


def _under_root(gl: GraphLib, node: dict, root: str) -> bool:
    """True if a file node lies at or under a folder root, in any path form.

    The root query is matched against every form the file answers to (source-
    relative `file`, `absolute_file`, basename), so a relative root, an absolute
    root, or a bare folder name all select the same subtree."""
    r = _norm(root)
    if not r:
        return True
    prefix = r + "/"
    for key in file_node_keys(gl, node):
        if key == r or key.startswith(prefix):
            return True
    return False


def _folder_chain(rel_path: str) -> list[str]:
    """Ancestor folder paths of a file, outermost first (a/b/c.ts -> [a, a/b])."""
    parts = rel_path.split("/")[:-1]  # drop the filename
    return ["/".join(parts[: i + 1]) for i in range(len(parts))]


def _fnode(folder: str) -> dict:
    """A synthetic folder node (id namespaced so it never collides with graph ids)."""
    return {
        "id": f"nav:folder:{folder}",
        "kind": "folder",
        "label": folder,
        "properties": {"path": folder, "basename": folder.rsplit("/", 1)[-1]},
    }


def _edge(source: str, target: str, kind: str) -> dict:
    return {"source": source, "target": target, "kind": kind,
            "properties": {"display": edge_names.verb(kind)}}


def build_folder_graph(
    gl: GraphLib, root: str | None = None, files_only: bool = False,
    include_external: bool = False,
) -> dict:
    prov = _file_provenance(gl)

    # 1. select the files in scope
    files: list[dict] = []
    for node in gl.index.nodes_of_kind("file"):
        path = gl.prop(node, "file")
        if not path:
            continue
        if not include_external and _is_external(path, prov):
            continue
        if root and not _under_root(gl, node, root):
            continue
        files.append(node)

    # 2. group declarations by their file path (the complete containment mechanism)
    decls_by_file: dict[str, list[dict]] = {}
    if not files_only:
        for kind in DECL_KINDS:
            for node in gl.index.nodes_of_kind(kind):
                path = gl.prop(node, "file")
                if path:
                    decls_by_file.setdefault(path, []).append(node)

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen_edges: set[tuple[str, str]] = set()

    def add_edge(src: str, tgt: str, kind: str) -> None:
        if (src, tgt) not in seen_edges:
            seen_edges.add((src, tgt))
            edges.append(_edge(src, tgt, kind))

    for fnode in files:
        path = gl.prop(fnode, "file")
        # file node (carry a compact label = basename for readability)
        nodes[fnode["id"]] = {
            "id": fnode["id"], "kind": "file", "label": path.rsplit("/", 1)[-1],
            "properties": {"file": path},
            "location": {"start_line": 1},
        }
        # folder chain -> file
        chain = _folder_chain(path)
        prev = None
        for folder in chain:
            fid = f"nav:folder:{folder}"
            if fid not in nodes:
                nodes[fid] = _fnode(folder)
            if prev is not None:
                add_edge(prev["id"], fid, "CONTAINS")
            prev = nodes[fid]
        if prev is not None:
            add_edge(prev["id"], fnode["id"], "CONTAINS")

        # file -> declarations
        for decl in decls_by_file.get(path, []):
            _, line, _ = gl.loc(decl)
            nodes[decl["id"]] = {
                "id": decl["id"], "kind": decl["kind"], "label": gl.label(decl),
                "properties": {"file": path},
                "location": {"start_line": line},
            }
            add_edge(fnode["id"], decl["id"], "DECLARES")

    manifest = {
        "layer": "L0",
        "view": "folder-graph",
        "root": root or "(all application files)",
        "files_only": files_only,
        "counts": {"nodes": len(nodes), "edges": len(edges), "files": len(files)},
    }
    return {"manifest": manifest, "nodes": list(nodes.values()), "edges": edges}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="L0 folder graph builder")
    p.add_argument("graph")
    p.add_argument("--out", help="write the L0 graph JSON here (default: stdout)")
    p.add_argument("--root", help="scope to files under this path prefix")
    p.add_argument("--files-only", action="store_true",
                   help="stop at files; do not attach declared functions")
    p.add_argument("--include-external", action="store_true",
                   help="keep dependency / node_modules files too")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    gl = GraphLib.load(args.graph)
    graph = build_folder_graph(gl, root=args.root, files_only=args.files_only,
                               include_external=args.include_external)
    text = json.dumps(graph, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        c = graph["manifest"]["counts"]
        print(f"L0: {c['files']} files, {c['nodes']} nodes, {c['edges']} edges -> {args.out}",
              file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
