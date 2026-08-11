#!/usr/bin/env python3
"""The traversal / flow view — how an agent talks over the graphed codebase.

This is the seam that makes L0–L3 a *free-traversal* graph rather than a fixed
drill-down. Search a name, land on a node, and get back:
  * a small **named-edge neighborhood** (its file, who calls it, what it calls) —
    "the graph flow, with the edges named"; and
  * an explicit **move list** — the concrete next hops available from here
    (open the folder = L0, open the file = L1, list callers / callees, jump
    through a stub). The agent may take any move in any order (L1→L1→L0 is
    legal); nothing forces a hierarchy.

Each move is an **adapter** — flow.py hands back the exact command that drives
the already-built machinery, it does not re-derive it.

  python3 nav/flow.py graph.kuzu --find handleRequest
  python3 nav/flow.py graph.kuzu --find handleRequest --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nav.graphlib import GraphLib
from nav import edge_names
from nav import symbol_index as si


def _dir_of(path: str | None) -> str | None:
    if not path or "/" not in path:
        return path
    return path.rsplit("/", 1)[0]


def moves_for(gl: GraphLib, graph_path: str, entry: dict) -> list[dict]:
    """The concrete next hops available from a resolved node — each a runnable move."""
    node_id = entry["node_id"]
    file = entry.get("file")
    name = entry["name"]
    granularity = entry.get("granularity")
    moves: list[dict] = []

    if file:
        moves.append({
            "move": "open_file", "level": "L1",
            "why": "see this file's imports, functions and their calls",
            "cmd": f"python3 nav/file_graph.py {graph_path} --file {file} --out l1.json",
        })
        folder = _dir_of(file)
        if folder:
            moves.append({
                "move": "open_folder", "level": "L0",
                "why": "see sibling files in this folder and what each declares",
                "cmd": f"python3 nav/folder_graph.py {graph_path} --root {folder} --out l0.json",
            })
    if granularity in ("function", "method"):
        moves.append({
            "move": "callers", "level": "L1",
            "why": "who calls this — reverse-jump to call sites",
            "cmd": f"python3 nav/symbol_index.py {graph_path} --refs {name}",
        })
        moves.append({
            "move": "callees", "level": "L1",
            "why": "what this calls — forward-jump into dependencies",
            "cmd": f"python3 nav/symbol_index.py {graph_path} --callees {name}",
        })
        moves.append({
            "move": "guard_differential", "level": "L1",
            "why": "compare this against its sibling functions — who guards, who does not",
            "cmd": f"python3 nav/siblings.py {graph_path} --sym {name}",
        })
    return moves


def neighborhood(gl: GraphLib, entry: dict) -> dict:
    """A named-edge graph around a node: its file, its callers, its callees.

    This is the renderable 'flow' — the node in the middle, containment above,
    callers feeding in, callees flowing out, every edge labeled in plain language.
    """
    node_id = entry["node_id"]
    center = gl.nodes.get(node_id) or {"id": node_id, "kind": entry.get("kind", "?"),
                                        "label": entry["name"]}
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def put(nid: str, kind: str, label: str, line=None) -> None:
        nodes.setdefault(nid, {
            "id": nid, "kind": kind, "label": label,
            "location": {"start_line": line} if line else {},
        })

    def link(src: str, tgt: str, kind: str) -> None:
        edges.append({"source": src, "target": tgt, "kind": kind,
                      "properties": {"display": edge_names.verb(kind)}})

    put(node_id, center.get("kind", "?"), gl.label(center) or entry["name"],
        entry.get("line"))

    # containment: the file that declares it (context above the node)
    file = entry.get("file")
    if file:
        for fnode in gl.index.nodes_of_kind("file"):
            if gl.prop(fnode, "file") == file:
                put(fnode["id"], "file", file.rsplit("/", 1)[-1])
                link(fnode["id"], node_id, "DECLARES")
                break

    # callers feed in, callees flow out (declaration-level, external filtered)
    for c in si.callers(gl, node_id):
        put(c["node_id"], c["kind"] or "function", c["name"], c.get("line"))
        link(c["node_id"], node_id, "CALLS")
    for c in si.callees(gl, node_id):
        put(c["node_id"], c["kind"] or "function", c["name"], c.get("line"))
        link(node_id, c["node_id"], "CALLS")

    manifest = {"layer": "flow", "view": "neighborhood", "center": node_id,
                "name": entry["name"], "file": file,
                "counts": {"nodes": len(nodes), "edges": len(edges)}}
    return {"manifest": manifest, "nodes": list(nodes.values()), "edges": edges}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="nav flow view — search, neighborhood, jump moves")
    p.add_argument("graph")
    p.add_argument("--find", metavar="NAME", required=True,
                   help="resolve a name and show its flow + available moves")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--limit", type=int, default=5, help="max name candidates to consider")
    return p


def _print_text(entry: dict, hood: dict, moves: list[dict]) -> None:
    loc = f"{entry.get('file')}:{entry.get('line')}" if entry.get("file") else "?"
    print(f"● {entry['name']}  [{entry.get('granularity')}]  {loc}")
    print(f"  node: {entry['node_id']}")
    c = hood["manifest"]["counts"]
    print(f"  flow: {c['nodes']} nodes / {c['edges']} named edges around it")
    print("  moves:")
    for m in moves:
        print(f"    [{m['level']:2}] {m['move']:12} — {m['why']}")
        print(f"         $ {m['cmd']}")


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    gl = GraphLib.load(args.graph)
    entries = si.build_index(gl)
    hits = si._resolve(gl, entries, args.find)
    if not hits:
        print(f"no node named {args.find!r}", file=sys.stderr)
        return 2
    entry = hits[0]
    hood = neighborhood(gl, entry)
    moves = moves_for(gl, args.graph, entry)

    if args.json:
        print(json.dumps({"resolved": entry, "flow": hood, "moves": moves},
                         indent=2, ensure_ascii=False))
    else:
        _print_text(entry, hood, moves)
        if len(hits) > 1:
            print(f"  ({len(hits) - 1} other candidate(s): "
                  f"{', '.join(h['name'] for h in hits[1:])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
