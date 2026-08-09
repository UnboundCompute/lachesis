#!/usr/bin/env python3
"""Name index + jump moves — the teleport mechanism for agent graph traversal.

This is NOT a tier in a drill-down stack. The navigation layer is a graph an
agent walks in any order (folder <-> file <-> body <-> proof); this index is how
it *enters and teleports*: resolve any function / method / type / symbol name to
its canonical node id, then hand back the moves available from there (open the
file's functional view, open the body CFG, list callers, list callees).

Every result carries a `granularity` (folder | file | type | function | method)
so the caller knows which view a jump lands in, and a real `node_id` so it feeds
straight into investigate.py --focus-id or render_graph.py --owner.

Usage:
  python3 nav/symbol_index.py graph.json --build index.json
  python3 nav/symbol_index.py graph.json --search readTeams
  python3 nav/symbol_index.py graph.json --search verify --exact
  python3 nav/symbol_index.py graph.json --refs readTeamsWebhook      # who calls it
  python3 nav/symbol_index.py graph.json --callees readTeamsWebhook   # what it calls
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tier1_flag.graphlib import GraphLib

# node kinds that are addressable jump targets, mapped to a granularity label
INDEXED_KINDS = {
    "file": "file",
    "class": "type", "interface": "type", "enum": "type", "type": "type",
    "function": "function", "method": "method", "constructor": "method",
}
# CALLS is declaration->declaration (function/method -> function/method): the clean
# call graph for caller/callee moves. INVOKES/MAY_INVOKE/CONTEXT_CALLS originate at
# call-site / call-context nodes, so they'd land moves on non-declaration noise.
CALL_EDGES = ("CALLS",)
_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|[0-9]+")
# Generic test/spec-file conventions (not vendor/interface literals). This is the
# SINGLE SOURCE OF TRUTH for "is this a test file": the graph builder imports the same
# predicate to exclude tests at file-discovery (Arachne/pipeline.source_inventory), so
# "in the graph" and "not a test" can never drift apart.
_TEST_PATH = re.compile(
    r"\.(test|spec)\.|\.integration\.|\.e2e\.|(^|/)__tests__/|(^|/)tests?/|_test\.",
    re.I)


def _tokens(name: str) -> list[str]:
    return [t.lower() for t in _TOKEN.findall(name or "")]


def is_test_path(file: str | None) -> bool:
    """True if a path is a test/spec file. The canonical predicate — reused by the
    builder so build-time exclusion and any query-time handling share one definition."""
    return bool(file) and _TEST_PATH.search(file) is not None


# Back-compat alias (the predicate was originally private).
_is_test = is_test_path


def _file_provenance(gl: GraphLib) -> dict[str, str]:
    """Map repo-relative file path -> provenance (application/dependency/...).

    The file node carries the clean signal for 'app code vs node_modules noise';
    fall back to the path-string test when a node has no provenance property.
    """
    prov: dict[str, str] = {}
    for node in gl.index.nodes_of_kind("file"):
        path = gl.prop(node, "file")
        if path:
            prov[path] = gl.prop(node, "provenance") or ""
    return prov


def _is_external(file: str | None, prov: dict[str, str]) -> bool:
    """True if a file is outside the application (dependency / stdlib / node_modules)."""
    if not file:
        return False
    provenance = prov.get(file)
    if provenance:
        return provenance != "application"
    return "node_modules" in file  # fallback when provenance is absent


def build_index(gl: GraphLib, include_external: bool = False) -> list[dict]:
    """One entry per addressable node, with location + navigation affordances."""
    exported = gl.exported_ids
    prov = _file_provenance(gl)
    entries: list[dict] = []
    for kind, granularity in INDEXED_KINDS.items():
        for node in gl.index.nodes_of_kind(kind):
            name = gl.label(node)
            if not name:
                continue
            file, line, _ = gl.loc(node)
            if not include_external and _is_external(file, prov):
                continue  # external type-stub noise, not the codebase
            owner = gl.owner_function(node)
            container = gl.label(owner) if owner and owner["id"] != node["id"] else None
            entries.append({
                "node_id": node["id"],
                "name": name,
                "kind": kind,
                "granularity": granularity,
                "file": file,
                "line": line,
                "exported": node["id"] in exported,
                "container": container,
                "tokens": _tokens(name),
                "handle": f"{file}:{line}" if file and line else None,
                "is_test": _is_test(file),
            })
    entries.sort(key=lambda e: (e["name"].lower(), e["file"] or "", e["line"] or 0))
    return entries


def _score(entry: dict, q: str, mode: str) -> int | None:
    """Higher is better; None means no match."""
    name = entry["name"]
    low = name.lower()
    ql = q.lower()
    if mode == "exact":
        return 100 if low == ql else None
    if mode == "prefix":
        return 90 if low.startswith(ql) else None
    # default fuzzy: exact > prefix > token-hit > substring
    if low == ql:
        return 100
    if low.startswith(ql):
        return 85
    if ql in entry["tokens"]:
        return 70
    if ql in low:
        return 55
    if all(any(qt in tok for tok in entry["tokens"]) for qt in _tokens(q)) and _tokens(q):
        return 40
    return None


def _ranked(entries: list[dict], q: str, mode: str = "fuzzy") -> list[tuple[int, dict]]:
    """Every match, fully sorted (best first).

    Test symbols are excluded from the graph at build time (the default), so no
    query-time test-demotion is needed; the `is_test` flag survives only as metadata
    for the rare `--include-tests` build, where tests then rank by score like anything
    else."""
    hits = []
    for e in entries:
        s = _score(e, q, mode)
        if s is not None:
            hits.append((s, e))
    # exported and shallower paths rank up on ties
    hits.sort(key=lambda se: (
        -se[0], not se[1]["exported"], se[1]["name"].lower(), se[1]["file"] or "",
    ))
    return hits


def search(entries: list[dict], q: str, mode: str = "fuzzy", limit: int = 25) -> list[dict]:
    """Back-compat list form (used by `_resolve` and seed resolution)."""
    return [e for _, e in _ranked(entries, q, mode)[:limit]]


def search_page(entries: list[dict], q: str, mode: str = "fuzzy",
                limit: int = 25, offset: int = 0) -> dict:
    """Paged search with a real total, so a cold search never silently caps.

    Returns the window `[offset, offset+limit)` plus `total`/`has_more` so an agent
    can see "showing 25 of 340" and page instead of assuming 25 is everything."""
    ranked = _ranked(entries, q, mode)
    total = len(ranked)
    offset = max(0, offset)
    window = [e for _, e in ranked[offset:offset + limit]]
    return {
        "query": q, "mode": mode, "total": total,
        "offset": offset, "limit": limit, "returned": len(window),
        "has_more": offset + len(window) < total,
        "hits": window,
    }


_HANDLE = re.compile(r"^(?P<path>.+):(?P<line>\d+)$")


def _resolve_handle(entries: list[dict], query: str) -> list[dict]:
    """Resolve a `path:line` handle (e.g. `oauth.ts:168`) to node entries.

    This is how anonymous / non-uniquely-named nodes (`<anonymous@N>`) become
    addressable: they have no useful name but always have a file:line."""
    m = _HANDLE.match(query.strip())
    if not m:
        return []
    path, line = m.group("path"), int(m.group("line"))
    hits = [e for e in entries
            if e.get("file") and (e["file"] == path or e["file"].endswith(path))
            and e.get("line") == line]
    # tightest path match first (exact file over endswith), then production over test
    hits.sort(key=lambda e: (e["file"] != path, e.get("is_test", False),
                             e["file"] or ""))
    return hits


def _resolve(gl: GraphLib, entries: list[dict], name: str) -> list[dict]:
    exact = [e for e in entries if e["name"] == name]
    if exact:
        return exact
    handle = _resolve_handle(entries, name)
    if handle:
        return handle
    return search(entries, name, "fuzzy", limit=5)


def callers(gl: GraphLib, node_id: str, include_external: bool = False) -> list[dict]:
    """Who calls this node (reverse call edges) — a traversal move.

    ``gl.index.sources`` yields node DICTS, not ids; climb each to its enclosing
    function so the move lands on a declaration the agent can open."""
    prov = _file_provenance(gl)
    out, seen = [], set()
    for node in gl.index.sources(node_id, *CALL_EDGES):
        owner = gl.owner_function(node) or node
        if owner["id"] in seen:
            continue
        seen.add(owner["id"])
        f, l, _ = gl.loc(owner)
        if not include_external and _is_external(f, prov):
            continue
        out.append({"node_id": owner["id"], "name": gl.label(owner),
                    "kind": gl.kind(owner["id"]), "file": f, "line": l})
    return out


def callees(gl: GraphLib, node_id: str, include_external: bool = False) -> list[dict]:
    """What this node calls (forward call edges) — a traversal move.

    ``gl.index.targets`` yields node DICTS, not ids — use them directly."""
    prov = _file_provenance(gl)
    out, seen = [], set()
    for node in gl.index.targets(node_id, *CALL_EDGES):
        if node["id"] in seen:
            continue
        seen.add(node["id"])
        f, l, _ = gl.loc(node)
        if not include_external and _is_external(f, prov):
            continue  # skip external stubs (e.g. Array.push in lib.es5.d.ts)
        out.append({"node_id": node["id"], "name": gl.label(node),
                    "kind": gl.kind(node["id"]), "file": f, "line": l})
    return out


def _fmt(e: dict) -> str:
    exp = "export " if e.get("exported") else ""
    loc = f"{e.get('file')}:{e.get('line')}" if e.get("file") else "?"
    cont = f"  in {e['container']}" if e.get("container") else ""
    return f"  {exp}{e.get('granularity', e.get('kind')):8} {e['name']:32} {loc}{cont}\n    {e['node_id']}"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="name index + jump moves for graph navigation")
    p.add_argument("graph")
    p.add_argument("--build", metavar="OUT", help="write the full index JSON here")
    p.add_argument("--search", metavar="Q", help="find a name (fuzzy by default)")
    p.add_argument("--exact", action="store_true", help="with --search: exact match only")
    p.add_argument("--prefix", action="store_true", help="with --search: prefix match")
    p.add_argument("--refs", metavar="NAME", help="list callers of NAME (a jump move)")
    p.add_argument("--callees", metavar="NAME", help="list what NAME calls (a jump move)")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--offset", type=int, default=0, help="with --search: page offset")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    gl = GraphLib.load(args.graph)
    entries = build_index(gl)

    if args.build:
        Path(args.build).write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"indexed {len(entries)} names -> {args.build}", file=sys.stderr)

    if args.search:
        mode = "exact" if args.exact else "prefix" if args.prefix else "fuzzy"
        page = search_page(entries, args.search, mode, args.limit, args.offset)
        if args.json:
            print(json.dumps(page, indent=2, ensure_ascii=False))
        else:
            lo = page["offset"] + 1 if page["returned"] else 0
            hi = page["offset"] + page["returned"]
            more = "  (+more; page with --offset)" if page["has_more"] else ""
            print(f"{page['total']} match(es) for {args.search!r}"
                  f" — showing {lo}-{hi}{more}:")
            for e in page["hits"]:
                print(_fmt(e))
        return 0

    if args.refs or args.callees:
        name = args.refs or args.callees
        targets = _resolve(gl, entries, name)
        if not targets:
            print(f"no node named {name!r}", file=sys.stderr)
            return 2
        for tgt in targets:
            moves = callers(gl, tgt["node_id"]) if args.refs else callees(gl, tgt["node_id"])
            verb = "callers of" if args.refs else "callees of"
            if args.json:
                print(json.dumps({"target": tgt, "verb": verb, "moves": moves}, indent=2, ensure_ascii=False))
            else:
                print(f"{verb} {tgt['name']}  ({tgt['file']}:{tgt['line']}):")
                for m in moves or []:
                    print(_fmt(m))
                if not moves:
                    print("  (none)")
        return 0

    if not args.build:
        # default: summary
        from collections import Counter
        c = Counter(e["granularity"] for e in entries)
        print(f"indexed {len(entries)} names: {dict(c)}")
        print("try --search <name> | --refs <name> | --callees <name> | --build index.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
