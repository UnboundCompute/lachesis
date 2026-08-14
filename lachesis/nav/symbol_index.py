#!/usr/bin/env python3
"""Name index + jump moves — the teleport mechanism for agent graph traversal.

This is NOT a tier in a drill-down stack. The navigation layer is a graph an
agent walks in any order (folder <-> file <-> body <-> proof); this index is how
it *enters and teleports*: resolve any function / method / type / symbol name to
its canonical node id, then hand back the moves available from there (open the
file's functional view, open the body CFG, list callers, list callees).

Every result carries a `granularity` (folder | file | type | function | method)
so the caller knows which view a jump lands in, and a real `node_id` so it feeds
straight into the flow view or the reasoning layer as a focus node.

Usage:
  python3 nav/symbol_index.py graph.kuzu --build index.json
  python3 nav/symbol_index.py graph.kuzu --search readWebhook
  python3 nav/symbol_index.py graph.kuzu --search verify --exact
  python3 nav/symbol_index.py graph.kuzu --refs readWebhookBody      # who calls it
  python3 nav/symbol_index.py graph.kuzu --callees readWebhookBody   # what it calls
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.nav.graphlib import GraphLib, CALLABLE_KINDS

# The kind vocabulary lives in `lachesis.indices`, which also builds the persisted
# `decl_index` from it. Imported rather than restated so `search` and the stored index
# cannot come to disagree about which nodes are reachable by name.
from lachesis.indices import CALLSITE_KINDS, INDEXED_KINDS, signature_of
from lachesis.resolution import owned_callsites

# Kind precedence for name resolution: when one name resolves to multiple nodes, prefer
# the DEFINITION over a reference to it. §4 made variable/property/constant name-
# addressable (import bindings, ops-struct slot assignments `.read = foo`, extern
# decls), which introduced collisions — a function `foo` now shares its name with the
# import binding `foo` and the struct slot `.foo`. Declaration kinds must outrank
# reference kinds so read_body / name-seeded callers land on the def; references stay
# reachable by explicit node_id / file:line handle. Lower rank = preferred.
_KIND_RANK = {
    "function": 0, "method": 0, "constructor": 0,          # callable definitions
    "class": 1, "interface": 1, "enum": 1, "type": 1,      # type definitions
    "record": 1, "union": 1,
    "file": 2,
    "variable": 5, "property": 5, "constant": 5,           # references / bindings / slots
}


def _kind_rank(entry: dict) -> int:
    """Resolution precedence for an entry (definitions < unknown < references)."""
    return _KIND_RANK.get(entry.get("kind"), 3)
# CALLS is declaration->declaration (function/method -> function/method): the clean,
# resolved direct call graph. It is the DIRECT set.
CALL_EDGES = ("CALLS",)
# The indirect-dispatch family. These edges originate at call-site / argument /
# call-context nodes (not the owning declaration), so a caller/callee move reaches them
# by walking the call-sites the function owns, then resolving each edge's declaration
# endpoint. Unioning them is what makes the move see function-pointer / ops-struct /
# runtime dispatch — on C/kernel that IS the control flow; on TS it recovers the ~22%
# of functions reachable only indirectly. Every unioned row is TAGGED (`via`) so a
# resolved call is never silently conflated with a maybe-dispatch, and `direct_only`
# recovers the pure decl->decl graph unchanged.
INDIRECT_CALL_EDGES = ("INVOKES", "MAY_INVOKE", "CONTEXT_CALLS", "READS_CALLEE")
# Human-readable dispatch label per edge kind, surfaced inside `via=indirect(<label>)`.
_VIA_LABEL = {
    "INVOKES": "invokes", "MAY_INVOKE": "may_invoke",
    "CONTEXT_CALLS": "context", "READS_CALLEE": "fn-pointer",
}
# call-site node kinds a function owns (where INDIRECT edges originate). Same
# vocabulary the persisted `callsite_index` is keyed over, for the same reason.
_CALLSITE_KINDS = CALLSITE_KINDS


def _via_label(edge: dict) -> str:
    """`indirect(<label>)` tag for an indirect-dispatch edge (kind, or EXPANDS_TO via)."""
    kind = edge.get("kind")
    if kind == "EXPANDS_TO":
        kind = edge.get("properties", {}).get("via") or kind
    return f"indirect({_VIA_LABEL.get(kind, (kind or 'dispatch').lower())})"
_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|[0-9]+")
# Generic test/spec-file conventions (not vendor/interface literals). This is the
# SINGLE SOURCE OF TRUTH for "is this a test file": the graph builder imports the same
# predicate to exclude tests at file-discovery (lachesis/pipeline.source_inventory), so
# "in the graph" and "not a test" can never drift apart.
# Generic test/spec conventions across languages (no vendor/interface literals):
#  - JS/TS: *.test.*, *.spec.*, *.integration.*, *.e2e.*, __tests__/, test(s)/
#  - C/kernel: *_test.c (KUnit), selftests/ and tools/testing/ (kernel test trees).
#  - Python: pytest's own default globs, test_*.py and conftest.py. The *_test.py
#    half is already covered by the language-neutral `_test.` alternative.
# The `(^|/)tests?/` anchor requires a slash before "test", so it does NOT catch
# "selftests/" — that needs its own alternative. `test_` is anchored the same way
# for the same reason: unanchored it would swallow "latest_snapshot.py".
_TEST_PATH = re.compile(
    r"\.(test|spec)\.|\.integration\.|\.e2e\.|(^|/)__tests__/|(^|/)tests?/|_test\."
    r"|(^|/)selftests/|(^|/)tools/testing/"
    r"|(^|/)test_[^/]*\.py$|(^|/)conftest\.py$",
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
            nid = node["id"]
            # Twin-disambiguation signals. `declaration_only` is the crisp flag the C
            # frontend stamps on a bodyless prototype (twins the real definition under
            # the same name); `degree` is the language-agnostic fallback (a definition
            # bears call/body edges, a prototype bears none). Both let name resolution
            # prefer the body-bearing definition when a name collides with its prototype.
            degree = (len(gl.index.outgoing.get(nid, ()))
                      + len(gl.index.incoming.get(nid, ())))
            entries.append({
                "node_id": nid,
                "name": name,
                "kind": kind,
                "granularity": granularity,
                "file": file,
                "line": line,
                "exported": nid in exported,
                "container": container,
                "tokens": _tokens(name),
                # §5's field, taken from the frontend and never synthesized -- the
                # same value the persisted `decl_index` carries, from the same helper.
                "signature": signature_of(node.get("properties") or {}),
                "handle": f"{file}:{line}" if file and line else None,
                "is_test": _is_test(file),
                "declaration_only": bool(gl.prop(node, "declaration_only")),
                "degree": degree,
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
    # definitions outrank references (§4 collisions); within a kind the body-bearing
    # definition outranks its bodyless prototype twin (declaration_only / higher degree),
    # then exported, then name/path
    hits.sort(key=lambda se: (
        -se[0], _kind_rank(se[1]),
        se[1].get("declaration_only", False), -se[1].get("degree", 0),
        not se[1]["exported"], se[1]["name"].lower(), se[1]["file"] or "",
    ))
    return hits


def search(entries: list[dict], q: str, mode: str = "fuzzy", limit: int = 25) -> list[dict]:
    """Back-compat list form (used by `_resolve` and seed resolution)."""
    return [e for _, e in _ranked(entries, q, mode)[:limit]]


def _with_homonyms(entry: dict, by_name: dict) -> dict:
    """A hit, plus the other declarations that answer to exactly its name.

    Eleven of the seventeen tools seed from ``hits[0]`` and then say nothing about the
    ones they passed over, so a codebase with four ``funcA``s reads, through the tools,
    like a codebase with one. Rewiring that seeding is a later phase; making the
    collapse *visible* costs one field and is worth having before then — an agent that
    sees ``homonyms`` knows to pass a ``node_id`` instead of a name.

    Same name only, never fuzzy: a near-miss is a search result, and calling it a
    homonym would say the tools had silently chosen between two things that are not in
    fact the same name. Absent when the name is unique, so the field's presence means
    something.
    """
    twins = [
        {"node_id": other["node_id"], "file": other["file"], "line": other["line"],
         "kind": other["kind"]}
        for other in by_name.get(entry["name"], ())
        if other["node_id"] != entry["node_id"]
    ]
    return {**entry, "homonyms": twins} if twins else entry


def search_page(entries: list[dict], q: str, mode: str = "fuzzy",
                limit: int = 25, offset: int = 0) -> dict:
    """Paged search with a real total, so a cold search never silently caps.

    Returns the window `[offset, offset+limit)` plus `total`/`has_more` so an agent
    can see "showing 25 of 340" and page instead of assuming 25 is everything."""
    ranked = _ranked(entries, q, mode)
    total = len(ranked)
    offset = max(0, offset)
    # Grouped once for the page rather than scanned once per hit: on a large C tree
    # `entries` is six figures and the window is twenty-five.
    by_name: dict = {}
    for entry in entries:
        by_name.setdefault(entry["name"], []).append(entry)
    window = [_with_homonyms(e, by_name) for _, e in ranked[offset:offset + limit]]
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
    # tightest path match first (exact file over endswith), then definition over a
    # co-located reference, then body-bearing definition over prototype twin, then
    # production over test
    hits.sort(key=lambda e: (e["file"] != path, _kind_rank(e),
                             e.get("declaration_only", False), -e.get("degree", 0),
                             e.get("is_test", False), e["file"] or ""))
    return hits


def _resolve(gl: GraphLib, entries: list[dict], name: str) -> list[dict]:
    exact = [e for e in entries if e["name"] == name]
    if exact:
        # Prefer the definition over a reference sharing the name (§4 collisions), then
        # the body-bearing definition over its bodyless prototype twin (declaration_only
        # / higher degree), then exported, then production over test, then a stable
        # path/line order.
        exact.sort(key=lambda e: (_kind_rank(e),
                                  e.get("declaration_only", False), -e.get("degree", 0),
                                  not e["exported"],
                                  e.get("is_test", False), e["file"] or "", e["line"] or 0))
        return exact
    handle = _resolve_handle(entries, name)
    if handle:
        return handle
    return search(entries, name, "fuzzy", limit=5)


def _owned_callsites(gl: GraphLib, node_id: str) -> tuple[dict, ...]:
    """The call-site / construct nodes a function owns (where indirect edges start).

    The set itself is computed in `lachesis.resolution`, because it is also the set the
    resolver binds; keeping two definitions would let the sites nav reports indirect
    edges from drift away from the sites resolution decides.
    """
    return owned_callsites(gl.index, node_id)


def _caller_decl(gl: GraphLib, node: dict) -> dict | None:
    """The declaration that owns a call-site / call-context node.

    ``owner_function`` climbs ``owner_function_id``; call-context nodes instead carry
    ``caller_function_id``, so honor that first before falling back to the climb."""
    if gl.kind(node["id"]) == "call-context":
        caller_id = node.get("properties", {}).get("caller_function_id")
        if caller_id:
            return gl.nodes.get(caller_id)
    return gl.owner_function(node)


def _dispatch_of(edge: dict) -> dict:
    """The dispatch descriptor an indirect edge carries: ``{dispatch, slot}``.

    Ops-struct registration edges (`MAY_INVOKE`) stamp ``dispatch="ops-struct"`` and
    the ``slot`` field name — the reverse-dispatch differentiator. Returns only the
    keys actually present so a non-dispatch edge adds nothing."""
    props = edge.get("properties") or {}
    out: dict = {}
    if props.get("dispatch"):
        out["dispatch"] = props["dispatch"]
    if props.get("slot"):
        out["slot"] = props["slot"]
    return out


def callers(gl: GraphLib, node_id: str, include_external: bool = False,
            direct_only: bool = False, with_dispatch: bool = False) -> list[dict]:
    """Who calls this node — a traversal move, direct + indirect dispatch (tagged).

    Direct (``CALLS``) callers land on the calling declaration. Indirect callers are
    found by walking the INDIRECT edges that TARGET this node (their source is a
    call-site / call-context node) back to the declaration that owns them, so a
    function reached only through a function pointer / ops-struct slot / runtime
    dispatch still shows its caller. Every row is tagged ``via`` (`direct` vs
    `indirect(...)`); ``direct_only`` returns exactly the old decl->decl set.

    ``with_dispatch`` additionally stamps each indirect row with the edge's
    ``dispatch``/``slot`` (e.g. ops-struct `.ndo_open`) so a text renderer can show
    `via=ops-struct[.slot]`. It defaults off, so the default return — and therefore
    the JSON a programmatic caller sees — is byte-identical to before."""
    prov = _file_provenance(gl)
    out: list[dict] = []
    seen: dict[str, int] = {}

    def _add(decl: dict, via: str, resolved: bool, edge: dict | None = None) -> None:
        f, l, _ = gl.loc(decl)
        if not include_external and _is_external(f, prov):
            return
        did = decl["id"]
        if did in seen:  # prefer the direct tag when a pair is reachable both ways
            idx = seen[did]
            if via == "direct" and out[idx]["via"] != "direct":
                out[idx].update(via="direct", resolved=True)
            return
        seen[did] = len(out)
        row = {"node_id": did, "name": gl.label(decl), "kind": gl.kind(did),
               "file": f, "line": l, "via": via, "resolved": resolved}
        if with_dispatch and edge is not None:
            row.update(_dispatch_of(edge))
        out.append(row)

    for node in gl.index.sources(node_id, *CALL_EDGES):
        decl = gl.owner_function(node) or node
        _add(decl, "direct", True)
    if direct_only:
        return out
    for edge in gl.index.incoming_of_kind(node_id, *INDIRECT_CALL_EDGES):
        src = gl.nodes.get(edge.get("source"))
        if src is None:
            continue
        decl = _caller_decl(gl, src) or src
        _add(decl, _via_label(edge), True, edge)
    return out


def callees(gl: GraphLib, node_id: str, include_external: bool = False,
            direct_only: bool = False, with_dispatch: bool = False) -> list[dict]:
    """What this node calls — a traversal move, direct + indirect dispatch (tagged).

    Direct (``CALLS``) targets are already declarations. Indirect targets come from
    the call-sites this function owns: each INDIRECT edge's target is the resolved
    callee declaration — except ``READS_CALLEE``, whose target is the unresolved
    function-pointer *slot* (a field/variable). Slot rows carry ``resolved=False`` so
    the indirection is visible without pretending a concrete callee was found. Every
    row is tagged ``via``; ``direct_only`` returns exactly the old decl->decl set.

    ``with_dispatch`` stamps each indirect row with the edge's ``dispatch``/``slot``
    (text-render differentiator); it defaults off, so the default return is unchanged."""
    prov = _file_provenance(gl)
    out: list[dict] = []
    seen: dict[str, int] = {}

    def _add(node: dict, via: str, resolved: bool, edge: dict | None = None) -> None:
        f, l, _ = gl.loc(node)
        if not include_external and _is_external(f, prov):
            return  # skip external stubs (e.g. Array.push in lib.es5.d.ts)
        nid = node["id"]
        if nid in seen:
            idx = seen[nid]
            if via == "direct" and out[idx]["via"] != "direct":
                out[idx].update(via="direct", resolved=True)
            return
        seen[nid] = len(out)
        row = {"node_id": nid, "name": gl.label(node), "kind": gl.kind(nid),
               "file": f, "line": l, "via": via, "resolved": resolved}
        if with_dispatch and edge is not None:
            row.update(_dispatch_of(edge))
        out.append(row)

    for node in gl.index.targets(node_id, *CALL_EDGES):
        _add(node, "direct", True)
    if direct_only:
        return out
    for site in _owned_callsites(gl, node_id):
        for edge in gl.index.outgoing_of_kind(site["id"], *INDIRECT_CALL_EDGES):
            tgt = gl.nodes.get(edge.get("target"))
            if tgt is None:
                continue
            _add(tgt, _via_label(edge), gl.kind(tgt["id"]) in CALLABLE_KINDS, edge)
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
    p.add_argument("--direct-only", action="store_true",
                   help="with --refs/--callees: only direct CALLS edges (drop indirect dispatch)")
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
            move = callers if args.refs else callees
            moves = move(gl, tgt["node_id"], direct_only=args.direct_only)
            verb = "callers of" if args.refs else "callees of"
            if args.json:
                print(json.dumps({"target": tgt, "verb": verb, "moves": moves}, indent=2, ensure_ascii=False))
            else:
                print(f"{verb} {tgt['name']}  ({tgt['file']}:{tgt['line']}):")
                for m in moves or []:
                    tag = m.get("via", "")
                    if tag and not m.get("resolved", True):
                        tag += " [unresolved]"
                    print(f"{_fmt(m)}    {tag}".rstrip())
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
