#!/usr/bin/env python3
"""nav-reasoning — a dependency-free MCP (stdio JSON-RPC) server: the LLM's hands on the graph.

This is the last piece: it wraps the *already-proven* reasoning library (graph_store,
reachability, guards, call_roles, siblings) as MCP tools so an agent can navigate and
reason over the canonical Lachesis graph directly. No SDK, no new dependency — just a
hand-rolled stdio JSON-RPC loop, with the usual discipline that makes that safe
(stdout is the protocol channel and carries nothing but JSON-RPC; all logs go to
stderr).

The graph + sidecar overlay load **once** at startup; every tool is then O(neighbors),
not a re-parse. Each reasoning tool returns the shared `path_shape` envelope (nodes
named + file:line, edges typed with via/reason/role/confidence/fact_origin), so the
agent gets one consistent, provenance-carrying shape back from every move.

Tools:
  cold-start — hubs (centrality spine; language-agnostic), guards_top (guard-shaped; security)
  navigation — search, callers, callees, read_body (L3), open_file (L1), open_folder (L0)
  reasoning  — flow, reaches, sources_of, points_to, aliases, guards, call_roles, siblings

Profiles (additive): the default "all" exposes every tool (TS surface unchanged). The
opt-in "comprehension" profile (env LACHESIS_MCP_PROFILE=comprehension, or a 3rd argv)
hides the four security tools for a focused understanding run — nothing else changes.

  python3 nav/mcp_server.py <graph.json> [overlay.json] [profile]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nav.graph_store import GraphStore
from nav.reachability import Reachability
from nav.guards import GuardProfiles
from nav.call_roles import CallRoles
from nav.siblings import SiblingDiff
from nav import symbol_index as si
from nav.hubs import Hubs
from nav.folder_graph import build_folder_graph
from nav.file_graph import build_file_graph, _find_file_node
from nav import render as render_mod

_GRAPH_PATH = None
_OVERLAY_PATH = None
_CTX = None  # lazily-built bundle of store + engines, loaded once
_PROFILE = "all"  # tool-surface profile: "all" (default) | "comprehension"
# Process-wide default output format for tools/call when a call omits `format`.
# "text" = compact LLM-facing rendering (Spec 1); "json" = the full result dict.
# Set from LACHESIS_FORMAT in main(); defaults to text.
_DEFAULT_FORMAT = "text"

# The security-hunting tools. Under the DEFAULT "all" profile every one is exposed
# exactly as before (TS surface unchanged). The opt-in "comprehension" profile hides
# these four for a focused language-agnostic (C/kernel) understanding run — the only
# mode that narrows the surface, and only when explicitly requested.
SECURITY_TOOLS = ("guards", "call_roles", "siblings", "guards_top")

# Canonical display order for tools/list: the centrality cold-start (hubs) leads, then
# navigation, then value-flow reasoning, then the security tools last. Ordering only —
# a name missing here (or a future tool) still shows, appended in definition order.
TOOL_ORDER = (
    "load_graph",
    "hubs", "search", "callers", "callees", "read_body", "open_file", "open_folder",
    "flow", "reaches", "sources_of", "points_to", "aliases",
    "guards", "call_roles", "siblings", "guards_top",
)


def _visible_tools():
    """TOOLS filtered by the active profile and sorted into canonical order."""
    tools = TOOLS if _PROFILE != "comprehension" \
        else [t for t in TOOLS if t["name"] not in SECURITY_TOOLS]
    rank = {n: i for i, n in enumerate(TOOL_ORDER)}
    return sorted(tools, key=lambda t: rank.get(t["name"], len(rank)))


def log(*a):
    print("[nav-reasoning]", *a, file=sys.stderr, flush=True)


class _Ctx:
    def __init__(self, graph_path, overlay_path):
        self.store = GraphStore.load(graph_path, overlay_path=overlay_path)
        self.reach = Reachability(self.store)
        self.guards = GuardProfiles(self.store)
        self.roles = CallRoles(self.store, guards=self.guards)
        self.siblings = SiblingDiff(self.store)
        self.hubs = Hubs(self.store.gl)
        log(f"loaded {len(self.store.gl.nodes)} nodes; "
            f"overlay: {self.store.overlay.summary()['derived_edges']} derived edges")


def ctx():
    global _CTX
    if _CTX is None:
        _CTX = _Ctx(_GRAPH_PATH, _OVERLAY_PATH)
    return _CTX


def _seed(store, token):
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None


def _ref(store, node_id):
    """A reusable handle for a node: {node_id, name, at} so an agent always gets
    an addressable reference back — never just a non-unique `<anonymous@N>` name."""
    node = store.node(node_id)
    if not node:
        return {"node_id": node_id, "name": None, "at": None}
    f, l, _ = store.gl.loc(node)
    return {"node_id": node_id, "name": store.gl.label(node),
            "at": f"{f}:{l}" if f and l else None}


TOOLS = [
    {"name": "load_graph",
     "description": "Switch/attach the active graph the whole server reasons over — point it at a "
                    "different target (e.g. bnxt -> igb) mid-session with no restart. Takes a canonical "
                    "graph JSON path and an optional overlay + profile; the graph loads once and every "
                    "subsequent tool hits the in-memory copy.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string"},
         "overlay": {"type": "string"},
         "profile": {"type": "string", "enum": ["all", "comprehension"]}},
         "required": ["path"]}},
    {"name": "guards_top",
     "description": "The N most guard-shaped functions, ranked by derived guard signal, with no "
                    "name knowledge needed — a security-hunting entry point (for the spine of an "
                    "unfamiliar subsystem, use `hubs` instead). Each row carries node_id + handle "
                    "(file:line) so a high-signal function (even an anonymous one) is immediately "
                    "navigable.",
     "inputSchema": {"type": "object", "properties": {
         "n": {"type": "integer", "default": 20}}}},
    {"name": "hubs",
     "description": "The subsystem's spine: the N highest-degree functions over the UNION call "
                    "graph (direct CALLS + indirect function-pointer / ops-struct / runtime "
                    "dispatch), ranked by fan_in + fan_out — no name knowledge needed. Each row "
                    "carries node_id + handle (file:line), fan_in/fan_out/degree, and entry-point "
                    "flags (exported | dispatch_target | callback). Language-agnostic cold-start: "
                    "start here to find what a subsystem is built around, THEN callers/callees/"
                    "read_body to traverse.",
     "inputSchema": {"type": "object", "properties": {
         "n": {"type": "integer", "default": 20}}}},
    {"name": "search",
     "description": "Resolve a function/method/type/file name to its canonical node id(s) with "
                    "file:line. Teleport to any symbol, fuzzy by default. Returns a real "
                    "match total with paging (limit/offset), and de-prioritizes test/spec "
                    "symbols. NOTE: on a cold graph prefer `guards_top` first — blind "
                    "name-search has no ranking; use this once you know a name.",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"},
         "limit": {"type": "integer", "default": 25},
         "offset": {"type": "integer", "default": 0}},
         "required": ["name"]}},
    {"name": "callers",
     "description": "Who calls this symbol — direct + indirect dispatch (function-pointer / "
                    "ops-struct / runtime), external stubs filtered. Each row tagged via: "
                    "direct | indirect(may_invoke|context|fn-pointer). Set direct_only to get "
                    "only resolved decl->decl CALLS. A jump move.",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"},
         "direct_only": {"type": "boolean"}}, "required": ["name"]}},
    {"name": "callees",
     "description": "What this symbol calls — direct + indirect dispatch, in-repo only. Each row "
                    "tagged via: direct | indirect(...); an indirect row with resolved:false is an "
                    "unresolved function-pointer slot (the indirection is real, the target isn't "
                    "pinned). Set direct_only for resolved decl->decl CALLS only. A jump move.",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"},
         "direct_only": {"type": "boolean"}}, "required": ["name"]}},
    {"name": "read_body",
     "description": "Read a function/method's real source (L3) — the 'open this and read it' move, "
                    "so an agent never falls back to cat. Accepts a name or a node_id; returns the "
                    "exact source span from byte offsets plus {node_id, name, file, start_line, "
                    "end_line}, capped at max_chars (default 4000) with a truncated flag. If the "
                    "file/offsets are unavailable it reconstructs a best-effort body from the "
                    "function's L3 body nodes in line order.",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"},
         "node_id": {"type": "string"},
         "max_chars": {"type": "integer", "default": 4000}}}},
    {"name": "open_file",
     "description": "L1 file graph: imports, declarations, intra-file calls, cross-file jump-stubs "
                    "for one file (repo-relative path). Returns a {nodes,edges,manifest} graph.",
     "inputSchema": {"type": "object", "properties": {
         "file": {"type": "string"}}, "required": ["file"]}},
    {"name": "open_folder",
     "description": "L0 folder graph rooted at a path prefix: folder->file->declarations.",
     "inputSchema": {"type": "object", "properties": {
         "root": {"type": "string"}}, "required": ["root"]}},
    {"name": "flow",
     "description": "Forward value-flow cone from a value/symbol: everything it reaches over "
                    "VALUE_FLOWS_TO + POINTS_TO (with alias-via-heap bridging). path_shape.",
     "inputSchema": {"type": "object", "properties": {
         "seed": {"type": "string"}, "limit": {"type": "integer", "default": 200}},
         "required": ["seed"]}},
    {"name": "reaches",
     "description": "Does src reach sink through value flow? Returns the labeled witness path or a "
                    "negative answer. src/sink may be node ids or names.",
     "inputSchema": {"type": "object", "properties": {
         "src": {"type": "string"}, "sink": {"type": "string"}},
         "required": ["src", "sink"]}},
    {"name": "sources_of",
     "description": "Reverse value-flow cone: which values can feed this sink. path_shape.",
     "inputSchema": {"type": "object", "properties": {
         "sink": {"type": "string"}, "limit": {"type": "integer", "default": 200}},
         "required": ["sink"]}},
    {"name": "points_to",
     "description": "Heap objects a value points to (POINTS_TO). path_shape.",
     "inputSchema": {"type": "object", "properties": {
         "value": {"type": "string"}}, "required": ["value"]}},
    {"name": "aliases",
     "description": "Values that alias this one (share a heap-object via POINTS_TO) — the "
                    "destructuring/alias set. path_shape.",
     "inputSchema": {"type": "object", "properties": {
         "value": {"type": "string"}}, "required": ["value"]}},
    {"name": "guards",
     "description": "Derived guard profile of a function (Fix 2): score, class "
                    "(guard|validate|passthrough), and the raw CONDITION/short-circuit/throw counts.",
     "inputSchema": {"type": "object", "properties": {
         "fn": {"type": "string"}}, "required": ["fn"]}},
    {"name": "call_roles",
     "description": "Type the outgoing calls of a function by derived security role "
                    "(verify|sanitize|authz|validate|none) — Fix 4. NOT AST structural roles.",
     "inputSchema": {"type": "object", "properties": {
         "fn": {"type": "string"}}, "required": ["fn"]}},
    {"name": "siblings",
     "description": "Peer differential (Fix 3): form the symbol's cross-module family, classify each "
                    "member guarded/unguarded with guard transitivity, and flag the unguarded outlier "
                    "shown against the peer guard it lacks (negative space).",
     "inputSchema": {"type": "object", "properties": {
         "sym": {"type": "string"}}, "required": ["sym"]}},
]

# Every tool accepts an optional `format` ("text" compact | "json" full). Inject it
# once here so each tool advertises it in tools/list without repeating the property on
# 17 schemas. `load_graph` is control-plane, not a graph query, so it is left json-only.
for _t in TOOLS:
    if _t["name"] != "load_graph":
        _t["inputSchema"].setdefault("properties", {})["format"] = {
            "type": "string", "enum": ["text", "json"],
            "description": "text (compact, default) | json (full result dict)"}
# Paging fields on the list-shaped moves: they window the TEXT rendering only (JSON is
# always the full, un-paged result), so a call on a 400-caller hub stays bounded.
for _name in ("hubs", "callers", "callees"):
    _tool = next(t for t in TOOLS if t["name"] == _name)
    _tool["inputSchema"]["properties"].update(
        offset={"type": "integer", "default": 0},
        limit={"type": "integer", "default": 40})


def _emit(name, result, fmt, offset=0, limit=render_mod.DEFAULT_LIMIT):
    """Serialize a tool's result dict: full JSON, or compact text via the renderer.

    JSON is byte-identical to the pre-render behavior; text applies id/handle/null
    stripping, path relativization, and the offset/limit window (text-only paging)."""
    if fmt == "json":
        return json.dumps(result)
    return render_mod.render(name, result, offset=offset, limit=limit)


def call_tool(name, args, format=None):
    fmt = "json" if format == "json" else ("text" if format == "text" else _DEFAULT_FORMAT)
    offset, limit = int(args.get("offset", 0)), int(args.get("limit", render_mod.DEFAULT_LIMIT))

    if name == "load_graph":
        return _load_graph(args)
    if _PROFILE == "comprehension" and name in SECURITY_TOOLS:
        return _emit(name, {"error": f"tool {name!r} is hidden under the "
                                     "'comprehension' profile (security tool)"}, fmt)
    c = ctx()
    store, gl = c.store, c.store.gl
    text = fmt != "json"  # text mode enriches callers/callees with dispatch slots

    if name == "guards_top":
        rows = c.guards.top(int(args.get("n", 20)))
        return _emit(name, {"move": "guards_top", "count": len(rows), "ranked": [
            {"node_id": r["node_id"], "name": r["name"], "at": r["handle"],
             "score": r["guard_signal"]["score"], "class": r["guard_signal"]["class"],
             "conditions": r["guard_signal"]["conditions"],
             "short_circuits": r["guard_signal"]["short_circuits"],
             "throws": r["guard_signal"]["throws"],
             "security_weight": r["guard_signal"]["security_weight"]}
            for r in rows]}, fmt, offset, limit)
    if name == "hubs":
        rows = c.hubs.top(int(args.get("n", 20)))
        return _emit(name, {"move": "hubs", "count": len(rows), "ranked": rows},
                     fmt, offset, limit)
    if name == "search":
        page = si.search_page(store.entries, args["name"], "fuzzy",
                              int(args.get("limit", 25)), int(args.get("offset", 0)))
        return _emit(name, page, fmt, offset, limit)
    if name in ("callers", "callees"):
        seed = _seed(store, args["name"])
        if not seed:
            return _emit(name, {"error": f"no node named {args['name']!r}"}, fmt)
        move = si.callers if name == "callers" else si.callees
        moves = move(gl, seed, direct_only=bool(args.get("direct_only")),
                     with_dispatch=text)
        return _emit(name, {name: moves, "of": args["name"]}, fmt, offset, limit)
    if name == "read_body":
        seed = args.get("node_id") if store.node(args.get("node_id") or "") \
            else _seed(store, args.get("name") or "")
        if not seed:
            return _emit(name, {"error": f"no node named {args.get('name') or args.get('node_id')!r}"}, fmt)
        node = store.node(seed)
        f, sl, el = gl.loc(node)
        body = gl.source_text(node)
        via = "offsets"
        if not body:  # file/offsets unavailable — reconstruct from L3 body nodes in line order
            parts = sorted((n for n in gl.body_nodes(seed)),
                           key=lambda n: (gl.loc(n)[1] or 0))
            body = "\n".join(gl.label(n) for n in parts if gl.label(n))
            via = "body_nodes"
        cap = int(args.get("max_chars", 4000))
        truncated = len(body) > cap
        return _emit(name, {"move": "read_body", "node_id": seed, "name": gl.label(node),
                            "file": f, "start_line": sl, "end_line": el, "via": via,
                            "truncated": truncated, "body": body[:cap]}, fmt)
    if name == "open_file":
        fn = _find_file_node(gl, path=args["file"], file_id=None)
        if not fn:
            return _emit(name, {"error": f"no file node for {args['file']!r}"}, fmt)
        return _emit(name, build_file_graph(gl, fn), fmt, offset, limit)
    if name == "open_folder":
        return _emit(name, build_folder_graph(gl, root=args["root"]), fmt, offset, limit)
    if name == "flow":
        seed = _seed(store, args["seed"])
        if not seed:
            return _emit(name, {"error": f"no node for {args['seed']!r}"}, fmt)
        return _emit(name, c.reach.flow(seed, limit=int(args.get("limit", 200))),
                     fmt, offset, limit)
    if name == "reaches":
        src, sink = _seed(store, args["src"]), _seed(store, args["sink"])
        if not src or not sink:
            return _emit(name, {"error": "could not resolve src/sink"}, fmt)
        return _emit(name, c.reach.reaches(src, sink), fmt, offset, limit)
    if name == "sources_of":
        sink = _seed(store, args["sink"])
        if not sink:
            return _emit(name, {"error": f"no node for {args['sink']!r}"}, fmt)
        return _emit(name, c.reach.sources_of(sink, limit=int(args.get("limit", 200))),
                     fmt, offset, limit)
    if name == "points_to":
        value = _seed(store, args["value"])
        if not value:
            return _emit(name, {"error": f"no node for {args['value']!r}"}, fmt)
        heaps = list(store.index.targets(value, "POINTS_TO"))
        edges = store.index.outgoing_of_kind(value, "POINTS_TO")
        return _emit(name, store.path_shape([store.node(value)] + heaps, edges,
                                            manifest={"move": "points_to", "value": value}),
                     fmt, offset, limit)
    if name == "aliases":
        value = _seed(store, args["value"])
        if not value:
            return _emit(name, {"error": f"no node for {args['value']!r}"}, fmt)
        alias_nodes, edges = [], []
        for heap in store.index.targets(value, "POINTS_TO"):
            for sib in store.index.sources(heap["id"], "POINTS_TO"):
                if sib["id"] != value:
                    alias_nodes.append(sib)
                    edges.append({"source": value, "target": sib["id"],
                                  "kind": "POINTS_TO",
                                  "properties": {"reason": "alias-via-heap",
                                                 "via": heap["id"]}})
        return _emit(name, store.path_shape([store.node(value)] + alias_nodes, edges,
                                            manifest={"move": "aliases", "value": value}),
                     fmt, offset, limit)
    if name == "guards":
        fn = _seed(store, args["fn"])
        if not fn:
            return _emit(name, {"error": f"no function for {args['fn']!r}"}, fmt)
        return _emit(name, {"function": _ref(store, fn),
                            "guard_signal": c.guards.profile(fn)}, fmt)
    if name == "call_roles":
        fn = _seed(store, args["fn"])
        if not fn:
            return _emit(name, {"error": f"no function for {args['fn']!r}"}, fmt)
        recs = c.roles.roles_for(fn)
        return _emit(name, {"function": _ref(store, fn),
                            "calls": [{"callee": r["callee"], "role": r["role"],
                                       "fact_origin": r["fact_origin"],
                                       "at": f"{r['file']}:{r['line']}"} for r in recs]}, fmt)
    if name == "siblings":
        hits = store.resolve(args["sym"])
        if not hits:
            return _emit(name, {"error": f"no node named {args['sym']!r}"}, fmt)
        return _emit(name, c.siblings.diff(hits[0]), fmt, offset, limit)
    raise ValueError(f"unknown tool: {name}")


def _load_graph(args):
    """Runtime target switch: repoint the server and drop the cached ctx so the next
    tool call rebuilds against the new graph (load-once still holds within a target)."""
    global _GRAPH_PATH, _OVERLAY_PATH, _PROFILE, _CTX
    path = args.get("path")
    if not path or not os.path.exists(path):
        return json.dumps({"error": f"graph path not found: {path!r}"})
    _GRAPH_PATH = path
    _OVERLAY_PATH = args.get("overlay")
    prof = args.get("profile")
    if prof in ("all", "comprehension"):
        _PROFILE = prof
    _CTX = None
    c = ctx()  # eager load so a load failure surfaces here, not on the next tool call
    return json.dumps({"move": "load_graph", "graph": path, "profile": _PROFILE,
                       "nodes": len(c.store.gl.nodes)})


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    global _GRAPH_PATH, _OVERLAY_PATH, _PROFILE, _DEFAULT_FORMAT
    # Config precedence: explicit argv wins, else env. The graph path may come from
    # argv[1] or LACHESIS_GRAPH; a session can also (re)attach at runtime via load_graph.
    _GRAPH_PATH = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("LACHESIS_GRAPH")
    if not _GRAPH_PATH:
        print("usage: mcp_server.py <graph.json> [overlay.json] [profile]\n"
              "   or: LACHESIS_GRAPH=<graph.json> mcp_server.py", file=sys.stderr)
        return 2
    _OVERLAY_PATH = sys.argv[2] if len(sys.argv) > 2 else None
    # Profile: explicit 3rd argv wins, else env (LACHESIS_PROFILE, back-compat
    # LACHESIS_MCP_PROFILE), else the default "all". Only "comprehension" narrows the
    # surface; any other value falls back to "all".
    profile = (sys.argv[3] if len(sys.argv) > 3
               else os.environ.get("LACHESIS_PROFILE")
               or os.environ.get("LACHESIS_MCP_PROFILE", "all"))
    _PROFILE = "comprehension" if profile == "comprehension" else "all"
    # Default output format when a tools/call omits `format`: text (compact) unless
    # LACHESIS_FORMAT=json flips the whole server back to full JSON.
    _DEFAULT_FORMAT = render_mod.default_format()
    log(f"starting; graph = {_GRAPH_PATH}; profile = {_PROFILE}; format = {_DEFAULT_FORMAT}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as e:  # noqa: BLE001
            log("bad json:", e)
            continue
        mid, method = msg.get("id"), msg.get("method")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nav-reasoning", "version": "0.1.0"}}})
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": _visible_tools()}})
        elif method == "tools/call":
            p = msg.get("params") or {}
            try:
                a = p.get("arguments") or {}
                text = call_tool(p["name"], a, format=a.get("format"))
                send({"jsonrpc": "2.0", "id": mid,
                      "result": {"content": [{"type": "text", "text": text}]}})
            except Exception as e:  # noqa: BLE001
                log("tool error:", e)
                send({"jsonrpc": "2.0", "id": mid,
                      "result": {"content": [{"type": "text", "text": f"error: {e}"}],
                                 "isError": True}})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif mid is not None:
            send({"jsonrpc": "2.0", "id": mid,
                  "error": {"code": -32601, "message": f"method not found: {method}"}})


if __name__ == "__main__":
    raise SystemExit(main())
