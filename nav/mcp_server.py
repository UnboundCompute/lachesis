#!/usr/bin/env python3
"""nav-reasoning — a dependency-free MCP (stdio JSON-RPC) server: the LLM's hands on the graph.

This is the last piece: it wraps the *already-proven* reasoning library (graph_store,
reachability, guards, call_roles, siblings) as MCP tools so an agent can navigate and
reason over the canonical Arachne graph directly. No SDK, no new dependency — the same
hand-rolled stdio JSON-RPC loop shrude-memory uses (stdout = protocol channel, all logs
to stderr).

The graph + sidecar overlay load **once** at startup; every tool is then O(neighbors),
not a re-parse. Each reasoning tool returns the shared `path_shape` envelope (nodes
named + file:line, edges typed with via/reason/role/confidence/fact_origin), so the
agent gets one consistent, provenance-carrying shape back from every move.

Tools:
  navigation — search, callers, callees, open_file (L1), open_folder (L0)
  reasoning  — flow, reaches, sources_of, points_to, aliases, guards, call_roles, siblings

  python3 nav/mcp_server.py <graph.json> [overlay.json]
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
from nav.folder_graph import build_folder_graph
from nav.file_graph import build_file_graph, _find_file_node

_GRAPH_PATH = None
_OVERLAY_PATH = None
_CTX = None  # lazily-built bundle of store + engines, loaded once


def log(*a):
    print("[nav-reasoning]", *a, file=sys.stderr, flush=True)


class _Ctx:
    def __init__(self, graph_path, overlay_path):
        self.store = GraphStore.load(graph_path, overlay_path=overlay_path)
        self.reach = Reachability(self.store)
        self.guards = GuardProfiles(self.store)
        self.roles = CallRoles(self.store, guards=self.guards)
        self.siblings = SiblingDiff(self.store)
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


TOOLS = [
    {"name": "search",
     "description": "Resolve a function/method/type/file name to its canonical node id(s) with "
                    "file:line. The entry point — teleport to any symbol, fuzzy by default.",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"}}, "required": ["name"]}},
    {"name": "callers",
     "description": "Who calls this symbol (reverse call graph, external stubs filtered). A jump move.",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"}}, "required": ["name"]}},
    {"name": "callees",
     "description": "What this symbol calls (forward call graph, in-repo only). A jump move.",
     "inputSchema": {"type": "object", "properties": {
         "name": {"type": "string"}}, "required": ["name"]}},
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


def call_tool(name, args):
    c = ctx()
    store, gl = c.store, c.store.gl

    if name == "search":
        return json.dumps({"query": args["name"], "hits": store.resolve(args["name"])})
    if name in ("callers", "callees"):
        seed = _seed(store, args["name"])
        if not seed:
            return json.dumps({"error": f"no node named {args['name']!r}"})
        moves = (si.callers if name == "callers" else si.callees)(gl, seed)
        return json.dumps({name: moves, "of": args["name"]})
    if name == "open_file":
        fn = _find_file_node(gl, path=args["file"], file_id=None)
        if not fn:
            return json.dumps({"error": f"no file node for {args['file']!r}"})
        return json.dumps(build_file_graph(gl, fn))
    if name == "open_folder":
        return json.dumps(build_folder_graph(gl, root=args["root"]))
    if name == "flow":
        seed = _seed(store, args["seed"])
        if not seed:
            return json.dumps({"error": f"no node for {args['seed']!r}"})
        return json.dumps(c.reach.flow(seed, limit=int(args.get("limit", 200))))
    if name == "reaches":
        src, sink = _seed(store, args["src"]), _seed(store, args["sink"])
        if not src or not sink:
            return json.dumps({"error": "could not resolve src/sink"})
        return json.dumps(c.reach.reaches(src, sink))
    if name == "sources_of":
        sink = _seed(store, args["sink"])
        if not sink:
            return json.dumps({"error": f"no node for {args['sink']!r}"})
        return json.dumps(c.reach.sources_of(sink, limit=int(args.get("limit", 200))))
    if name == "points_to":
        value = _seed(store, args["value"])
        if not value:
            return json.dumps({"error": f"no node for {args['value']!r}"})
        heaps = list(store.index.targets(value, "POINTS_TO"))
        edges = store.index.outgoing_of_kind(value, "POINTS_TO")
        return json.dumps(store.path_shape([store.node(value)] + heaps, edges,
                                           manifest={"move": "points_to", "value": value}))
    if name == "aliases":
        value = _seed(store, args["value"])
        if not value:
            return json.dumps({"error": f"no node for {args['value']!r}"})
        alias_nodes, edges = [], []
        for heap in store.index.targets(value, "POINTS_TO"):
            for sib in store.index.sources(heap["id"], "POINTS_TO"):
                if sib["id"] != value:
                    alias_nodes.append(sib)
                    edges.append({"source": value, "target": sib["id"],
                                  "kind": "POINTS_TO",
                                  "properties": {"reason": "alias-via-heap",
                                                 "via": heap["id"]}})
        return json.dumps(store.path_shape([store.node(value)] + alias_nodes, edges,
                                           manifest={"move": "aliases", "value": value}))
    if name == "guards":
        fn = _seed(store, args["fn"])
        if not fn:
            return json.dumps({"error": f"no function for {args['fn']!r}"})
        return json.dumps({"function": gl.label(store.node(fn)),
                           "guard_signal": c.guards.profile(fn)})
    if name == "call_roles":
        fn = _seed(store, args["fn"])
        if not fn:
            return json.dumps({"error": f"no function for {args['fn']!r}"})
        recs = c.roles.roles_for(fn)
        return json.dumps({"function": gl.label(store.node(fn)),
                           "calls": [{"callee": r["callee"], "role": r["role"],
                                      "fact_origin": r["fact_origin"],
                                      "at": f"{r['file']}:{r['line']}"} for r in recs]})
    if name == "siblings":
        hits = store.resolve(args["sym"])
        if not hits:
            return json.dumps({"error": f"no node named {args['sym']!r}"})
        return json.dumps(c.siblings.diff(hits[0]))
    raise ValueError(f"unknown tool: {name}")


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main():
    global _GRAPH_PATH, _OVERLAY_PATH
    if len(sys.argv) < 2:
        print("usage: mcp_server.py <graph.json> [overlay.json]", file=sys.stderr)
        return 2
    _GRAPH_PATH = sys.argv[1]
    _OVERLAY_PATH = sys.argv[2] if len(sys.argv) > 2 else None
    log(f"starting; graph = {_GRAPH_PATH}")
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
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            p = msg.get("params") or {}
            try:
                text = call_tool(p["name"], p.get("arguments") or {})
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
