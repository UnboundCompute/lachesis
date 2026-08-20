#!/usr/bin/env python3
"""lachesis — a dependency-free MCP (stdio JSON-RPC) server: the LLM's hands on the graph.

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
  hunting    — candidates, candidate_detail, candidate_census (facts and ranking, no verdict)

Profiles (additive): the default "all" exposes every tool (TS surface unchanged). The
opt-in "comprehension" profile (env LACHESIS_MCP_PROFILE=comprehension, or a 3rd argv)
hides the four security tools for a focused understanding run — nothing else changes.

  python3 nav/mcp_server.py <graph.kuzu> [overlay.json] [profile]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lachesis.nav.graph_store import GraphStore
from lachesis.nav.reachability import Reachability
from lachesis.nav.guards import GuardProfiles
from lachesis.nav.call_roles import CallRoles
from lachesis.nav.siblings import SiblingDiff
from lachesis.nav import symbol_index as si
from lachesis.nav.hubs import Hubs
from lachesis.nav.folder_graph import build_folder_graph
from lachesis.nav.file_graph import build_file_graph, _find_file_node
from lachesis.nav import render as render_mod
from lachesis.nav import skeleton as skeleton_mod
from lachesis.nav.comprehension import Comprehension

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

# Removed for now: each of these builds `GuardProfiles`, whose `_build()` scans every
# guard-kind edge across the WHOLE graph (and `call_roles` also full-scans CALLS). On a
# large graph (e.g. Django: millions of CONDITION/short-circuit edges) that is a
# multi-minute, all-cores cold start. A hard "never scan the whole graph" rule takes
# precedence, so these are hidden from tools/list and refuse to run until the guard
# signal is reworked to a bounded, per-seed computation.
DISABLED_TOOLS = SECURITY_TOOLS

# The tools that genuinely read overlay-derived edges, and therefore the only ones a
# core-only store has to fold for. Everything else was folding for nothing: measured on
# the pinned corpus, twelve of the seventeen tools answer *identically* against a store
# whose overlay tier was never built -- 4,523 rows, zero lost. Only `flow` lost real
# ground (20 edges: POINTS_TO, READS_HEAP, VALUE_FLOWS_TO, all from the heap overlay),
# and `points_to`/`aliases` read POINTS_TO out of the index by hand a few lines below.
#
# What it costs is honest and small: `hubs` and `search` rank by degree, and degree over
# the core graph is lower than degree over the enriched one, so their *ordering* shifts
# even though their membership does not.
#
# These five no longer fold the whole graph either. Each one names a seed, so each one
# folds the call neighbourhood of that seed and nothing else -- see
# `GraphStore.ensure_dataflow_cone`. `reaches` names two, and gets both.
#
# The order hazard is worth naming, because it is now real. A cone graft mutates the
# shared index, so a `flow` from one seed leaves edges behind that a later `flow` from a
# different seed can see, and running the two in the other order gives the second one a
# smaller graph to reason over. The result is *monotone* -- more folding never removes an
# edge -- so no answer is wrong, but two sessions can disagree on how much they found.
# `cone.truncated` and the grafted counts are reported for exactly this reason: the
# scope is part of the answer, so it is in the answer.
OVERLAY_TOOLS = ("flow", "reaches", "sources_of", "points_to", "aliases")

# Which argument each of them seeds from. A cone needs a centre, and the centre is the
# node the caller already asked about; deriving it from the arguments keeps that in one
# place rather than repeating a fold call in five branches below.
OVERLAY_SEED_ARGS = {
    "flow": ("seed",), "reaches": ("src", "sink"), "sources_of": ("sink",),
    "points_to": ("value",), "aliases": ("value",),
}

# Canonical display order for tools/list: the centrality cold-start (hubs) leads, then
# navigation, then value-flow reasoning, then the security tools last. Ordering only —
# a name missing here (or a future tool) still shows, appended in definition order.
TOOL_ORDER = (
    "load_graph",
    "hubs", "search", "callers", "callees", "read_body", "open_file", "open_folder",
    "unknowns", "coverage_map", "field_history", "sibling_compare",
    "type_explain", "component_boundary", "indirect_targets",
    "architecture_map", "execution_story",
    "flow", "reaches", "sources_of", "points_to", "aliases",
    "candidates", "candidate_detail", "candidate_census", "skeleton",
    "flow_pass", "flow_skeleton", "taint",
    "guards", "call_roles", "siblings", "guards_top",
)


def _visible_tools():
    """TOOLS filtered by the active profile and sorted into canonical order."""
    hidden = set(DISABLED_TOOLS)
    if _PROFILE == "comprehension":
        hidden |= set(SECURITY_TOOLS)
    tools = [t for t in TOOLS if t["name"] not in hidden]
    rank = {n: i for i, n in enumerate(TOOL_ORDER)}
    return sorted(tools, key=lambda t: rank.get(t["name"], len(rank)))


def log(*a):
    print("[lachesis-mcp]", *a, file=sys.stderr, flush=True)


# What this server calls itself when a client asks. It is the name the user sees in
# their client's server list, so it is the product's name -- not `nav-reasoning`, which
# is an internal overlay identifier that happens to be where this code grew up. The
# overlay keeps that identifier: it is written into graph provenance, and renaming it
# would change what already-built stores say about themselves.
SERVER_NAME = "lachesis"
# Reported straight from the installed distribution, so the version a client sees is the
# version that is actually running rather than a literal that drifts at the next release.
try:
    from importlib.metadata import PackageNotFoundError, version as _distribution_version

    SERVER_VERSION = _distribution_version("lachesis-cpg")
except (ImportError, PackageNotFoundError):  # a source checkout that was never installed
    SERVER_VERSION = "0+unknown"


class _Ctx:
    """The loaded store plus the analysis objects, all built on first use.

    Lazy for two reasons. A store built without ``--enrich`` grows its dataflow tier on
    demand, and that rebinds ``store.index``; every analysis object here caches the
    index at construction, so anything built before the enrich would silently keep
    answering off the core tier. And orientation tools (`hubs`, `search`, `guards_top`)
    never touch dataflow, so they should never pay for it."""

    def __init__(self, graph_path, overlay_path):
        self.store = GraphStore.load(graph_path, overlay_path=overlay_path)
        self._built = {}
        self._tier = (self.store.dataflow_ready,
                      getattr(self.store, "cone_generation", 0))
        log(f"loaded {len(self.store.gl.nodes)} nodes; "
            f"overlay: {self.store.overlay.summary()['derived_edges']} derived edges; "
            f"dataflow tier: "
            f"{'present' if self.store.dataflow_ready else 'on demand, per cone'}")

    def _analysis(self, key, build):
        # Two ways the index can move: the whole tier arrives (`dataflow_ready` flips)
        # or a cone graft adds edges to the index in place (`cone_generation` ticks).
        # The second leaves `dataflow_ready` false forever -- the store still has no
        # full tier -- so watching only the flag would serve a `Reachability` built
        # before the graft, which is exactly the answer the graft existed to improve.
        tier = (self.store.dataflow_ready, getattr(self.store, "cone_generation", 0))
        if self._tier != tier:
            self._built.clear()  # the index moved under them; every cache is stale
            self._tier = tier
        if key not in self._built:
            self._built[key] = build()
        return self._built[key]

    @property
    def reach(self):
        # No `ensure_dataflow_tier` here. The cone for this call's seed is folded in
        # `call_tool`, which knows which argument the seed is; this property does not,
        # and folding the whole graph because it cannot tell is what cost 49 seconds.
        return self._analysis("reach", lambda: Reachability(self.store))

    @property
    def guards(self):
        return self._analysis("guards", lambda: GuardProfiles(self.store))

    @property
    def roles(self):
        return self._analysis("roles", lambda: CallRoles(self.store, guards=self.guards))

    @property
    def siblings(self):
        return self._analysis("siblings", lambda: SiblingDiff(self.store))

    @property
    def hubs(self):
        return self._analysis("hubs", lambda: Hubs(self.store.gl))

    @property
    def comprehension(self):
        return self._analysis("comprehension", lambda: Comprehension(self.store))

    @property
    def candidate_bundle(self):
        """The catalog-stamped graph and its cached obligation registry.

        Candidate enumeration binds catalog facts against the core symbol index. It
        deliberately does not build value flow or judge the resulting sites; the AI
        chooses follow-up graph tools for candidates it wants to investigate.
        """
        def build():
            from lachesis.integrations.atropos.enrich import atropos_enrich
            from lachesis.nav.kuzu_index import materialize_graph
            from lachesis.planner.registry import default_candidate_registry

            graph = materialize_graph(self.store.index)
            stamped, summary = atropos_enrich(graph, complete_dataflow=False)
            return {
                "registry": default_candidate_registry(stamped, summary),
                "stamped": stamped,
                "atropos": summary,
            }

        return self._analysis("candidate-registry", build)

    @property
    def flow_bundle(self):
        """The interprocedural flow pass over the whole graph, computed once and cached.

        Composes per-function summaries bottom-up, renders the stitched cross-function flow
        skeletons, and matches shape patterns over them. Reads the enriched graph only to
        project the IR; every later stage touches the IR, not the graph.
        """
        def build():
            from lachesis.flow.pipeline import run_pass
            return run_pass(self.store)

        return self._analysis("flow-pass", build)


def ctx():
    global _CTX
    if _CTX is None:
        _CTX = _Ctx(_GRAPH_PATH, _OVERLAY_PATH)
    return _CTX


def _seeds(store, token):
    """Every node this token could equally mean, best-first.

    A node id means itself. A name means as many nodes as share it, and `si.peers`
    decides which of the ranked hits are genuine rivals rather than also-rans."""
    if store.node(token):
        return [token]
    return [hit["node_id"] for hit in si.peers(store.resolve(token), token)]


def _seed(store, token):
    seeds = _seeds(store, token)
    return seeds[0] if seeds else None


def _fold_cone(store, name, args):
    """Fold the dataflow tier around this call's seeds. ``{}`` when nothing was scoped.

    Every tool that reads overlay-derived edges names the node it is about, so the fold
    can be scoped to that node's call neighbourhood rather than to the repo. This is the
    only place that mapping lives — a tool branch below must not have to remember to
    fold, because forgetting would not fail, it would quietly answer with fewer edges.

    The report rides back to the caller as ``cone``. Costing a query is a reasonable
    thing to want to see, and ``truncated`` there is load-bearing: it says the
    neighbourhood hit its budget, so the answer below is computed over less than
    everything that could reach the seed, and a smaller result may be an artifact of
    the scope rather than a fact about the code.
    """
    seed_args = OVERLAY_SEED_ARGS.get(name)
    if not seed_args:
        return {}
    folded = []
    for key in seed_args:
        token = args.get(key)
        if not token:
            continue
        seed = _seed(store, token)
        if seed:
            folded.append(store.ensure_dataflow_cone(seed))
    if not folded:
        return {}
    return {"cone": {
        "members": sum(f["members"] for f in folded),
        "nodes": sum(f["nodes"] for f in folded),
        "edges": sum(f["edges"] for f in folded),
        "truncated": any(f["truncated"] for f in folded),
    }}


def _alts(store, token):
    """``{"homonyms": [...]}`` when a token names more than one node, else nothing.

    The tools below that take a single seed still take a single seed — flow from four
    different `funcA`s at once is four answers, not one. What changes is that the
    caller is told the choice was made, and handed the ids it was made between, so a
    silent collapse becomes a visible one it can undo with an explicit node_id."""
    seeds = _seeds(store, token)
    if len(seeds) < 2:
        return {}
    return {"homonyms": [_ref(store, node_id) for node_id in seeds]}


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
    {"name": "unknowns",
     "description": "Explicit comprehension frontiers: unresolved calls, dynamic runtime "
                    "behavior, and parser/compiler diagnostics. Distinguishes proven-absent "
                    "from couldn't-cross instead of silently treating missing graph facts as none.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string", "description": "optional function name or node id"},
         "limit": {"type": "integer", "default": 100}}}},
    {"name": "coverage_map",
     "description": "Deterministic indexed-graph coverage by component: files, callable bodies, "
                    "diagnostics, and unmodeled frontiers. This reports graph coverage, not mutable "
                    "per-client session activity.",
     "inputSchema": {"type": "object", "properties": {
         "component_depth": {"type": "integer", "default": 1}}}},
    {"name": "field_history",
     "description": "For a field/property, list graph-evidenced initialization, modification, "
                    "reads, checks, and value-flow events with owning functions.",
     "inputSchema": {"type": "object", "properties": {
         "field": {"type": "string"},
         "owner_type": {"type": "string", "description": "optional type name/id disambiguator"}},
         "required": ["field"]}},
    {"name": "sibling_compare",
     "description": "Compare structurally similar callables by callees and control structure. "
                    "Returns differences as facts only; it does not rank anomalies or issue verdicts.",
     "inputSchema": {"type": "object", "properties": {
         "symbol": {"type": "string"}}, "required": ["symbol"]}},
    {"name": "type_explain",
     "description": "Explain a type from graph facts: fields and constructor, mutator, consumer, "
                    "and destructor method roles.",
     "inputSchema": {"type": "object", "properties": {
         "type": {"type": "string"}}, "required": ["type"]}},
    {"name": "component_boundary",
     "description": "Show calls, callbacks, and type references crossing between two path "
                    "components, in both directions, with confidence and source locations.",
     "inputSchema": {"type": "object", "properties": {
         "from_component": {"type": "string"}, "to_component": {"type": "string"}},
         "required": ["from_component", "to_component"]}},
    {"name": "indirect_targets",
     "description": "Resolve function-pointer, callback, ops-table, and runtime dispatch sites "
                    "inside a function. Keeps unresolved sites visible and reports confidence.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string"}}, "required": ["function"]}},
    {"name": "architecture_map",
     "description": "Deterministic file communities over the call + dependency graph, with "
                    "internal/boundary edge counts and call-graph hubs. Returns no generated labels.",
     "inputSchema": {"type": "object", "properties": {
         "component_depth": {"type": "integer", "default": 2},
         "max_communities": {"type": "integer", "default": 30}}}},
    {"name": "execution_story",
     "description": "Bounded forward call-and-branch trace from an entry point, including resolved "
                    "indirect dispatch. Returns graph structure, not generated narrative prose.",
     "inputSchema": {"type": "object", "properties": {
         "entry": {"type": "string"}, "max_depth": {"type": "integer", "default": 5},
         "max_steps": {"type": "integer", "default": 100}}, "required": ["entry"]}},
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
    {"name": "taint",
     "description": "Taint witnesses from the Atropos catalog: where untrusted input actually reaches "
                    "a dangerous sink through value flow. Folds the Atropos taint models (sources / "
                    "sinks / summaries) onto this graph's exact nodes and runs propagation, returning "
                    "each source->sink reach with the catalog model id, CWE, and file:line for both "
                    "ends. `atropos_connected` rows are the ones a catalog fact drove (e.g. request -> "
                    "urlopen SSRF); the rest are the engine's own generic-role reaches. Costs one "
                    "whole-graph value-flow build on first call per graph (cached after). A no-op with "
                    "a clear reason if the Atropos catalog is not checked out. Each witness carries "
                    "`source_id`/`sink_id`, the exact graph node ids of the bound endpoints. "
                    "`unwitnessed` lists bound sinks/sources that took part in no reach -- feed those "
                    "ids straight to `sources_of`/`flow`/`reaches` to trace why (on a C graph they mark "
                    "where value-flow gaps sever the chain); no name resolution needed since the "
                    "endpoint is often an external callee the name index can't seed.",
     "inputSchema": {"type": "object", "properties": {
         "limit": {"type": "integer", "default": 50},
         "atropos_only": {"type": "boolean",
                          "description": "only witnesses a catalog fact drove"}}}},
    {"name": "candidates",
     "description": "Enumerate and rank every observable obligation site selected by an Atropos "
                    "fact. This is a POINTER, not a safety check: candidates are never suppressed "
                    "because a size is constant, a guard seems nearby, or no input flow was "
                    "witnessed. The first constructor is memory.copy.capacity. Costs one "
                    "catalog bind on first call per graph (cached after). `frontiers` here reports "
                    "coverage as counts (e.g. unbound_sinks_count); call candidate_census for the "
                    "full roster of catalog sinks that never bound.",
     "inputSchema": {"type": "object", "properties": {
         "domain": {"type": "string"},
         # Wire name avoids the bare key `constructor`: it collides with
         # Object.prototype.constructor and breaks the client's Zod record check.
         "constructor_id": {"type": "string"},
         "language": {"type": "string", "enum": ["c", "python", "javascript", "typescript"]},
         "limit": {"type": "integer", "default": 40},
         "cursor": {"type": "string"},
         "detail": {"type": "string", "enum": ["brief", "compact", "full"], "default": "compact",
                    "description": "brief (one-line scan: id/rank/callee/at/size), "
                                   "compact (triage capsule, no inferences), "
                                   "full (whole capsule incl. inferences)"}}}},
    {"name": "candidate_detail",
     "description": "Return the complete neutral evidence capsule for one candidate id. It "
                    "contains observations and bounded inferences, but no safe/unsafe verdict.",
     "inputSchema": {"type": "object", "properties": {
         "candidate_id": {"type": "string"}}, "required": ["candidate_id"]}},
    {"name": "candidate_census",
     "description": "Report constructor metadata, exhaustive counts, and explicit analysis "
                    "frontiers. Use this to distinguish an empty result from missing coverage.",
     "inputSchema": {"type": "object", "properties": {
         "constructor_id": {"type": "string"}}}},
    {"name": "skeleton",
     "description": "Render a function's sink map as a pseudo-function: every catalogued sink "
                    "(all families -- memory, os, file, ...) shown in place, each annotated with "
                    "its size expression, destination-capacity status, and guard dominance "
                    "(fall-through | guarded-region | none-observed), plus the branch/loop "
                    "structure that scopes them, with everything else elided. A sink is not "
                    "adjudicable alone -- the guard that dominates it decides it -- so "
                    "co-locating each sink with its controlling branches and loops makes closure "
                    "a local read. Every obligation on a line is shown, highest-rank first; "
                    "operand provenance is a drill-down (candidate_detail / sources_of). Pass "
                    "`function` (a name or node id) for the whole enclosing function, or "
                    "`candidate_id` to focus its enclosing function.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string", "description": "function name or node id"},
         "candidate_id": {"type": "string", "description": "candidate id; renders its "
                          "enclosing function"}}}},
    {"name": "flow_pass",
     "description": "Run the interprocedural flow pass (the 3rd pass) over the whole graph and "
                    "return its per-function SUMMARY census -- the layer beneath the skeletons. "
                    "For each function: its taxonomy, whether it is a taint source, the ordered "
                    "sink-flow signatures (which value reaches which sink, guarded or not, and "
                    "the callee it flows through), and the pointer lifetime signatures "
                    "(alloc->use->free->escape). This is the composed, interprocedural summary "
                    "the shape matcher runs on -- one call materializes and caches the pass. Use "
                    "`function` to scope to one function; paginate with offset/limit.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string", "description": "scope the census to one function"}}}},
    {"name": "flow_skeleton",
     "description": "Interprocedural flow skeletons: compose per-function summaries into "
                    "linear, nesting-aware {control|sink|lifecycle} streams STITCHED across "
                    "call seams -- the cross-function flow a single-function `skeleton` cannot "
                    "show -- then match shape patterns over them. Two skeleton kinds: REACH "
                    "(a value's guard-nesting down the call chain to a sink; feeds the "
                    "guarded-vs-unguarded size differential) and TYPESTATE (a pointer's ordered "
                    "alloc/use/free/escape; feeds double-free / use-after-free / leak). Returns "
                    "shape-matcher LEADS (not verdicts -- adjudicate with sources_of/reaches). "
                    "No arg: every lead, source-rooted first. Pass `function` to scope to one "
                    "entry and see its rendered skeletons; `kind` to filter reach|typestate.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string", "description": "entry function name; scopes skeletons "
                      "and renders them"},
         "kind": {"type": "string", "enum": ["reach", "typestate"],
                  "description": "filter to one skeleton kind"}}}},
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
for _name in ("hubs", "callers", "callees", "flow_pass", "flow_skeleton"):
    _tool = next(t for t in TOOLS if t["name"] == _name)
    _tool["inputSchema"]["properties"].update(
        offset={"type": "integer", "default": 0},
        limit={"type": "integer", "default": 40})


def _atropos_envelope(summary, *, full):
    """The Atropos coverage block attached to a candidate response.

    `full=True` (census only) keeps every per-language `unbound` row so the
    coverage tool can show exactly which catalog sinks/sources never bound.
    `full=False` (list/detail moves) drops those row lists and keeps the status
    counts, so a page carries the shape of coverage without its full weight."""
    per_language = summary.get("per_language", {})
    if not full:
        per_language = {lang: {k: v for k, v in stats.items() if k != "unbound"}
                        for lang, stats in per_language.items()}
    return {
        "root": summary.get("atropos_root"),
        "languages": summary.get("languages", []),
        "bind": per_language,
        "role_nodes": summary.get("role_nodes", {}),
    }


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
    if name in DISABLED_TOOLS:
        return _emit(name, {"error": f"tool {name!r} is disabled: it requires a "
                                     "whole-graph guard scan (removed for now)"}, fmt)
    if _PROFILE == "comprehension" and name in SECURITY_TOOLS:
        return _emit(name, {"error": f"tool {name!r} is hidden under the "
                                     "'comprehension' profile (security tool)"}, fmt)
    c = ctx()
    cone = _fold_cone(c.store, name, args)
    store, gl = c.store, c.store.gl
    text = fmt != "json"  # text mode enriches callers/callees with dispatch slots

    if name == "unknowns":
        result = c.comprehension.unknowns(
            function=args.get("function"), limit=int(args.get("limit", 100)))
        return _emit(name, result, fmt, offset, limit)
    if name == "coverage_map":
        result = c.comprehension.coverage_map(
            component_depth=int(args.get("component_depth", 1)))
        return _emit(name, result, fmt, offset, limit)
    if name == "field_history":
        result = c.comprehension.field_history(args["field"], args.get("owner_type"))
        return _emit(name, result, fmt, offset, limit)
    if name == "sibling_compare":
        result = c.comprehension.sibling_compare(args["symbol"])
        return _emit(name, result, fmt, offset, limit)
    if name == "type_explain":
        result = c.comprehension.type_explain(args["type"])
        return _emit(name, result, fmt, offset, limit)
    if name == "component_boundary":
        result = c.comprehension.component_boundary(
            args["from_component"], args["to_component"])
        return _emit(name, result, fmt, offset, limit)
    if name == "indirect_targets":
        return _emit(name, c.comprehension.indirect_targets(args["function"]),
                     fmt, offset, limit)
    if name == "architecture_map":
        result = c.comprehension.architecture_map(
            component_depth=int(args.get("component_depth", 2)),
            max_communities=int(args.get("max_communities", 30)))
        return _emit(name, result, fmt, offset, limit)
    if name == "execution_story":
        result = c.comprehension.execution_story(
            args["entry"], max_depth=int(args.get("max_depth", 5)),
            max_steps=int(args.get("max_steps", 100)))
        return _emit(name, result, fmt, offset, limit)

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
        seeds = _seeds(store, args["name"])
        if not seeds:
            return _emit(name, {"error": f"no node named {args['name']!r}"}, fmt)
        direct_only = bool(args.get("direct_only"))
        move = si.callers if name == "callers" else si.callees
        # Every homonym, unioned — not the first one. `callers("funcA")` returning only
        # the callers of whichever `funcA` sorted first is the failure a vulnerability
        # hunter cannot see: the answer looks complete. Each row carries its own
        # node_id, and `of` names the seeds, so the union stays separable.
        moves, seen = [], set()
        for seed in seeds:
            for row in move(gl, seed, direct_only=direct_only, with_dispatch=text,
                            resolver=store.resolver):
                if row["node_id"] in seen:
                    continue
                seen.add(row["node_id"])
                moves.append(row)
        payload = {name: moves, "of": args["name"],
                   **_alts(store, args["name"])}
        if name == "callees" and not direct_only:
            # Invariant 2: an undecidable call is a node, not an omission.
            payload["unresolved"] = [row for seed in seeds
                                     for row in si.unresolved_callees(
                                         gl, seed, store.resolver)]
        return _emit(name, payload, fmt, offset, limit)
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
        return _emit(name, {**c.reach.flow(seed, limit=int(args.get("limit", 200))),
                            **_alts(store, args["seed"]), **cone}, fmt, offset, limit)
    if name == "reaches":
        src, sink = _seed(store, args["src"]), _seed(store, args["sink"])
        if not src or not sink:
            return _emit(name, {"error": "could not resolve src/sink"}, fmt)
        return _emit(name, {**c.reach.reaches(src, sink),
                            **_alts(store, args["src"]), **cone}, fmt, offset, limit)
    if name == "sources_of":
        sink = _seed(store, args["sink"])
        if not sink:
            return _emit(name, {"error": f"no node for {args['sink']!r}"}, fmt)
        return _emit(name, {**c.reach.sources_of(sink, limit=int(args.get("limit", 200))),
                            **_alts(store, args["sink"]), **cone}, fmt, offset, limit)
    if name == "points_to":
        value = _seed(store, args["value"])
        if not value:
            return _emit(name, {"error": f"no node for {args['value']!r}"}, fmt)
        heaps = list(store.index.targets(value, "POINTS_TO"))
        edges = store.index.outgoing_of_kind(value, "POINTS_TO")
        shape = store.path_shape([store.node(value)] + heaps, edges,
                                 manifest={"move": "points_to", "value": value})
        return _emit(name, {**shape, **_alts(store, args["value"]), **cone},
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
        shape = store.path_shape([store.node(value)] + alias_nodes, edges,
                                 manifest={"move": "aliases", "value": value})
        return _emit(name, {**shape, **_alts(store, args["value"]), **cone},
                     fmt, offset, limit)
    if name == "guards":
        fn = _seed(store, args["fn"])
        if not fn:
            return _emit(name, {"error": f"no function for {args['fn']!r}"}, fmt)
        return _emit(name, {"function": _ref(store, fn),
                            "guard_signal": c.guards.profile(fn),
                            **_alts(store, args["fn"])}, fmt)
    if name == "call_roles":
        fn = _seed(store, args["fn"])
        if not fn:
            return _emit(name, {"error": f"no function for {args['fn']!r}"}, fmt)
        recs = c.roles.roles_for(fn)
        return _emit(name, {"function": _ref(store, fn),
                            "calls": [{"callee": r["callee"], "role": r["role"],
                                       "fact_origin": r["fact_origin"],
                                       "at": f"{r['file']}:{r['line']}"} for r in recs],
                            **_alts(store, args["fn"])}, fmt)
    if name == "siblings":
        # `diff` takes the resolved *entry*, not an id, so this one keeps `store.resolve`
        # rather than going through `_seeds`.
        hits = si.peers(store.resolve(args["sym"]), args["sym"])
        if not hits:
            return _emit(name, {"error": f"no node named {args['sym']!r}"}, fmt)
        return _emit(name, {**c.siblings.diff(hits[0]),
                            **_alts(store, args["sym"])}, fmt, offset, limit)
    if name in ("candidates", "candidate_detail", "candidate_census"):
        bundle = c.candidate_bundle
        summary = bundle["atropos"]
        if not summary.get("applied"):
            return _emit(name, {
                "move": name, "applied": False, "reason": summary.get("reason"),
                "hint": "no Atropos catalog found; set ATROPOS_ROOT or place a checkout "
                        "at ../atropos, then reload",
            }, fmt, offset, limit)
        registry = bundle["registry"]
        if name == "candidates":
            result = registry.candidates(
                domain=args.get("domain"), constructor=args.get("constructor_id"),
                language=args.get("language"), limit=args.get("limit", 40),
                cursor=args.get("cursor"), detail=args.get("detail", "compact"))
        elif name == "candidate_detail":
            result = registry.detail(args["candidate_id"])
        else:
            result = registry.census(args.get("constructor_id"))
        result["applied"] = True
        # The per-language bind report carries the full `unbound` row lists
        # (hundreds of rows, ~90KB on a large catalog). That is coverage data:
        # it belongs on `candidate_census`, the move whose job is to distinguish
        # an empty result from missing coverage. Every other move gets the
        # counts only, so a list page stays bounded. Nothing is dropped -- the
        # rows are one census call away.
        result["atropos"] = _atropos_envelope(summary, full=(name == "candidate_census"))
        return _emit(name, result, fmt, offset, limit)
    if name == "skeleton":
        bundle = c.candidate_bundle
        summary = bundle["atropos"]
        if not summary.get("applied"):
            return _emit(name, {
                "move": "skeleton", "applied": False, "reason": summary.get("reason"),
                "hint": "no Atropos catalog found; set ATROPOS_ROOT or place a checkout "
                        "at ../atropos, then reload",
            }, fmt, offset, limit)
        registry = bundle["registry"]
        store, gl = c.store, c.store.gl
        if args.get("candidate_id"):
            result = skeleton_mod.skeleton_for_candidate(gl, registry, args["candidate_id"])
        elif args.get("function"):
            fn = args["function"]
            fid = fn if store.node(fn) else _seed(store, fn)
            if not fid:
                return _emit(name, {"move": "skeleton", "error": f"no node named {fn!r}"}, fmt)
            result = skeleton_mod.skeleton_for_function(gl, registry, fid)
        else:
            return _emit(name, {"move": "skeleton",
                                "error": "pass either `function` or `candidate_id`"}, fmt)
        result["move"] = "skeleton"
        return _emit(name, result, fmt, offset, limit)
    if name == "flow_pass":
        bundle = c.flow_bundle
        summaries, F = bundle["summaries"], bundle["F"]
        fn = args.get("function")
        names = [fn] if fn else sorted(summaries)
        if fn and fn not in summaries:
            return _emit(name, {"move": "flow_pass",
                                "error": f"no function named {fn!r} in the pass"}, fmt)
        rows = []
        for nm in names:
            s = summaries[nm]
            flows = []
            for f in s["sink_flows"]:
                if not f["guarded"]:
                    g = "UNGUARDED"
                elif f.get("site_guarded"):
                    g = "G[" + ",".join(f["guards"]) + "]"
                else:
                    g = "G~[" + ",".join(f["guards"]) + "]"
                via = "" if f["via"] == "direct" else f"~{f['via']}"
                val = f["value"] or f["provenance"] or "expr"
                flows.append(f"{val}->{f['sink']}({g}){via}")
            life = []
            for v, evs in s.get("typestate", {}).items():
                life.append(f"{v}:" + "->".join(e["kind"] for e in evs))
            for v, evs in s.get("param_typestate", {}).items():
                life.append(f"param {v}:" + "->".join(e["kind"] for e in evs))
            rows.append({"name": nm, "taxonomy": s["taxonomy"],
                         "is_source": F.get(nm, {}).get("is_source", False),
                         "flows": flows, "lifetime": life,
                         "frees": sorted(s.get("frees_params", {})),
                         "returns": s.get("returns", "value")})
        # Most-informative first: sources, then functions carrying flows, then the rest.
        rows.sort(key=lambda r: (not r["is_source"], not r["flows"], r["name"]))
        result = {
            "move": "flow_pass",
            "counts": {"functions": len(summaries),
                       "with_flows": sum(1 for n in summaries if summaries[n]["sink_flows"]),
                       "sources": sum(1 for n in summaries
                                      if F.get(n, {}).get("is_source", False)),
                       "skeletons": len(bundle["skeletons"]), "leads": len(bundle["leads"])},
            "functions": rows,
            "lifetime": bundle.get("lifetime", {}),
        }
        return _emit(name, result, fmt, offset, limit)
    if name == "flow_skeleton":
        bundle = c.flow_bundle
        all_skels, leads = bundle["skeletons"], bundle["leads"]
        kind, fn = args.get("kind"), args.get("function")
        skels = all_skels
        _reach_pats = ("reachability", "relational", "presence")
        if kind in ("reach", "typestate"):
            skels = [s for s in skels if s["kind"] == kind]
            want_reach = kind == "reach"
            leads = [l for l in leads
                     if (l.get("pattern") in _reach_pats) == want_reach]
        if fn:
            skels = [s for s in skels if s["entry"] == fn]
            leads = [l for l in leads if l.get("entry") == fn]
            if not skels and not leads:
                return _emit(name, {"move": "flow_skeleton",
                                    "error": f"no flow skeletons for entry {fn!r}"}, fmt)
        result = {
            "move": "flow_skeleton",
            "counts": {"skeletons": len(all_skels),
                       "reach": sum(1 for s in all_skels if s["kind"] == "reach"),
                       "typestate": sum(1 for s in all_skels if s["kind"] == "typestate"),
                       "leads": len(bundle["leads"])},
            "leads": leads,
            "lifetime": bundle.get("lifetime", {}),
        }
        # Render skeleton text only when scoped -- the whole-graph stream would be huge.
        if fn or kind:
            from lachesis.flow import render_text as render_flow_skeleton
            result["skeletons"] = [
                {"entry": s["entry"], "kind": s["kind"], "sink": s.get("sink"),
                 "var": s.get("var"), "is_source": s["is_source"],
                 "complete": s.get("complete", True), "text": render_flow_skeleton(s)}
                for s in sorted(skels, key=lambda x: (not x["is_source"], x["entry"]))]
        return _emit(name, result, fmt, offset, limit)
    if name == "taint":
        return _emit(name, _taint(c.store, args), fmt, offset, limit)
    raise ValueError(f"unknown tool: {name}")


def _taint(store, args):
    """Fold the Atropos catalog over the whole-graph value-flow tier and list reaches.

    The disk dataflow tier stays catalog-free (it is keyed by the core content hash
    alone, so it cannot also encode a model set); the model stamping and a fresh
    propagation happen here, in RAM, on top of it. That keeps the cache unambiguous
    and confines every catalog effect to this one on-demand tool.
    """
    from lachesis.integrations.atropos.enrich import atropos_enrich
    from lachesis.core.overlays.taint import TaintPropagation
    from lachesis.nav.kuzu_index import materialize_graph

    store.ensure_dataflow_tier()  # whole-graph value flow, built once then cached to disk
    graph = materialize_graph(store.index)
    stamped, summary = atropos_enrich(graph)
    if not summary.get("applied"):
        return {"move": "taint", "applied": False, "reason": summary.get("reason"),
                "hint": "no Atropos catalog found; set ATROPOS_ROOT or place a checkout "
                        "at ../atropos, then reload"}

    by_id = {n["id"]: n for n in stamped["nodes"]}
    marked = {}  # value_id -> the atropos role node that stamped it
    for node in stamped["nodes"]:
        props = node.get("properties", {})
        if props.get("fact_origin") == "atropos-model" and "value_id" in props:
            marked[props["value_id"]] = node

    def _loc(value_id):
        props = by_id.get(value_id, {}).get("properties", {})
        f = props.get("absolute_file") or props.get("file")
        line = props.get("start_line")
        return f"{f}:{line}" if f else None

    def _label(value_id):
        node = by_id.get(value_id, {})
        return node.get("label") or (node.get("properties", {}) or {}).get("label") or value_id

    rows = []
    witnessed = set()  # value_ids that took part in at least one reach
    for witness in TaintPropagation().enrich(stamped).nodes:
        if witness.get("kind") != "taint-reach":
            continue
        props = witness.get("properties", {})
        sv, kv = props.get("source_value_id"), props.get("sink_value_id")
        witnessed.add(sv)
        witnessed.add(kv)
        src_role, sink_role = marked.get(sv), marked.get(kv)
        model_props = (sink_role or src_role or {}).get("properties", {})
        rows.append({
            "source": _label(sv), "source_at": _loc(sv), "source_id": sv,
            "sink": _label(kv), "sink_at": _loc(kv), "sink_id": kv,
            "source_model": (src_role or {}).get("properties", {}).get("model_id"),
            "sink_model": (sink_role or {}).get("properties", {}).get("model_id"),
            "cwe": model_props.get("cwe", []),
            "atropos_connected": bool(src_role or sink_role),
        })
    # A catalog-driven reach is the point of the tool, so those sort first.
    rows.sort(key=lambda r: not r["atropos_connected"])
    total = len(rows)
    connected = sum(1 for r in rows if r["atropos_connected"])
    if args.get("atropos_only"):
        rows = [r for r in rows if r["atropos_connected"]]

    # Bound endpoints that never took part in a reach. These are the addressable
    # seeds for the dataflow tools -- `sources_of <sink_id>` / `flow <source_id>`
    # over MCP, no name resolution needed (the endpoint is an external callee's
    # arg the name index can't reach). On a C graph this listing is the frontier
    # where the value-flow gaps sever the source->sink chain.
    lim = int(args.get("limit", 50))
    unwit = {"sources": [], "sinks": []}
    for value_id, role_node in marked.items():
        if value_id in witnessed:
            continue
        bucket = role_node.get("kind")
        if bucket not in ("source", "sink"):
            continue
        rp = role_node.get("properties", {})
        unwit[bucket + "s"].append({
            "id": value_id, "label": _label(value_id), "at": _loc(value_id),
            "model": rp.get("model_id"), "cwe": rp.get("cwe", []),
        })
    return {
        "move": "taint", "applied": True,
        "atropos_root": summary["atropos_root"],
        "languages": summary["languages"],
        "bind": summary["per_language"],
        "role_nodes": summary["role_nodes"],
        "witness_count": total,
        "atropos_connected": connected,
        "witnesses": rows[:lim],
        "unwitnessed": {
            "sources": unwit["sources"][:lim],
            "sinks": unwit["sinks"][:lim],
            "source_total": len(unwit["sources"]),
            "sink_total": len(unwit["sinks"]),
        },
    }


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
    # A graph only exists after a build somebody had to know to run, which made this
    # server unusable as the first thing anyone tries. So a directory is accepted in
    # the graph's place, and no argument at all means the working directory: the
    # index is built or reused, and the client's config needs no paths in it.
    if not _GRAPH_PATH or os.path.isdir(_GRAPH_PATH) and not _GRAPH_PATH.endswith(".kuzu"):
        from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                          ensure_graph)
        from lachesis.cli.progress import Progress
        source = _GRAPH_PATH or os.getcwd()
        try:
            # Progress writes to stderr only; stdout is the JSON-RPC channel.
            graph, _ = ensure_graph(source, progress=Progress(enabled=True))
        except EnvironmentProblem as error:
            for check in error.checks:
                print(f"lachesis-mcp: {check.name}: {check.detail}", file=sys.stderr)
            return 3
        except NoSourceFound as error:
            print(f"lachesis-mcp: {error}", file=sys.stderr)
            return 2
        _GRAPH_PATH = str(graph)
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
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}}})
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
