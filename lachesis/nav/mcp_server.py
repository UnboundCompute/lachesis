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
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lachesis.nav.graph_store import GraphStore
from lachesis.nav.reachability import Reachability
from lachesis.nav.guards import GuardProfiles
from lachesis.nav.call_roles import CallRoles
from lachesis.nav.siblings import SiblingDiff
from lachesis.nav import symbol_index as si
from lachesis.nav.hubs import Hubs
from lachesis.nav.communities import Communities
from lachesis.nav.folder_graph import build_folder_graph
from lachesis.nav.file_graph import build_file_graph, _find_file_node
from lachesis.nav import render as render_mod
from lachesis.nav import skeleton as skeleton_mod
from lachesis.nav.comprehension import Comprehension
from lachesis.nav.concept import ConceptSearch, DEFAULT_MODEL
from lachesis.session import Analysis, LeadSet

_GRAPH_PATH = None
_OVERLAY_PATH = None
_CTX = None  # lazily-built bundle of store + engines, loaded once
_PROFILE = "all"  # tool-surface profile: "all" (default) | "comprehension"
# Process-wide default output format for tools/call when a call omits `format`.
# "text" = compact LLM-facing rendering (Spec 1); "json" = the full result dict.
# Set from LACHESIS_FORMAT in main(); defaults to text.
_DEFAULT_FORMAT = "text"

# Hunting-only tools are excluded from the opt-in comprehension surface. The default
# remains additive/backward-compatible; a caller has to request the narrower profile.
SECURITY_TOOLS = ("guards", "call_roles", "siblings", "guards_top")
HUNTING_TOOLS = SECURITY_TOOLS + (
    "candidates", "candidate_detail", "candidate_census", "explain", "skeleton",
    "enrich", "flow_pass", "leads", "flow_skeleton", "taint", "scan", "guard_dominance",
    "counterexample", "range_analysis", "object_lifecycle", "error_path_summary",
)

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
    "load_graph", "build_graph",
    "hubs", "communities", "search", "callers", "callees", "read_body", "open_file", "open_folder",
    "unknowns", "coverage_map", "field_history", "sibling_compare",
    "type_explain", "component_boundary", "indirect_targets",
    "architecture_map", "execution_story",
    "change_context", "tests_for", "spec_links",
    "concept_search", "context_pack",
    "scan", "wrapper_model", "guard_dominance", "counterexample", "invariant_trace",
    "representation_roundtrip", "cross_boundary_paths", "range_analysis",
    "object_lifecycle", "error_path_summary",
    "flow", "reaches", "sources_of", "points_to", "aliases",
    "candidates", "candidate_detail", "candidate_census", "explain", "skeleton",
    "enrich", "flow_pass", "leads", "flow_skeleton", "taint",
    "guards", "call_roles", "siblings", "guards_top",
)


def _visible_tools():
    """TOOLS filtered by the active profile and sorted into canonical order."""
    hidden = set(DISABLED_TOOLS)
    if _PROFILE == "comprehension":
        hidden |= set(HUNTING_TOOLS)
    tools = [t for t in TOOLS if t["name"] not in hidden]
    rank = {n: i for i, n in enumerate(TOOL_ORDER)}
    return sorted(tools, key=lambda t: rank.get(t["name"], len(rank)))


def log(*a):
    print("[lachesis mcp]", *a, file=sys.stderr, flush=True)


def _expand(path):
    """Expand a leading ``~`` so a user-typed home path resolves instead of 404ing.

    A path that exists on disk but is spelled ``~/.lachesis/graphs/x.kuzu`` used to come
    back "path not found" because nothing called ``expanduser``. ``None``/empty passes
    through untouched (an optional overlay or graph that was simply not supplied)."""
    return os.path.expanduser(path) if path else path


# One graph/ctx per process, mutated in place by load_graph. The stdin loop already
# reads and dispatches requests serially, so there is no live race today; this lock makes
# that serial contract explicit and keeps the shared _CTX swap atomic under any future
# concurrent transport, so an overlapping call can never observe a half-attached store.
_DISPATCH_LOCK = threading.Lock()


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


class _Ctx(Analysis):
    """The loaded store plus the analysis objects, all built on first use.

    Subclasses the public :class:`lachesis.session.Analysis`: the store-load, the memo
    (``_analysis``/``_sync_tier``), and the two heavy builds (``_flow_bundle``/
    ``_bind_bundle``) all live on the base, so the MCP server and the library share one
    implementation. This class adds only the navigation properties the tool surface reads.

    Lazy for two reasons. A store built without ``--enrich`` grows its dataflow tier on
    demand, and that rebinds ``store.index``; every analysis object here caches the
    index at construction, so anything built before the enrich would silently keep
    answering off the core tier. And orientation tools (`hubs`, `search`, `guards_top`)
    never touch dataflow, so they should never pay for it."""

    def __init__(self, graph_path, overlay_path):
        store = GraphStore.load(graph_path, overlay_path=overlay_path)
        super().__init__(store)
        log(f"loaded {len(self.store.gl.nodes)} nodes; "
            f"overlay: {self.store.overlay.summary()['derived_edges']} derived edges; "
            f"dataflow tier: "
            f"{'present' if self.store.dataflow_ready else 'on demand, per cone'}")

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
    def communities(self):
        return self._analysis("communities", lambda: Communities(self.store.gl))

    @property
    def comprehension(self):
        return self._analysis("comprehension", lambda: Comprehension(self.store))

    def concepts(self, model=DEFAULT_MODEL):
        return self._analysis(f"concept:{model}", lambda: ConceptSearch(self.store, model))

    @property
    def candidate_bundle(self):
        """The catalog-stamped graph and its cached obligation registry.

        The build lives on :meth:`Analysis._bind_bundle` so the library and the MCP surface
        share one implementation. Candidate enumeration binds catalog facts against the core
        symbol index and publishes the cached semantic skeleton to the temporal constructors,
        which emit observations, never verdicts; the graph matcher remains the authority for
        proving a lifecycle relation.

        Bounded by the same default budget as every other temporal path
        (:meth:`Analysis._resolve_deadline`: ``LACHESIS_HARD_STOP`` or 180s) so the temporal
        bind cannot hang the request loop; a bind that hits the budget degrades to the
        structural families (``temporal_evaluated=False``) and is not cached, so a later call
        with a larger budget completes it. ``LACHESIS_HARD_STOP=0`` runs it unbounded.
        """
        return self._bind_bundle(deadline=self._resolve_deadline(None, None))

    @property
    def flow_bundle(self):
        """The interprocedural flow pass over the whole graph, computed once and cached.

        Delegates to the single native Rust flow engine shared with the public library.
        Engine selection is intentionally not configurable on the MCP surface.

        It is *not* neutral on the clock: the pass is bounded by the same default budget the
        library uses (:meth:`Analysis._resolve_deadline`: ``LACHESIS_HARD_STOP`` or 180s), so a
        large graph degrades to partial leads instead of hanging the request loop. A timed-out
        result is never memoized (see ``_flow_bundle``), so a later call with a larger budget
        recomputes cleanly. ``LACHESIS_HARD_STOP=0`` runs it unbounded.
        """
        return self._flow_bundle(
                                 deadline=self._resolve_deadline(None, None))

    @property
    def scan_bundle(self):
        """The cached guard-differential scan used by the public CLI.

        Scanning is deliberately shared with ``lachesis scan`` rather than being a
        second MCP-only implementation.  The dataflow tier is materialized once on
        first use; subsequent calls only page/filter the cached constructor result.
        """
        def build():
            from lachesis.planner.constructors import GuardDifferential

            self.store.ensure_dataflow_tier()
            return GuardDifferential(self.store).run()

        return self._analysis("guard-differential-scan", build)

    def scan_bundle_for(self, limit_entrypoints: int = 0):
        """Return a scan result, reusing the full result or a bounded variant."""
        if not limit_entrypoints:
            return self.scan_bundle

        def build():
            from lachesis.planner.constructors import GuardDifferential

            self.store.ensure_dataflow_tier()
            return GuardDifferential(self.store).run(
                limit_entrypoints=max(0, int(limit_entrypoints)),
            )

        return self._analysis(f"guard-differential-scan:{int(limit_entrypoints)}", build)


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


def _parse_at(value):
    """Parse a `leads` position arg: ``file`` | ``file:line`` | ``file:lo-hi``.

    Returns ``(file, lines)`` where ``lines`` is an inclusive ``(lo, hi)`` tuple or ``None``.
    Split from the right so a path that itself contains no line suffix is returned whole; a
    trailing ``:N``/``:LO-HI`` is only consumed when it actually parses as numbers, so a bare
    file with a colon in the name is not mistaken for a line spec.
    """
    head, sep, tail = value.rpartition(":")
    if sep and head:
        if "-" in tail:
            lo, _, hi = tail.partition("-")
            if lo.isdigit() and hi.isdigit():
                return head, (int(lo), int(hi))
        elif tail.isdigit():
            return head, (int(tail), int(tail))
    return value, None


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
        "deferred_edges_omitted": sum(f.get("deferred_edges_omitted", 0)
                                      for f in folded),
        "truncated": any(f["truncated"] for f in folded),
        "complete": (not any(f["truncated"] for f in folded)
                     and not any(f.get("deferred_edges_omitted", 0) for f in folded)),
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


# Shared bounding args for the candidate tools. The temporal families (double-free,
# use-after-free, ...) read the Pass 3 semantic skeleton, whose flow pass materializes the
# whole dataflow tier -- the one candidate cost that can run long on a large graph. These give
# a client the escape hatch: `temporal:false` answers the structural families immediately with
# no tier at all, and `hard_stop` bounds the temporal path so a slow graph degrades to
# structural (with `temporal_evaluated:false`) instead of hanging the server.
_TEMPORAL_ARG = {"type": "boolean", "default": True,
                 "description": "evaluate the temporal families (double-free/UAF/...). Default "
                                "true. Set false for the guaranteed-bounded fast path: "
                                "structural families only, no dataflow tier -- use it when a "
                                "large graph makes the full bind run long. The result's "
                                "`temporal_evaluated` flag reports whether they were evaluated."}
_HARD_STOP_ARG = {"type": "number",
                  "description": "wall-clock budget (seconds) for the temporal families; on "
                                 "expiry the result degrades to the structural families with "
                                 "`temporal_evaluated:false` rather than hang. 0 = unbounded."}

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
    {"name": "build_graph",
     "description": "Build a Lachesis graph from a source directory and attach it — the zero-config "
                    "way to start on a repo that has no graph yet, no separate lachesis build step "
                    "needed. Content-addressed: an unchanged tree returns instantly from cache; pass "
                    "refresh=true to force a rebuild. On success the new graph is loaded, so the next "
                    "tool call reasons over it. Toolchain: Python needs nothing extra; TypeScript/"
                    "JavaScript need `node` on PATH and C needs `clang` — a missing one comes back as "
                    "an actionable 'missing toolchain prerequisite' error, not a crash. Builds run "
                    "in-process and can take minutes on a large tree (capped by timeout_seconds, "
                    "default 300); a build longer than the MCP client's own request timeout may need a "
                    "smaller subtree or an out-of-band `lachesis build`.",
     "inputSchema": {"type": "object", "properties": {
         "source": {"type": "string", "description": "path to the source directory to analyse"},
         "refresh": {"type": "boolean", "default": False,
                     "description": "force a rebuild even if the cached graph is current"},
         "timeout_seconds": {"type": "integer", "default": 300,
                             "description": "per-build compile timeout; raise for large trees"}},
         "required": ["source"]}},
    {"name": "unknowns",
     "description": "Read-only. List the graph's explicit comprehension frontiers: unresolved calls, "
                    "dynamic/reflective runtime behavior, and parser/compiler diagnostics. It "
                    "separates proven-absent from couldn't-cross, so you never read a missing fact as "
                    "'none'. Call it to gauge how much of an answer is trustworthy; scope to one "
                    "`function` or survey the whole graph.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string",
                      "description": "optional function name or node id to scope frontiers to"},
         "limit": {"type": "integer", "default": 100, "description": "maximum rows returned"},
         "offset": {"type": "integer", "default": 0, "description": "row offset for paging"}}}},
    {"name": "coverage_map",
     "description": "Read-only. Report deterministic graph coverage by component: how many files and "
                    "callable bodies are indexed, plus diagnostics and unmodeled frontiers. It "
                    "measures what the graph contains, not per-client session activity — use it to "
                    "decide whether an empty result means 'clean' or 'not analyzed'. All params "
                    "optional.",
     "inputSchema": {"type": "object", "properties": {
         "component_depth": {"type": "integer", "default": 1,
                             "description": "path-prefix depth used to group files into components"},
         "limit": {"type": "integer", "default": 100,
                   "description": "maximum component rows returned"},
         "offset": {"type": "integer", "default": 0, "description": "row offset for paging"}}}},
    {"name": "field_history",
     "description": "For a field/property, list graph-evidenced initialization, modification, "
                    "reads, checks, and value-flow events with owning functions.",
     "inputSchema": {"type": "object", "properties": {
         "field": {"type": "string"},
         "owner_type": {"type": "string", "description": "optional type name/id disambiguator"},
         "limit": {"type": "integer", "default": 100},
         "offset": {"type": "integer", "default": 0}},
         "required": ["field"]}},
    {"name": "sibling_compare",
     "description": "Compare structurally similar callables by callees and control structure. "
                    "Returns differences as facts only; it does not rank anomalies or issue verdicts.",
     "inputSchema": {"type": "object", "properties": {
         "symbol": {"type": "string"}, "limit": {"type": "integer", "default": 100},
         "offset": {"type": "integer", "default": 0},
         "call_offset": {"type": "integer", "default": 0}},
         "required": ["symbol"]}},
    {"name": "type_explain",
     "description": "Read-only. Explain a type from graph facts: its fields plus the methods that "
                    "construct, mutate, consume, or destroy it, each role graph-derived. Use it to "
                    "learn a struct/class's shape and how it is handled before reading call sites. "
                    "Paginate fields with offset and methods with member_offset.",
     "inputSchema": {"type": "object", "properties": {
         "type": {"type": "string", "description": "type name or graph node id"},
         "limit": {"type": "integer", "default": 100, "description": "maximum rows returned"},
         "offset": {"type": "integer", "default": 0, "description": "field offset for paging"},
         "member_offset": {"type": "integer", "default": 0,
                           "description": "method/member offset for paging"}},
         "required": ["type"]}},
    {"name": "component_boundary",
     "description": "Read-only. Show every call, callback, and type reference crossing between two "
                    "path components, in both directions, with confidence and file:line. Use it to "
                    "audit the contract between two modules/dirs; `cross_boundary_paths` adds rarity "
                    "ranking over the same crossings. Components are path prefixes (e.g. src/net vs "
                    "src/crypto).",
     "inputSchema": {"type": "object", "properties": {
         "from_component": {"type": "string",
                            "description": "source component: a path prefix (e.g. src/net)"},
         "to_component": {"type": "string",
                          "description": "destination component: a path prefix (e.g. src/crypto)"},
         "limit": {"type": "integer", "default": 100, "description": "maximum crossing rows returned"},
         "offset": {"type": "integer", "default": 0, "description": "row offset for paging"}},
         "required": ["from_component", "to_component"]}},
    {"name": "indirect_targets",
     "description": "Resolve function-pointer, callback, ops-table, and runtime dispatch sites "
                    "inside a function. Keeps unresolved sites visible and reports confidence.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string"}, "limit": {"type": "integer", "default": 100},
         "offset": {"type": "integer", "default": 0},
         "target_offset": {"type": "integer", "default": 0}},
         "required": ["function"]}},
    {"name": "architecture_map",
     "description": "Read-only. Map the codebase's architecture: deterministic file communities over "
                    "the call + dependency graph, each with internal/boundary edge counts and its "
                    "call-graph hubs (labels are graph-derived member names, never generated prose). "
                    "A directory-independent 'what are the big pieces' view — use `communities` for "
                    "function-level subsystems and `hubs` for the central functions. All params "
                    "optional; paginate communities with offset and files with file_offset.",
     "inputSchema": {"type": "object", "properties": {
         "component_depth": {"type": "integer", "default": 2,
                             "description": "path-prefix depth used to group files into components"},
         "max_communities": {"type": "integer", "default": 30,
                             "description": "maximum communities returned"},
         "max_files_per_community": {"type": "integer", "default": 50,
                                     "description": "maximum files listed per community"},
         "offset": {"type": "integer", "default": 0, "description": "community offset for paging"},
         "file_offset": {"type": "integer", "default": 0,
                         "description": "file offset within each community for paging"}}}},
    {"name": "execution_story",
     "description": "Read-only. Bounded forward call-and-branch trace from an entry point, following "
                    "resolved indirect dispatch — the ordered structure of what runs, not generated "
                    "narrative prose. Use it to see the control skeleton reachable from an entry; "
                    "bound cost with max_depth/max_steps and page the branches/frontier. For pure "
                    "centrality use `hubs` instead.",
     "inputSchema": {"type": "object", "properties": {
         "entry": {"type": "string", "description": "entry-point function name or node id"},
         "max_depth": {"type": "integer", "default": 5, "description": "maximum call depth to trace"},
         "max_steps": {"type": "integer", "default": 100,
                       "description": "maximum total steps before truncating"},
         "offset": {"type": "integer", "default": 0, "description": "step offset for paging"},
         "branch_limit": {"type": "integer", "default": 20,
                          "description": "maximum branches recorded per node"},
         "branch_offset": {"type": "integer", "default": 0, "description": "branch offset for paging"},
         "frontier_offset": {"type": "integer", "default": 0,
                             "description": "offset into the unresolved-frontier list for paging"}},
         "required": ["entry"]}},
    {"name": "change_context",
     "description": "Read-only. Join a symbol to its Git history: the exact commits that touched it "
                    "with author, date, and subject. Returns history facts only — no generated 'why' "
                    "narrative. Use it to date a change or find who last touched a function; newest "
                    "first, paged with limit/offset.",
     "inputSchema": {"type": "object", "properties": {
         "symbol": {"type": "string", "description": "symbol name or graph node id"},
         "limit": {"type": "integer", "default": 12, "description": "maximum commits returned"},
         "offset": {"type": "integer", "default": 0, "description": "commit offset for paging"}},
         "required": ["symbol"]}},
    {"name": "tests_for",
     "description": "Find exact references to a symbol in test/spec files, including nearby "
                    "assertion evidence. Reads the recorded source tree because tests are normally "
                    "excluded from the production graph.",
     "inputSchema": {"type": "object", "properties": {
         "symbol": {"type": "string"}, "limit": {"type": "integer", "default": 50},
         "offset": {"type": "integer", "default": 0}},
         "required": ["symbol"]}},
    {"name": "spec_links",
     "description": "Read-only. Link a symbol to its documentation and source comments, preserving "
                    "any standards URLs (RFCs, CVEs) and exact file:line evidence. Use it to recover "
                    "the spec/standard a function implements; returns comment/doc references paged "
                    "with limit/offset. Reads recorded source, so it works even where comments are "
                    "outside the production graph.",
     "inputSchema": {"type": "object", "properties": {
         "symbol": {"type": "string", "description": "symbol name or graph node id"},
         "limit": {"type": "integer", "default": 50, "description": "maximum reference rows returned"},
         "offset": {"type": "integer", "default": 0, "description": "row offset for paging"}},
         "required": ["symbol"]}},
    {"name": "context_pack",
     "description": "Return a minimal coherent factual set for a code question: relevant symbols, "
                    "call relationships, conditions, tests, specs, and explicit unknowns. Uses "
                    "identifier/graph relevance until concept_search embeddings are configured.",
     "inputSchema": {"type": "object", "properties": {
         "question": {"type": "string"},
         "max_symbols": {"type": "integer", "default": 6},
         "max_neighbors": {"type": "integer", "default": 30},
         "symbol_offset": {"type": "integer", "default": 0},
         "relationship_offset": {"type": "integer", "default": 0},
         "condition_offset": {"type": "integer", "default": 0},
         "test_offset": {"type": "integer", "default": 0},
         "spec_offset": {"type": "integer", "default": 0},
         "unknown_offset": {"type": "integer", "default": 0}},
         "required": ["question"]}},
    {"name": "scan",
     "description": "Return ranked leads from the whole taxonomy by default (lens=all): "
                    "questions to investigate, never verdicts. Use lens=guard-diff for the "
                    "entrypoint-to-effect guard view or lens=flow for native object-lifetime "
                    "leads. Results are bounded and paged; the response includes coverage and "
                    "whether the requested temporal work completed. The single native engine "
                    "is selected internally.",
     "inputSchema": {"type": "object", "properties": {
         "lens": {"type": "string", "enum": ["all", "guard-diff", "flow"],
                  "default": "all", "description": "lead view; all is the broad default"},
         "entrypoints": {"type": "integer", "default": 0,
                         "description": "scan only the first N entrypoints (0 = all)"},
         "min_rank": {"type": "number", "default": 0.0},
         "limit": {"type": "integer", "default": 20},
         "hard_stop": {"type": "number", "default": 180,
                       "description": "temporal budget in seconds; 0 = unbounded"},
         "include_suppressions": {"type": "boolean", "default": False}},
         "required": []}},
    {"name": "wrapper_model",
     "description": "Infer wrapper semantics from graph evidence: allocator, deallocator, "
                    "I/O, validator, and forwarding call roles. This is evidence with "
                    "confidence, not a registry mutation.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string"}, "limit": {"type": "integer", "default": 50}},
         "required": ["function"]}},
    {"name": "guard_dominance",
     "description": "Check whether recognized guards on an entry-to-effect call path "
                    "dominate the effect. Returns proven, skippable, or undecided evidence "
                    "and never emits a safety verdict.",
     "inputSchema": {"type": "object", "properties": {
         "entry": {"type": "string"}, "effect": {"type": "string"},
         "depth": {"type": "integer", "default": 6}},
         "required": ["entry", "effect"]}},
    {"name": "counterexample",
     "description": "Find a bounded call path from src to sink that avoids a named "
                    "validator/guard. This is the inverse reachability move; absence of a "
                    "path is not proof when the search is truncated.",
     "inputSchema": {"type": "object", "properties": {
         "src": {"type": "string"}, "sink": {"type": "string"},
         "validator": {"type": "string"}, "depth": {"type": "integer", "default": 6},
         "limit": {"type": "integer", "default": 20}},
         "required": ["src", "sink", "validator"]}},
    {"name": "invariant_trace",
     "description": "Read-only. Trace the producers, mutators, checkers, and consumers of a value or "
                    "field over a bounded local flow cone — who sets it, who guards it, who reads it. "
                    "Use it to reconstruct an invariant around one value; returns role-tagged nodes "
                    "with file:line, bounded by `depth`. Local, not interprocedural — use `flow` / "
                    "`sources_of` to cross call seams.",
     "inputSchema": {"type": "object", "properties": {
         "value": {"type": "string", "description": "value or field name / graph node id to trace"},
         "limit": {"type": "integer", "default": 100, "description": "maximum event rows returned"},
         "depth": {"type": "integer", "default": 4,
                   "description": "how many flow hops out from the value to walk"}},
         "required": ["value"]}},
    {"name": "representation_roundtrip",
     "description": "Read-only. Compare two functions/paths side by side for graph-visible calls, "
                    "control structure, conversions, and side-effect differences — e.g. an "
                    "encode/decode or serialize/parse pair. Returns the differences as facts only, "
                    "inferring no semantic verdict. Use `sibling_compare` for auto-discovered "
                    "structural peers, this for a deliberate two-sided pairing.",
     "inputSchema": {"type": "object", "properties": {
         "left": {"type": "string", "description": "first function/path name or node id"},
         "right": {"type": "string", "description": "second function/path name or node id"}},
         "required": ["left", "right"]}},
    {"name": "cross_boundary_paths",
     "description": "List crossings between two components with boundary tags and rarity "
                    "ranking, preserving direction and confidence.",
     "inputSchema": {"type": "object", "properties": {
         "from_component": {"type": "string"}, "to_component": {"type": "string"},
         "limit": {"type": "integer", "default": 100},
         "offset": {"type": "integer", "default": 0}},
         "required": ["from_component", "to_component"]}},
    {"name": "range_analysis",
     "description": "Read-only. Return the lightweight numeric evidence graph guards expose for a "
                    "value (comparisons, bounds checks) — not a full interval solve: real "
                    "value-range analysis stays unavailable until the numeric model ships, and the "
                    "response names that frontier honestly. Scope with `value` and/or `function`; "
                    "omit both for the capability report.",
     "inputSchema": {"type": "object", "properties": {
         "value": {"type": "string", "description": "value name or graph node id to bound"},
         "function": {"type": "string", "description": "function name/id to scope the search to"},
         "limit": {"type": "integer", "default": 50,
                   "description": "maximum evidence rows returned"}}}},
    {"name": "object_lifecycle",
     "description": "Read-only. Report what lifecycle evidence the graph holds for a value or "
                    "function — Pass 3 alloc/release/deref/alias/generation events and its "
                    "source-rooted coverage — plus the matcher leads that relate them. "
                    "Give `value` or `function` to scope it; omit both for the capability report. "
                    "Prefer `field_history` for one field's events and `flow_pass` for the composed "
                    "interprocedural summary.",
     "inputSchema": {"type": "object", "properties": {
         "value": {"type": "string",
                   "description": "value name or graph node id to scope lifecycle evidence to"},
         "function": {"type": "string",
                      "description": "function name or node id to scope lifecycle evidence to"}}}},
    {"name": "error_path_summary",
     "description": "Read-only. For one function, report its exit paths (returns / error branches) "
                    "and the resource-handling evidence on them, plus the honest frontier: complete "
                    "transfer summaries remain a separate frontier from the lifecycle graph. Use "
                    "it to see how a function leaves on its error paths; pair with `guards` and "
                    "`flow_pass` for the interprocedural picture.",
     "inputSchema": {"type": "object", "properties": {
         "function": {"type": "string", "description": "function name or node id to summarize"},
         "limit": {"type": "integer", "default": 100,
                   "description": "maximum exit-path rows returned"}},
         "required": ["function"]}},
    {"name": "concept_search",
     "description": "Search code by behavior rather than spelling using an optional local "
                    "embedding model. Search is offline-only and never downloads implicitly; "
                    "install the concept-search extra and run `lachesis concept-model download`.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string"}, "limit": {"type": "integer", "default": 20},
         "min_score": {"type": "number", "default": 0.0},
         "offset": {"type": "integer", "default": 0},
         "model": {"type": "string", "default": "BAAI/bge-small-en-v1.5"}},
         "required": ["query"]}},
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
    {"name": "communities",
     "description": "The codebase's SUBSYSTEMS: partitions the call graph into clusters that "
                    "call each other more than the rest of the tree (label propagation), "
                    "independent of the directory layout — the structure the code HAS, not "
                    "how it was filed. Each community carries a label (its highest-degree "
                    "member), size, cohesion, the files it spans, and its top members with "
                    "node_id + handle. Reports the graph modularity and lifts out cross-"
                    "cutting connector hubs. Partitions over precise compiler calls by "
                    "default; set include_dispatch for C function-pointer trees. Use AFTER "
                    "hubs to go from 'what is central' to 'what are the parts'.",
     "inputSchema": {"type": "object", "properties": {
         "n": {"type": "integer", "default": 20},
         "members": {"type": "integer", "default": 8},
         "min_size": {"type": "integer", "default": 2},
         "include_dispatch": {"type": "boolean", "default": False}}}},
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
     "description": "Read-only. L0 folder graph rooted at a path prefix: folder -> file -> "
                    "declarations. The coarsest orientation move — use it to see what lives under a "
                    "directory before drilling in with `open_file` (one file's graph) or `read_body` "
                    "(one function's source). Returns a {nodes, edges, manifest} graph.",
     "inputSchema": {"type": "object", "properties": {
         "root": {"type": "string",
                  "description": "repo-relative path prefix to root the folder graph at"}},
         "required": ["root"]}},
    {"name": "flow",
     "description": "Read-only. Forward value-flow cone from a value/symbol: everything it can reach "
                    "over VALUE_FLOWS_TO + POINTS_TO, bridging aliases through the heap. Use it to "
                    "answer 'where does this value go?'; for the reverse (what feeds a sink) use "
                    "`sources_of`, and for a yes/no witness between two points use `reaches`. Returns "
                    "labeled nodes/edges; a missing path is over-approximation-safe, not proof of "
                    "none.",
     "inputSchema": {"type": "object", "properties": {
         "seed": {"type": "string", "description": "value/symbol name or graph node id to flow from"},
         "limit": {"type": "integer", "default": 200, "description": "maximum nodes returned"}},
         "required": ["seed"]}},
    {"name": "reaches",
     "description": "Read-only. Does src reach sink through value flow? Returns the labeled witness "
                    "path when it does, or an honest negative when it doesn't (a negative under "
                    "truncation is not proof of no path). Use it to confirm one specific "
                    "source->sink pair; use `flow`/`sources_of` to explore a whole cone. NOTE: it "
                    "follows VALUE_FLOWS_TO/POINTS_TO, a different edge set than `taint`, so "
                    "adjudicate taint witnesses from their own `path`.",
     "inputSchema": {"type": "object", "properties": {
         "src": {"type": "string", "description": "source value name or graph node id"},
         "sink": {"type": "string", "description": "sink value name or graph node id"}},
         "required": ["src", "sink"]}},
    {"name": "sources_of",
     "description": "Read-only reverse value-flow cone for a sink. Use this after a candidate "
                    "or sink is selected to find values that may feed it; it returns labeled "
                    "nodes and edges plus explicit truncation/frontier metadata. A missing path "
                    "is not proof that no flow exists.",
     "inputSchema": {"type": "object", "properties": {
         "sink": {"type": "string", "description": "sink name or graph node id"},
         "limit": {"type": "integer", "default": 200, "description": "maximum rows returned"}},
         "required": ["sink"]}},
    {"name": "points_to",
     "description": "Read-only. Return the heap objects a value may point to through POINTS_TO "
                    "edges — the alias set behind a pointer. Use it for pointer/alias follow-up, not "
                    "for callers (`callers`) or value-flow (`flow`/`reaches`). Returns the "
                    "pointed-to objects with path evidence plus explicit unknowns; a missing edge is "
                    "over-approximation-safe, not proof the pointer is null.",
     "inputSchema": {"type": "object", "properties": {
         "value": {"type": "string", "description": "value name or graph node id"}},
         "required": ["value"]}},
    {"name": "aliases",
     "description": "Read-only. Return the values that alias this one — those sharing a heap object "
                    "through POINTS_TO (the destructuring / alias set). Use it to find every name for "
                    "the same object before reasoning about a mutation; complements `points_to` "
                    "(objects a value points to) and `flow` (where a value goes). Response carries "
                    "the alias set with path evidence.",
     "inputSchema": {"type": "object", "properties": {
         "value": {"type": "string", "description": "value name or graph node id"}},
         "required": ["value"]}},
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
                    "`source_id`/`sink_id`, the exact graph node ids of the bound endpoints, plus "
                    "`path` -- the ordered source->sink hops taint actually walked ({id,label,at} each). "
                    "Adjudicate a witness from its `path` (read source at each hop); do NOT re-derive it "
                    "with `reaches`, which follows a different edge set (VALUE_FLOWS_TO/POINTS_TO) and can "
                    "return 0 hops for a pair taint reached over REACHING_DEF/summary edges. "
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
                                   "full (whole capsule incl. inferences)"},
         "temporal": _TEMPORAL_ARG, "hard_stop": _HARD_STOP_ARG}}},
    {"name": "candidate_detail",
     "description": "Return the complete neutral evidence capsule for one candidate id. It "
                    "contains observations and bounded inferences, but no safe/unsafe verdict.",
     "inputSchema": {"type": "object", "properties": {
         "candidate_id": {"type": "string"},
         "temporal": _TEMPORAL_ARG, "hard_stop": _HARD_STOP_ARG}, "required": ["candidate_id"]}},
    {"name": "candidate_census",
     "description": "Report constructor metadata, exhaustive counts, and explicit analysis "
                    "frontiers. Use this to distinguish an empty result from missing coverage.",
     "inputSchema": {"type": "object", "properties": {
         "constructor_id": {"type": "string"},
         "temporal": _TEMPORAL_ARG, "hard_stop": _HARD_STOP_ARG}}},
    {"name": "explain",
     "description": "One shot from a candidate (by id, or by the sink's file:line) to a "
                    "judgeable picture: the obligation and where it lands, the guard the "
                    "enclosing function does or does not place over it, the bounded reverse "
                    "value-flow cone into the sink, and the enclosing function's source read "
                    "inline -- the census->candidates->detail->sources_of->read_body chain "
                    "composed into one result. Provenance and guard are evidence, not verdicts: "
                    "an empty cone is 'nothing observed under this tier', not 'unreachable'. "
                    "Pass candidate_id, or file and line.",
     "inputSchema": {"type": "object", "properties": {
         "candidate_id": {"type": "string",
                          "description": "the candidate to explain (from candidates/census)"},
         "file": {"type": "string", "description": "with `line`: locate the sink by position "
                                                   "(full path, suffix, or basename)"},
         "line": {"type": "integer", "description": "with `file`: the sink's source line"},
         "provenance_limit": {"type": "integer", "default": 200,
                              "description": "cap on reverse-cone source nodes shown"},
         "max_source_chars": {"type": "integer", "default": 4000,
                              "description": "cap on the inlined enclosing-function source"},
         "temporal": _TEMPORAL_ARG, "hard_stop": _HARD_STOP_ARG}}},
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
    {"name": "enrich",
     "description": "Warm this graph's sidecars once (the 2nd pass), so later flow_pass / leads / "
                    "candidates / explain answer fast instead of paying the cost cold. Folds the "
                    "dataflow tier over the whole graph and binds the catalog, and persists both "
                    "beside the store (.dataflow.pb / .bind.pb) -- the difference between a >120s "
                    "cold census and an instant one. Idempotent: a store already enriched is a "
                    "no-op that just reports what is on disk. An unevaluated temporal family is "
                    "reported as 'not evaluated', never 'clean'. No arguments.",
     "inputSchema": {"type": "object", "properties": {}}},
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
    {"name": "leads",
     "description": "Query the flow pass's LEADS in memory -- the shape-matcher findings the "
                    "3rd pass already computed and cached, not a fresh cold run. This is the "
                    "warm counterpart to re-deriving leads by hand every question: the pass is "
                    "materialized once (via `flow_pass`), then this filters the held result. No "
                    "arg: a by-pattern summary plus the honesty fields (whether the run timed "
                    "out, which functions were truncated) -- an empty result over a partial run "
                    "is never 'clean'. `pattern` filters to one bug shape; `function` to one "
                    "enclosing function; `at` locates by source position `file`, `file:line`, or "
                    "`file:lo-hi` (a lead carries only its function + line, so the file is "
                    "resolved through the symbol index; a basename or path suffix is enough). "
                    "Leads are leads, not verdicts -- adjudicate with sources_of/reaches.",
     "inputSchema": {"type": "object", "properties": {
         "pattern": {"type": "string", "description": "keep only this bug-shape pattern"},
         "function": {"type": "string", "description": "keep only leads in this function"},
         "at": {"type": "string", "description": "locate by source position: file | file:line "
                "| file:lo-hi"}}}},
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
            "description": "text (compact, default) | json (structured result page)"}
# Paging fields on these legacy list-shaped moves window their text rendering. Newer
# comprehension tools page structured results before they reach this layer and include
# total/next-offset metadata in both JSON and compact text.
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
    """Serialize a tool result as structured JSON or compact agent-facing text.

    Comprehension tools page evidence in the result contract itself. The renderer also
    windows legacy list-shaped text results and strips redundant detail."""
    if fmt == "json":
        return json.dumps(result)
    return render_mod.render(name, result, offset=offset, limit=limit)


def _tool_error(name, error):
    """Return a recoverable, agent-readable error envelope for one tool call."""
    message = str(error) or type(error).__name__
    lowered = message.lower()
    if "native" in lowered and ("kernel" in lowered or "rust" in lowered):
        fix = ("install a platform wheel with `python -m pip install --upgrade lachesis-cpg`, "
               "or build native/lifetime_kernel with cargo")
    elif "path" in lowered or "graph" in lowered or "source" in lowered:
        fix = "check the path and call `load_graph` or `build_graph` with a readable target"
    elif "deadline" in lowered or "timeout" in lowered:
        fix = "retry with a larger hard_stop/timeout, or request the structural fast path"
    else:
        fix = "inspect the message, then retry this tool; the MCP session remains available"
    partial = list(getattr(error, "partial_leads", ()) or ())
    return {
        "move": name,
        "ok": False,
        "error": {"type": type(error).__name__, "message": message, "fix": fix},
        "partial_leads": partial,
    }


def _capability_blocked(name, reason, prerequisite):
    return {"move": name, "supported": False, "status": "blocked",
            "reason": reason, "prerequisite": prerequisite}


def _semantic_lifecycle_report(c, args):
    """Expose Pass 3 lifecycle evidence without introducing a second matcher."""
    bundle = c.flow_bundle
    semantic = bundle.get("semantic_graph")
    if semantic is None:
        return _capability_blocked("object_lifecycle", "no semantic graph was produced",
                                   "Pass 3 semantic graph")
    payload = semantic.to_dict()
    raw_nodes = payload.get("nodes") or {}
    nodes = ([{"id": node_id, **(node or {})} for node_id, node in raw_nodes.items()]
             if isinstance(raw_nodes, dict) else list(raw_nodes))
    value, function = args.get("value"), args.get("function")
    lifecycle = {"alloc_attempt", "origin", "release", "invalidate", "read_storage",
                 "write_storage", "write_storage_null", "use", "escape", "derive",
                 "uninitialized", "realloc_attempt", "realloc_failed", "lost_from_slot"}
    events = []
    for node in nodes:
        props, event = node.get("properties") or {}, node.get("event") or {}
        kind = str(props.get("event_kind") or event.get("kind") or "").lower()
        kind = kind.removeprefix("eventkind.")
        obj = props.get("object_id") or props.get("target_id") or props.get("obj") or event.get("obj")
        owner = props.get("owner_function_id") or node.get("fragment") or props.get("function")
        if kind not in lifecycle:
            continue
        if value and value not in {str(obj), str(node.get("label")), str(node.get("id"))}:
            continue
        if function and function not in {str(owner), str(props.get("owner_function")), str(node.get("fragment"))}:
            continue
        events.append({"node": node.get("id"), "kind": kind, "object": obj,
                       "function": owner, "line": props.get("line") or event.get("line"),
                       "label": node.get("label")})
    events.sort(key=lambda item: (item.get("function") or "", item.get("line") or 0,
                                  item["node"] or ""))
    return {"move": "object_lifecycle", "supported": True, "status": "available",
            "events": events, "count": len(events), "coverage": bundle.get("coverage"),
            "lifetime": bundle.get("lifetime", {})}


def _wrapper_model(store, token, limit=50):
    """Infer wrapper roles from nearby callee names and graph effects."""
    seeds = _seeds(store, token)
    if not seeds:
        return {"move": "wrapper_model", "error": f"no function named {token!r}"}
    rows = []
    role_words = {
        "allocator": ("alloc", "malloc", "calloc", "realloc", "new", "create"),
        "deallocator": ("free", "delete", "destroy", "release", "close"),
        "io": ("read", "write", "recv", "send", "fread", "fwrite", "open"),
        "validator": ("check", "valid", "verify", "parse", "sanitize"),
    }
    for seed in seeds:
        callees = si.callees(store.gl, seed, resolver=store.resolver)
        for callee in callees[:max(1, limit)]:
            low = (callee.get("name") or "").lower()
            roles = [role for role, words in role_words.items()
                     if any(word in low for word in words)]
            if not roles:
                continue
            rows.append({"wrapper": _ref(store, seed), "callee": callee,
                         "roles": roles, "confidence": "heuristic-name",
                         "evidence": "resolved callee name"})
    return {"move": "wrapper_model", "functions": [_ref(store, s) for s in seeds],
            "wrappers": rows[:limit], "count": len(rows),
            "interpretation": "inference only; no registry facts were changed"}


def _guard_dominance(store, args):
    from lachesis.planner.dominance import Dominance

    entry, effect = _seed(store, args.get("entry", "")), _seed(store, args.get("effect", ""))
    if not entry or not effect:
        return {"move": "guard_dominance", "error": "could not resolve entry/effect"}
    depth = max(1, int(args.get("depth", 6)))
    dominance = Dominance(store)
    closure = dominance.call_closure(entry, depth=depth)
    if effect not in closure:
        return {"move": "guard_dominance", "entry": _ref(store, entry),
                "effect": _ref(store, effect), "reachable": False,
                "closure": closure.summary(), "guards": []}
    verdict = dominance.verdict(entry, effect, depth=depth)
    guards = dominance._recognitions_on(entry)
    return {"move": "guard_dominance", "entry": _ref(store, entry),
            "effect": _ref(store, effect), "reachable": True,
            "closure": closure.summary(), "verdict": verdict,
            "guards": guards}


def _counterexample(store, args):
    from collections import deque

    src, sink = _seed(store, args.get("src", "")), _seed(store, args.get("sink", ""))
    avoided = set(_seeds(store, args.get("validator", "")))
    if not src or not sink or not avoided:
        return {"move": "counterexample", "error": "could not resolve src/sink/validator"}
    max_depth, budget = max(1, int(args.get("depth", 6))), max(1, int(args.get("limit", 20)))
    queue, seen = deque([(src, [src])]), {src}
    truncated = False
    while queue:
        node, path = queue.popleft()
        if node == sink:
            return {"move": "counterexample", "found": True, "avoided":
                    [_ref(store, n) for n in avoided], "path": [_ref(store, n) for n in path],
                    "truncated": truncated}
        if len(path) - 1 >= max_depth:
            continue
        for callee in si.callees(store.gl, node):
            target = callee["node_id"]
            if target in avoided or target in seen:
                continue
            if len(seen) >= budget:
                truncated = True
                break
            seen.add(target)
            queue.append((target, path + [target]))
    return {"move": "counterexample", "found": False, "avoided":
            [_ref(store, n) for n in avoided], "visited": len(seen),
            "truncated": truncated,
            "interpretation": "no avoiding path found within the bounded call search"}


def _invariant_trace(store, args):
    seed = _seed(store, args.get("value", ""))
    if not seed:
        return {"move": "invariant_trace", "error": f"no value named {args.get('value')!r}"}
    flow_kinds = {"DEFINES", "READS_FROM", "WRITES_TO", "VALUE_FLOWS_TO",
                  "READS_HEAP", "WRITES_HEAP", "REACHING_DEF", "CONDITION",
                  "PROPERTY_READ", "PROPERTY_WRITE"}
    depth, limit = max(0, int(args.get("depth", 4))), max(1, int(args.get("limit", 100)))
    frontier, seen, events = [(seed, 0)], {seed}, []
    while frontier:
        node_id, level = frontier.pop(0)
        if level >= depth:
            continue
        for edge in (*store.index.incoming.get(node_id, ()),
                     *store.index.outgoing.get(node_id, ())):
            kind = edge.get("kind")
            if kind not in flow_kinds:
                continue
            other = edge["source"] if edge["target"] == node_id else edge["target"]
            if other not in store.gl.nodes:
                continue
            node = store.gl.nodes[other]
            role = ("producer" if kind in {"DEFINES", "VALUE_FLOWS_TO", "REACHING_DEF"}
                    else "mutator" if kind in {"WRITES_TO", "WRITES_HEAP"}
                    else "checker" if kind == "CONDITION" else "consumer")
            events.append({**_ref(store, other), "role": role, "via": kind, "depth": level + 1})
            if other not in seen:
                seen.add(other)
                frontier.append((other, level + 1))
    events.sort(key=lambda row: (row["depth"], row["role"], row["node_id"]))
    return {"move": "invariant_trace", "value": _ref(store, seed),
            "events": events[:limit], "count": len(events), "truncated": len(events) > limit}


def _representation_roundtrip(store, args):
    rows = []
    for key in ("left", "right"):
        seed = _seed(store, args.get(key, ""))
        if not seed:
            return {"move": "representation_roundtrip", "error": f"no callable named {args.get(key)!r}"}
        calls = si.callees(store.gl, seed, with_dispatch=True, resolver=store.resolver)
        controls = [n.get("properties", {}).get("control_kind")
                    for n in store.gl.body_nodes(seed)
                    if n.get("properties", {}).get("control_kind")]
        rows.append({"side": key, "function": _ref(store, seed),
                     "callees": calls, "control": sorted(controls)})
    left_calls = {r["node_id"] for r in rows[0]["callees"]}
    right_calls = {r["node_id"] for r in rows[1]["callees"]}
    return {"move": "representation_roundtrip", "paths": rows,
            "differences": {"left_only": sorted(left_calls - right_calls),
                            "right_only": sorted(right_calls - left_calls),
                            "control_left_only": sorted(set(rows[0]["control"]) - set(rows[1]["control"])),
                            "control_right_only": sorted(set(rows[1]["control"]) - set(rows[0]["control"]))},
            "interpretation": "structural differences only; no behavior verdict"}


def _cross_boundary_paths(c, args):
    result = c.comprehension.component_boundary(
        args["from_component"], args["to_component"],
        limit=max(1, int(args.get("limit", 1000))), offset=0)
    rows = result.get("crossings", [])
    counts = {}
    for row in rows:
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    for row in rows:
        row["rarity"] = 1.0 / counts[row["kind"]]
    rows.sort(key=lambda row: (-row["rarity"], row["kind"], row["source"]["node_id"]))
    start, size = max(0, int(args.get("offset", 0))), max(1, int(args.get("limit", 100)))
    page = rows[start:start + size]
    return {"move": "cross_boundary_paths", "from": args["from_component"],
            "to": args["to_component"], "crossings": page,
            "count": len(rows), "page": {"offset": start, "returned": len(page),
                                          "has_more": start + len(page) < len(rows)}}


def call_tool(name, args, format=None):
    fmt = "json" if format == "json" else ("text" if format == "text" else _DEFAULT_FORMAT)
    offset, limit = int(args.get("offset", 0)), int(args.get("limit", render_mod.DEFAULT_LIMIT))

    if name == "load_graph":
        return _load_graph(args)
    if name == "build_graph":
        return _build_graph(args)
    if name in DISABLED_TOOLS:
        return _emit(name, {"error": f"tool {name!r} is disabled: it requires a "
                                     "whole-graph guard scan (removed for now)"}, fmt)
    if _PROFILE == "comprehension" and name in HUNTING_TOOLS:
        return _emit(name, {"error": f"tool {name!r} is hidden under the "
                                     "'comprehension' profile (hunting-only tool)"}, fmt)
    c = ctx()
    cone = _fold_cone(c.store, name, args)
    store, gl = c.store, c.store.gl
    text = fmt != "json"  # text mode enriches callers/callees with dispatch slots

    if name == "unknowns":
        result = c.comprehension.unknowns(
            function=args.get("function"), limit=int(args.get("limit", 100)),
            offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "coverage_map":
        result = c.comprehension.coverage_map(
            component_depth=int(args.get("component_depth", 1)),
            limit=int(args.get("limit", 100)), offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "field_history":
        result = c.comprehension.field_history(
            args["field"], args.get("owner_type"), limit=int(args.get("limit", 100)),
            offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "sibling_compare":
        result = c.comprehension.sibling_compare(
            args["symbol"], limit=int(args.get("limit", 100)),
            offset=int(args.get("offset", 0)), call_offset=int(args.get("call_offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "type_explain":
        result = c.comprehension.type_explain(
            args["type"], limit=int(args.get("limit", 100)),
            offset=int(args.get("offset", 0)),
            member_offset=int(args.get("member_offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "component_boundary":
        result = c.comprehension.component_boundary(
            args["from_component"], args["to_component"],
            limit=int(args.get("limit", 100)), offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "indirect_targets":
        return _emit(name, c.comprehension.indirect_targets(
                         args["function"], limit=int(args.get("limit", 100)),
                         offset=int(args.get("offset", 0)),
                         target_offset=int(args.get("target_offset", 0))),
                     fmt, offset, limit)
    if name == "architecture_map":
        result = c.comprehension.architecture_map(
            component_depth=int(args.get("component_depth", 2)),
            max_communities=int(args.get("max_communities", 30)),
            max_files_per_community=int(args.get("max_files_per_community", 50)),
            offset=int(args.get("offset", 0)),
            file_offset=int(args.get("file_offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "execution_story":
        result = c.comprehension.execution_story(
            args["entry"], max_depth=int(args.get("max_depth", 5)),
            max_steps=int(args.get("max_steps", 100)),
            offset=int(args.get("offset", 0)),
            branch_limit=int(args.get("branch_limit", 20)),
            branch_offset=int(args.get("branch_offset", 0)),
            frontier_offset=int(args.get("frontier_offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "change_context":
        result = c.comprehension.change_context(
            args["symbol"], limit=int(args.get("limit", 12)),
            offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "tests_for":
        result = c.comprehension.tests_for(
            args["symbol"], limit=int(args.get("limit", 50)),
            offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "spec_links":
        result = c.comprehension.spec_links(
            args["symbol"], limit=int(args.get("limit", 50)),
            offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "context_pack":
        semantic = c.concepts(DEFAULT_MODEL).search(
            args["question"], limit=max(6, int(args.get("max_symbols", 6)) * 3))
        semantic_hits = semantic.get("results", []) if "error" not in semantic else []
        semantic_status = (f"ready:{semantic.get('model')}" if semantic_hits
                           else semantic.get("error", "no-semantic-matches"))
        result = c.comprehension.context_pack(
            args["question"], max_symbols=int(args.get("max_symbols", 6)),
            max_neighbors=int(args.get("max_neighbors", 30)),
            semantic_hits=semantic_hits, semantic_status=semantic_status,
            symbol_offset=int(args.get("symbol_offset", 0)),
            relationship_offset=int(args.get("relationship_offset", 0)),
            condition_offset=int(args.get("condition_offset", 0)),
            test_offset=int(args.get("test_offset", 0)),
            spec_offset=int(args.get("spec_offset", 0)),
            unknown_offset=int(args.get("unknown_offset", 0)))
        return _emit(name, result, fmt, offset, limit)
    if name == "concept_search":
        result = c.concepts(args.get("model", DEFAULT_MODEL)).search(
            args["query"], limit=int(args.get("limit", 20)),
            min_score=float(args.get("min_score", 0.0)),
            offset=int(args.get("offset", 0)))
        return _emit(name, result, fmt, offset, limit)

    if name == "scan":
        lens = args.get("lens", "all")
        if lens not in {"all", "guard-diff", "flow"}:
            raise ValueError("lens must be one of: all, guard-diff, flow")
        if lens == "guard-diff":
            scan = c.scan_bundle_for(int(args.get("entrypoints", 0)))
        elif lens == "flow":
            bundle = c._flow_bundle(
                deadline=c._resolve_deadline(args.get("hard_stop"), None))
            leads = [lead.to_dict() if hasattr(lead, "to_dict") else lead
                     for lead in bundle.get("leads") or ()]
            scan = {
                "constructor": "native-flow",
                "queue": leads,
                "census": bundle.get("coverage") or {},
                "suppressions": [],
            }
        else:
            result = c.candidates(
                temporal=True, hard_stop=args.get("hard_stop"), limit=0,
            )
            queue = list(result.get("candidates") or ())
            for group in result.get("groups") or ():
                queue.extend(group.get("candidates") or ())
            scan = {
                "constructor": "all",
                "queue": queue,
                "census": result.get("coverage") or {},
                "suppressions": [],
                "temporal_evaluated": result.get("temporal_evaluated"),
            }
        minimum = float(args.get("min_rank", 0.0))
        queue = [capsule for capsule in scan["queue"]
                 if float(capsule.get("rank") or 0.0) >= minimum]
        start, size = max(0, offset), max(1, limit)
        page = queue[start:start + size]
        next_offset = start + len(page)
        page_meta = {
            "total": len(queue), "offset": start, "returned": len(page),
            "has_more": next_offset < len(queue),
            "next_offset": next_offset if next_offset < len(queue) else None,
        }
        result = {
            "move": "scan",
            "lens": lens,
            "constructor": scan["constructor"],
            "census": scan["census"],
            "leads": page,
            "page": page_meta,
            "min_rank": minimum,
        }
        if args.get("include_suppressions"):
            result["suppressions"] = scan["suppressions"]
        return _emit(name, result, fmt, offset, limit)
    if name == "wrapper_model":
        return _emit(name, _wrapper_model(store, args["function"],
                                          int(args.get("limit", 50))), fmt, offset, limit)
    if name == "guard_dominance":
        return _emit(name, _guard_dominance(store, args), fmt, offset, limit)
    if name == "counterexample":
        return _emit(name, _counterexample(store, args), fmt, offset, limit)
    if name == "invariant_trace":
        return _emit(name, _invariant_trace(store, args), fmt, offset, limit)
    if name == "representation_roundtrip":
        return _emit(name, _representation_roundtrip(store, args), fmt, offset, limit)
    if name == "cross_boundary_paths":
        return _emit(name, _cross_boundary_paths(c, args), fmt, offset, limit)
    if name == "range_analysis":
        return _emit(name, _capability_blocked(
            name, "numeric range constraints are not emitted by the current graph",
            "local numeric model"), fmt, offset, limit)
    if name == "object_lifecycle":
        return _emit(name, _semantic_lifecycle_report(c, args), fmt, offset, limit)
    if name == "error_path_summary":
        return _emit(name, _capability_blocked(
            name, "release/transfer events are not yet emitted on exits",
            "memory.free and memory.deref constructors"), fmt, offset, limit)

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
    if name == "communities":
        disp = bool(args.get("include_dispatch"))
        comm = c._analysis(f"communities:disp={disp}",
                           lambda: Communities(c.store.gl, include_dispatch=disp))
        result = comm.summary(n=int(args.get("n", 20)),
                              members=int(args.get("members", 8)),
                              min_size=int(args.get("min_size", 2)))
        return _emit(name, {"move": "communities", **result}, fmt, offset, limit)
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
        # temporal:false is the guaranteed-bounded fast path (structural families, no dataflow
        # tier); hard_stop bounds the temporal families so a slow graph degrades instead of
        # hanging. Default matches the historical unbounded full bind.
        bundle = c._bound_bind(temporal=args.get("temporal", True),
                               hard_stop=args.get("hard_stop"), deadline=None)
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
        # An absent temporal family means "not evaluated on this bounded run", never "clean".
        result["temporal_evaluated"] = bool(bundle.get("temporal_evaluated"))
        # The per-language bind report carries the full `unbound` row lists
        # (hundreds of rows, ~90KB on a large catalog). That is coverage data:
        # it belongs on `candidate_census`, the move whose job is to distinguish
        # an empty result from missing coverage. Every other move gets the
        # counts only, so a list page stays bounded. Nothing is dropped -- the
        # rows are one census call away.
        result["atropos"] = _atropos_envelope(summary, full=(name == "candidate_census"))
        return _emit(name, result, fmt, offset, limit)
    if name == "explain":
        # The census->candidates->detail->sources_of->read_body chain in one call, over the
        # shared Analysis.explain. Bounded like every candidate move (temporal/hard_stop); the
        # provenance walk folds only a cone around the sink, never the whole graph.
        common = {"temporal": args.get("temporal", True), "hard_stop": args.get("hard_stop"),
                  "provenance_limit": int(args.get("provenance_limit", 200)),
                  "max_source_chars": int(args.get("max_source_chars", 4000))}
        if args.get("candidate_id"):
            result = c.explain(args["candidate_id"], **common)
        elif args.get("file") and args.get("line") is not None:
            result = c.explain_sink(args["file"], int(args["line"]), **common)
        else:
            result = {"move": "explain",
                      "error": "pass candidate_id, or both file and line"}
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
    if name == "enrich":
        result = c.enrich()
        result["move"] = "enrich"
        return _emit(name, result, fmt, offset, limit)
    if name == "flow_pass":
        bundle = c.flow_bundle
        semantic = bundle.get("semantic_graph")
        payload = semantic.to_dict() if semantic is not None else {"nodes": {}, "edges": {}}
        return _emit(name, {
            "move": "flow_pass",
            "counts": {
                "semantic_nodes": len(payload.get("nodes") or {}),
                "semantic_edges": sum(len(edges) for edges in
                                      (payload.get("edges") or {}).values()),
                "leads": len(bundle.get("leads") or ()),
            },
            "semantic_graph": payload,
            "leads": bundle.get("leads") or (),
            "lifetime": bundle.get("lifetime", {}),
        }, fmt, offset, limit)
    if name == "leads":
        # The warm counterpart to a cold re-run: `flow_bundle` is already materialized and
        # cached on the ctx, so this wraps it in a LeadSet and filters in memory. Same
        # LeadSet the library returns -- one implementation, queried from both surfaces.
        ls = LeadSet._from_bundle(c.flow_bundle, c.store)
        pattern, function, at = args.get("pattern"), args.get("function"), args.get("at")
        if pattern:
            ls = ls.by_pattern(pattern)
        if function:
            ls = ls.by_function(function)
        if at:
            file, lines = _parse_at(at)
            ls = ls.near(file, lines)
        # A bare call (or a summary-shaped one) returns the honest overview; a filtered call
        # returns the matching rows plus that overview so a thin/empty result still carries
        # whether the run was partial.
        result = {"move": "leads", "summary": ls.summary()}
        if pattern or function or at:
            result["leads"] = list(ls.leads)
            result["returned"] = len(ls)
        return _emit(name, result, fmt, offset, limit)
    if name == "flow_skeleton":
        bundle = c.flow_bundle
        semantic = bundle.get("semantic_graph")
        payload = semantic.to_dict() if semantic is not None else {"nodes": {}, "edges": {}}
        fn = args.get("function")
        leads = [lead for lead in bundle.get("leads") or ()
                 if not fn or lead.get("entry") == fn]
        return _emit(name, {
            "move": "flow_skeleton",
            "counts": {
                "semantic_nodes": len(payload.get("nodes") or {}),
                "semantic_edges": sum(len(edges) for edges in
                                      (payload.get("edges") or {}).values()),
                "leads": len(bundle.get("leads") or ()),
            },
            "semantic_graph": payload,
            "leads": leads,
            "lifetime": bundle.get("lifetime", {}),
        }, fmt, offset, limit)
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
    # Pass 2 already emits native taint role/reach records into the binary dataflow
    # overlay. Read those records directly; the deleted Python overlay solver must not
    # be reintroduced merely because an MCP client asks for taint evidence.
    store.ensure_dataflow_tier()
    index = store.index
    role_by_value = {}
    for role in index.nodes_of_kind("source", "sink"):
        properties = role.get("properties") or {}
        value_id = properties.get("value_id")
        if value_id:
            role_by_value[value_id] = role

    def _node(value_id):
        return store.node(value_id) or {}

    def _loc(value_id):
        properties = _node(value_id).get("properties") or {}
        file = properties.get("absolute_file") or properties.get("file")
        line = properties.get("start_line") or properties.get("line")
        return f"{file}:{line}" if file else None

    def _label(value_id):
        node = _node(value_id)
        return node.get("label") or (node.get("properties") or {}).get("label") or value_id

    rows = []
    witnessed = set()
    for witness in index.nodes_of_kind("taint-reach"):
        properties = witness.get("properties") or {}
        source_role = role_by_value.get(properties.get("source_id"))
        sink_role = role_by_value.get(properties.get("sink_id"))
        witness_ids = properties.get("witness_ids") or []
        if not isinstance(witness_ids, list):
            witness_ids = [witness_ids]
        if not witness_ids:
            continue
        source_value, sink_value = witness_ids[0], witness_ids[-1]
        witnessed.update(witness_ids)
        source_props = (source_role or {}).get("properties") or {}
        sink_props = (sink_role or {}).get("properties") or {}
        path = [{"id": value, "label": _label(value), "at": _loc(value)}
                for value in witness_ids]
        rows.append({
            "source": _label(source_value), "source_at": _loc(source_value),
            "source_id": source_value, "sink": _label(sink_value),
            "sink_at": _loc(sink_value), "sink_id": sink_value,
            "source_model": source_props.get("model_id"),
            "sink_model": sink_props.get("model_id"),
            "atropos_connected": bool(source_role or sink_role),
            "hops": len(path), "path": path,
        })

    rows.sort(key=lambda row: not row["atropos_connected"])
    if args.get("atropos_only"):
        rows = [row for row in rows if row["atropos_connected"]]
    limit = max(1, int(args.get("limit", 50)))
    unwitnessed = {"sources": [], "sinks": []}
    for value_id, role in role_by_value.items():
        if value_id in witnessed:
            continue
        kind = role.get("kind")
        if kind not in unwitnessed:
            continue
        props = role.get("properties") or {}
        unwitnessed[kind].append({
            "id": value_id, "label": _label(value_id), "at": _loc(value_id),
            "model": props.get("model_id"),
        })
    return {
        "move": "taint", "applied": True, "backend": "native-rust",
        "witness_count": len(rows),
        "atropos_connected": sum(row["atropos_connected"] for row in rows),
        "witnesses": rows[:limit],
        "unwitnessed": {
            "sources": unwitnessed["sources"][:limit],
            "sinks": unwitnessed["sinks"][:limit],
            "source_total": len(unwitnessed["sources"]),
            "sink_total": len(unwitnessed["sinks"]),
        },
    }

def _build_graph(args):
    """Build (or reuse) a graph for a source directory, then attach it in one call.

    Zero-config on-ramp: an agent that only has a repo path can call this and go, with no
    prior `lachesis build` step. In-process wrapper around `ensure_graph`, the same
    build-or-reuse path the server's own startup uses — content-addressed, so a second
    build of an unchanged tree returns instantly from cache. On success the freshly built
    store is loaded exactly as `load_graph` would, so the next tool call hits it."""
    source = _expand(args.get("source") or args.get("path"))
    if not source or not os.path.isdir(source):
        return json.dumps({"error": f"source must be an existing directory: {source!r}"})
    try:
        timeout = int(args.get("timeout_seconds", 300))
    except (TypeError, ValueError):
        return json.dumps({"error": "timeout_seconds must be an integer number of seconds"})
    if timeout < 1:
        return json.dumps({"error": "timeout_seconds must be greater than zero"})
    refresh = bool(args.get("refresh"))
    from lachesis.cache import entry_for
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                      ensure_graph)
    try:
        graph_path, rebuilt = ensure_graph(source, refresh=refresh,
                                            timeout_seconds=timeout)
    except EnvironmentProblem as error:
        # A missing frontend toolchain (node for TS/JS, clang for C). Actionable, not a crash.
        return json.dumps({"error": "missing toolchain prerequisite",
                           "checks": [{"name": c.name, "detail": c.detail, "fix": c.fix}
                                      for c in error.checks if not c.ok]})
    except NoSourceFound as error:
        return json.dumps({"error": str(error)})
    except Exception as error:  # noqa: BLE001 - a frontend timeout or compile failure
        return json.dumps({"error": f"build failed: {error}",
                           "hint": "large trees can exceed timeout_seconds (default 300); "
                                   "raise it and retry, or run lachesis build out of band"})
    meta = entry_for(source).meta() or {}
    loaded = json.loads(_load_graph({"path": str(graph_path)}))
    if "error" in loaded:  # built fine but could not attach — surface that, not a fake success
        return json.dumps({"error": loaded["error"], "graph": str(graph_path),
                           "rebuilt": rebuilt})
    return json.dumps({"move": "build_graph", "graph": str(graph_path),
                       "rebuilt": rebuilt,
                       "nodes": meta.get("nodes", loaded.get("nodes")),
                       "edges": meta.get("edges"),
                       "frontends": meta.get("frontends", []),
                       "profile": _PROFILE})


def _load_graph(args):
    """Runtime target switch: repoint the server and drop the cached ctx so the next
    tool call rebuilds against the new graph (load-once still holds within a target)."""
    global _GRAPH_PATH, _OVERLAY_PATH, _PROFILE, _CTX
    path = _expand(args.get("path"))
    if not path or not os.path.exists(path):
        return json.dumps({"error": f"graph path not found: {path!r}"})
    _GRAPH_PATH = path
    _OVERLAY_PATH = _expand(args.get("overlay"))
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


def _dispatch(msg):
    """Handle one JSON-RPC message, replying via ``send``.

    Split out of the read loop so that ``main`` can wrap a single request in one
    try/except: a failure in *any* branch (tool call, tools/list, a serialization
    error) becomes a JSON-RPC error for that one request, never a loop-killing
    traceback that takes all tools with it. Tool dispatch is held under
    ``_DISPATCH_LOCK`` so a load_graph swap stays atomic against an overlapping call."""
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
            with _DISPATCH_LOCK:
                text = call_tool(p["name"], a, format=a.get("format"))
            send({"jsonrpc": "2.0", "id": mid,
                  "result": {"content": [{"type": "text", "text": text}]}})
        except Exception as e:  # noqa: BLE001 - one tool's failure is that call's error
            log("tool error:", e)
            error_payload = _tool_error(p.get("name", "tool"), e)
            send({"jsonrpc": "2.0", "id": mid,
                  "result": {"content": [{"type": "text", "text": json.dumps(error_payload)}],
                             "structuredContent": error_payload,
                             "isError": True}})
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid,
              "error": {"code": -32601, "message": f"method not found: {method}"}})


def main():
    global _GRAPH_PATH, _OVERLAY_PATH, _PROFILE, _DEFAULT_FORMAT
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print("usage: lachesis mcp [graph.kuzu] [overlay] [profile]")
        print("Serve a Lachesis graph over MCP stdio; --version prints the installed version.")
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "--version":
        print(SERVER_VERSION)
        return 0
    # Config precedence: explicit argv wins, else env. The graph path may come from
    # argv[1] or LACHESIS_GRAPH; a session can also (re)attach at runtime via load_graph.
    _GRAPH_PATH = _expand(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("LACHESIS_GRAPH"))
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
                print(f"lachesis mcp: {check.name}: {check.detail}", file=sys.stderr)
            return 3
        except NoSourceFound as error:
            print(f"lachesis mcp: {error}", file=sys.stderr)
            return 2
        _GRAPH_PATH = str(graph)
    _OVERLAY_PATH = _expand(sys.argv[2] if len(sys.argv) > 2 else None)
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
        try:
            _dispatch(msg)
        except (BrokenPipeError, KeyboardInterrupt):
            # The client hung up (or Ctrl-C) mid-write; there is nothing left to send.
            # Leave the loop cleanly instead of dumping a traceback that reads as a crash.
            log("client disconnected; shutting down")
            break
        except Exception as e:  # noqa: BLE001 - one request must never kill the server
            # A failure anywhere in dispatch (even initialize/tools/list) is reported as
            # an error for that single request; the server keeps serving all 46 tools.
            log("dispatch error:", e)
            mid = msg.get("id") if isinstance(msg, dict) else None
            if mid is not None:
                try:
                    send({"jsonrpc": "2.0", "id": mid,
                          "error": {"code": -32603, "message": f"internal error: {e}"}})
                except Exception:  # noqa: BLE001 - client already gone
                    break


if __name__ == "__main__":
    raise SystemExit(main())
