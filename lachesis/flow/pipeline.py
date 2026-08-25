#!/usr/bin/env python3
"""Whole-graph driver -- run the flow pass over an already-loaded Lachesis store.

One call returns the full bundle so callers (the CLI in walk.py, the MCP tool) share a
single code path: translate -> traverse+order+summarise -> skeletons -> shape leads.
"""
import os
from collections import defaultdict, deque
from time import perf_counter

from .translate import build_F
from .skeleton import build_skeletons, _summaries_for
from .match import match_all, match_leak, match_reach, match_typestate
from .cfg import cfg_bundle
from .object_lifetime import ObjectLifetimeResult, analyze_object_lifetimes
from .semantic_graph import match_graph
from .fragment_store import Claus
from .coverage import CoverageScheduler
from lachesis.timeit import timeit


_LIFETIME_PATTERNS = {"double-free", "use-after-free"}
_DEFAULT_LIFETIME_ENGINE = "object"


def _lifetime_slice(F, succ, lang="c"):
    """Select the semantic call-graph region carrying lifecycle or sink facts.

    The name is retained for API compatibility.  The production skeleton must
    also include sink-only functions (for example a standalone bounded-copy
    helper) and realloc-only functions, otherwise Atropos reach patterns would
    remain stranded in the retired renderer.
    """
    from . import atropos

    sink_names = set(atropos.sink_catalog(lang))
    def carries_semantic_work(function):
        # A frontend may expose an inline/compiler artifact as a nominal source
        # function with no body, calls, lifecycle facts, or sink observations.
        # Such a node cannot contribute an object state and should not create a
        # permanently unresolved Pass 3 region. Real source wrappers remain
        # seeds because they carry calls/source sites even when their lifecycle
        # effect is entirely in a callee.
        return bool(function.get("events") or function.get("calls")
                    or function.get("source_calls") or function.get("source_sites"))

    def materializable(function):
        return (carries_semantic_work(function) or function.get("params") or
                function.get("returns") or function.get("body_node_count", 0) > 0)

    seeds = {
        name for name, function in F.items()
        # Source-rooted Pass 3 must not require a sink-shaped fact before it
        # explores a function.  A pointer-arithmetic or language-specific
        # semantic operation can be invisible to the generic operation census
        # and still be the only route to a matcher pattern.  The source
        # discovery result is the authoritative reachability gate; Claus and
        # the matcher decide later whether the region contains useful facts.
        if (function.get("source_reachable") and
            materializable(function))
        or any(event.get("kind") in {"alloc", "free", "escape", "realloc"}
               for event in function.get("events", ()))
        or any(call.get("is_sink") or call.get("callee") in sink_names
               for call in function.get("calls", ()))
    }
    if not seeds:
        return {}
    reverse = defaultdict(set)
    for caller, callees in succ.items():
        for callee in callees:
            reverse[callee].add(caller)
    region = set(seeds)
    queue = deque(seeds)
    while queue:
        name = queue.popleft()
        for neighbour in set(succ.get(name, ())) | set(reverse.get(name, ())):
            if (neighbour in F and neighbour not in region and
                (materializable(F[neighbour]) or succ.get(neighbour))):
                region.add(neighbour)
                queue.append(neighbour)
    return {name: F[name] for name in region}


def _lead_key(lead):
    # The two engines encode object display names differently; a differential is
    # about whether they agree on the finding site, not renderer spelling.
    return (lead.get("pattern"), lead.get("entry"), lead.get("line"))


def _select_lifetime_leads(legacy, object_identity, mode, covered_entries=None,
                           object_flow=None):
    preserved = [lead for lead in legacy if lead.get("pattern") not in _LIFETIME_PATTERNS]
    legacy_lifetime = [lead for lead in legacy if lead.get("pattern") in _LIFETIME_PATTERNS]
    object_lifetime = list(object_identity)
    if mode == "object":
        covered = set(covered_entries) if covered_entries is not None else None
        object_flow = object_flow or {}
        if covered is not None:
            # Keep an object lead when its function is object-trusted AND its object is
            # not one that flows into an unknown (unsafe) callee. The second test rescues
            # every lead in a function whose only unsafety is an unrelated failed callee.
            object_lifetime = [lead for lead in object_lifetime
                               if lead.get("entry") in covered
                               and lead.get("root") not in
                               object_flow.get(lead.get("entry"), ())]
        fallback = ([lead for lead in legacy_lifetime
                     if covered is not None and lead.get("entry") not in covered])
        selected = object_lifetime + fallback
    else:
        selected = legacy_lifetime
    seen, leads = set(), []
    for lead in preserved + selected:
        key = tuple(sorted((key, repr(value)) for key, value in lead.items()))
        if key not in seen:
            seen.add(key)
            leads.append(lead)

    legacy_by_key = {_lead_key(lead): lead for lead in legacy_lifetime}
    object_by_key = {_lead_key(lead): lead for lead in object_lifetime}
    legacy_only = sorted(set(legacy_by_key) - set(object_by_key), key=repr)
    object_only = sorted(set(object_by_key) - set(legacy_by_key), key=repr)
    differential = {
        "legacy": len(legacy_lifetime), "object": len(object_lifetime),
        "legacy_only": len(legacy_only), "object_only": len(object_only),
        # Bounded samples keep a large audit (the curl case that motivated this work)
        # from turning the diagnostic envelope into another 500-row result set.
        "legacy_only_sample": [legacy_by_key[key] for key in legacy_only[:25]],
        "object_only_sample": [object_by_key[key] for key in object_only[:25]],
        "sample_truncated": len(legacy_only) > 25 or len(object_only) > 25,
    }
    return leads, differential


@timeit(name="pipeline._match_object_mode_legacy")
def _match_object_mode_legacy(skels, cfg, fallback_entries):
    """Retain reach + leak globally and legacy lifetime only for coverage fallbacks."""
    fallback_entries = set(fallback_entries)
    leads = []
    for skeleton in skels:
        if skeleton["kind"] == "reach":
            leads.extend(match_reach(skeleton))
        elif skeleton.get("entry") in fallback_entries:
            leads.extend(match_typestate(skeleton, cfg=cfg))
        else:
            leads.extend(match_leak(skeleton))
    return leads


@timeit
def run_pass(store, lang="c", lifetime_engine=None, *,
             workers=None, snapshot=None, deadline=None, progress=None):
    """Return {F, succ, summaries, skeletons, leads, lifetime} for an opened GraphStore.

    The store's whole-graph value-flow tier is ensured once (cached to disk), then every
    later stage reads only the projected IR -- never the graph again. The one exception is
    the CFG bundle (successor edges + node resolver), projected once here so the typestate
    matcher's temporal shapes are path-sensitive over the real control-flow graph.

    C double-free/UAF leads use object identity by default. ``lifetime`` includes the
    bounded legacy differential and coverage diagnostics; functions with no complete
    object analysis retain legacy leads. Set ``LACHESIS_LIFETIME_ENGINE=shadow`` to run
    both without changing output, or ``legacy`` for an operational rollback.

    The keyword-only knobs make the pass configurable without process-wide env vars (which
    are not thread-safe and leak into spawned workers), each falling back to its env var
    when ``None``:
      ``workers``  -> LACHESIS_LIFETIME_WORKERS (object-analysis process count)
      ``snapshot`` -> LACHESIS_PASS3_SNAPSHOT   (opt-in semantic-graph disk cache; a footgun
                                                 on large graphs, so it defaults off)
      ``deadline`` -> a cooperative ``Deadline``; on expiry the pass returns the leads it has
                      with ``lifetime["timed_out"]=True`` instead of running unbounded. There
                      is no env fallback — an unset deadline means "no bound", preserving the
                      historical unbounded behavior for the existing callers.
      ``progress`` -> optional ``callable(label, elapsed_seconds)`` invoked at each phase
                      boundary so a long pass is never silent.
    """
    started = perf_counter()

    def _emit(label):
        if progress is not None:
            progress(label, perf_counter() - started)

    store.ensure_dataflow_tier()
    tier_done = perf_counter()
    _emit("dataflow tier")
    requested = lifetime_engine or os.environ.get(
        "LACHESIS_LIFETIME_ENGINE", _DEFAULT_LIFETIME_ENGINE)
    if requested not in {"legacy", "shadow", "object"}:
        raise ValueError(
            "LACHESIS_LIFETIME_ENGINE must be one of legacy, shadow, or object")
    # Pass 3 is a language-neutral semantic pipeline.  Frontends select the
    # appropriate catalog/normalizer and contribute their own graph facts; the
    # scheduler, Claus graph, and matcher must not make C the dispatch gate.
    object_requested = requested != "legacy"
    if object_requested:
        F, succ, analysis_graph = build_F(store, lang=lang, return_graph=True)
    else:
        F, succ = build_F(store, lang=lang)
        analysis_graph = None
    cached_coverage = getattr(store, "_pass3_coverage_cache", None)
    if (cached_coverage is not None and cached_coverage[0] is F
            and cached_coverage[1] is succ):
        coverage = cached_coverage[2]
    else:
        coverage = CoverageScheduler(F, succ).plan()
    projection_done = perf_counter()
    _emit("projection")
    summaries = _summaries_for(F, succ)
    legacy_summaries_done = perf_counter()
    _emit("summaries")
    # The semantic graph is the production lifetime substrate.  Keep the old
    # typestate renderer for legacy/shadow operation and for an explicit
    # fallback only; object mode still uses its reach skeletons for Atropos's
    # non-lifetime evaluators.
    skeletons = ([] if object_requested else
                 build_skeletons(F, summaries, lang=lang, include_typestate=True))
    skeletons_done = perf_counter()

    lifetime = {"requested": requested, "active": "legacy", "available": False}
    legacy_leads = None
    legacy_fallback_skeletons = []
    leads = []
    if object_requested:
        object_functions = _lifetime_slice(F, succ, lang=lang)
        object_succ = {
            name: [callee for callee in succ.get(name, ()) if callee in object_functions]
            for name in object_functions
        }
        from .emit import _native_object_substrate
        if _native_object_substrate(analysis_graph):
            object_result = analyze_object_lifetimes(
                store, object_functions, object_succ, lang=lang, graph=analysis_graph,
                workers=workers, deadline=deadline)
        else:
            # Frontends without declaration-rooted heap roles still participate in
            # Pass 3 through the generic F-IR semantic graph.  Do not route them
            # through the C-shaped object analyzer and call its substrate failure a
            # coverage result; the graph/matcher remains useful at the facts the
            # frontend actually emitted.
            object_result = ObjectLifetimeResult(
                (), {}, {
                    "backend": "frontend-ir",
                    "analyzed": 0,
                    "unsafe_functions": [],
                    "seed_unsafe_functions": [],
                    "unsafe_object_flow": {},
                    "unplaced": 0,
                    "unplaced_functions": {},
                    "capped": [],
                    "widenings": 0,
                    "transfers": 0,
                    "total_seconds": 0.0,
                }, {})
        # The semantic skeleton is deliberately built over the lifecycle/sink slice,
        # not over every translated function.  Give Claus the matching coverage plan;
        # passing the whole-program plan here would mark functions absent from the
        # skeleton as covered and make Pass 3's convergence claim unsound.
        semantic_coverage = CoverageScheduler(object_functions, object_succ).plan()
        # Keep the fragment store on the loaded graph session so repeated Pass 3
        # requests can reuse covered semantic regions.  The store key fingerprints
        # rebuilt summaries, so this is safe across fresh F dictionaries as long as
        # the underlying graph and semantic inputs remain unchanged.
        claus = getattr(store, "_pass3_claus", None)
        if claus is None:
            claus = Claus()
            store._pass3_claus = claus
        # A graph-backed session gets a reusable semantic-fragment sidecar.  The
        # FragmentStore still validates semantic fingerprints before accepting
        # anything, so an older graph or changed translator input is a miss rather
        # than a false coverage claim. In-memory stores remain purely in-memory.
        # The semantic snapshot is a large JSON serialization of the whole Claus
        # graph.  On a cold full-graph pass it can exceed a gigabyte and take longer
        # than the analysis itself, so it is an explicit opt-in cache rather than
        # part of the timing-critical path.  The compact Pass-1 structural sidecar
        # remains automatic and is what Pass 3 needs for cold substrate loading.
        if snapshot is None:
            snapshot_enabled = os.environ.get("LACHESIS_PASS3_SNAPSHOT", "").lower() in {
                "1", "true", "yes", "on"
            }
        else:
            snapshot_enabled = bool(snapshot)
        snapshot_path = (f"{store.graph_path}.pass3.json"
                         if snapshot_enabled and getattr(store, "graph_path", None)
                         else None)
        if snapshot_path and not getattr(store, "_pass3_snapshot_loaded", False):
            claus.fragments.load_snapshot(
                snapshot_path, F, lang, analysis_graph,
                object_result.summaries, summaries, object_result.artifacts)
            store._pass3_snapshot_loaded = True
        semantic_build_started = perf_counter()
        semantic_graph = claus.build(
            store, F, succ, lang=lang, graph=analysis_graph,
            summaries=object_result.summaries, coverage=semantic_coverage,
            reach_summaries=summaries, state_artifacts=object_result.artifacts,
            cfgs=object_result.cfgs)
        semantic_build_done = perf_counter()
        _emit("semantic graph")
        if snapshot_path:
            claus.fragments.save_snapshot(snapshot_path)
        semantic_match_started = perf_counter()
        semantic_leads = match_graph(semantic_graph)
        semantic_match_done = perf_counter()
        _emit("matching")
        # The projection already paid to materialize the disk graph. Reuse that same
        # in-memory index for the legacy coverage fallback instead of issuing another
        # whole-graph set of Kuzu scans merely to project CFG edges.
        if analysis_graph is not store.graph and not hasattr(analysis_graph, "nodes_of_kind"):
            from lachesis.nav.graph_store import GraphStore
            fallback_store = GraphStore(analysis_graph)
        else:
            fallback_store = store
        diagnostics = object_result.diagnostics
        unsafe = set(diagnostics.get("unsafe_functions", ()))
        # Object mode is fully untrusted only where the function's OWN analysis failed
        # (seed-unsafe); propagation-only-unsafe functions keep their object leads and are
        # filtered per-object by the object-flow map. Legacy fallback covers seed-unsafe.
        seed_unsafe = set(diagnostics.get("seed_unsafe_functions", unsafe))
        if requested == "shadow":
            # Shadow mode is an explicit differential, so it must materialize
            # the legacy stream even when object analysis has no fallback
            # functions.  Otherwise the comparison silently becomes
            # legacy-empty versus semantic and cannot audit recall.  Restrict
            # the diagnostic to the same source-rooted lifecycle slice as the
            # production semantic graph; unrelated sink-only functions do not
            # contribute lifetime recall and can make the old renderer explode
            # in size on mature graphs.
            legacy_functions = {name: F[name] for name in object_functions}
            legacy_summaries = {name: summaries.get(name, ())
                                for name in object_functions}
            skeletons = build_skeletons(legacy_functions, legacy_summaries, lang=lang,
                                        include_typestate=True)
        if seed_unsafe and requested == "object":
            # Re-enable the compatibility typestate stream only for functions
            # whose semantic object analysis could not produce a trustworthy
            # graph. Healthy object-mode paths never depend on the old flow.
            legacy_functions = {name: F[name] for name in seed_unsafe if name in F}
            legacy_summaries = {name: summaries.get(name, ())
                                for name in legacy_functions}
            skeletons = build_skeletons(F, summaries, lang=lang, include_typestate=True)
            legacy_fallback_skeletons = build_skeletons(
                legacy_functions, legacy_summaries, lang=lang, include_typestate=True)
        object_flow = diagnostics.get("unsafe_object_flow", {})
        covered = set(F) - seed_unsafe
        if requested == "shadow":
            legacy_leads = match_all(skeletons, cfg=cfg_bundle(fallback_store))
            leads, differential = _select_lifetime_leads(
                legacy_leads, object_result.leads, requested, covered_entries=covered,
                object_flow=object_flow)
        else:
            fallback_tokens = sum(len(skeleton.get("tokens", ()))
                                 for skeleton in legacy_fallback_skeletons)
            fallback_cfg = (cfg_bundle(fallback_store)
                            if fallback_tokens <= 100_000 and seed_unsafe else None)
            if seed_unsafe and not legacy_fallback_skeletons:
                legacy_functions = {name: F[name] for name in seed_unsafe if name in F}
                legacy_summaries = {name: summaries.get(name, ())
                                    for name in legacy_functions}
                legacy_fallback_skeletons = build_skeletons(
                    legacy_functions, legacy_summaries, lang=lang, include_typestate=True)
            # These functions are already outside the trustworthy object-analysis
            # set.  Use the legacy flat fallback rather than replaying the full CFG
            # parent-resolution automaton over their potentially enormous streams;
            # the flat may-analysis is conservative for this compatibility path.
            legacy_leads = _match_object_mode_legacy(
                legacy_fallback_skeletons, fallback_cfg, seed_unsafe)
            # The frozen graph/matcher is now the production lifetime path.  Keep the old
            # matcher only for non-lifetime reach leads and as a diagnostic fallback for
            # functions whose object projection could not be emitted.
            # Atropos sink observations now live in the semantic graph.  The
            # compatibility matcher contributes only lifetime fallback leads
            # for functions whose object analysis failed.
            reach_leads = []
            fallback_lifetime = [lead for lead in legacy_leads
                                 if lead.get("pattern") in _LIFETIME_PATTERNS
                                 and lead.get("entry") in seed_unsafe]
            # Object mode is source-rooted semantic-graph production.  A failed
            # object projection is reported in diagnostics, not silently converted
            # back into the legacy name-keyed lifetime verdicts.
            leads = fallback_lifetime + semantic_leads
            differential = {
                "computed": False,
                "reason": "set LACHESIS_LIFETIME_ENGINE=shadow for a full differential",
                "object": sum(lead.get("pattern") in _LIFETIME_PATTERNS
                              for lead in object_result.leads
                              if lead.get("entry") in covered),
                "legacy_fallback": sum(lead.get("pattern") in _LIFETIME_PATTERNS
                                       for lead in legacy_leads),
            }
        lifetime.update({
            "active": "object" if requested == "object" else "legacy",
            "available": True, "differential": differential,
            # A deadline that fired inside object analysis leaves this True and the
            # leads partial; callers surface it so an empty/short result is never read
            # as "clean". Absent deadline -> always False (the historical unbounded run).
            "timed_out": bool(diagnostics.get("timed_out")),
            "diagnostics": diagnostics,
            "fallback_functions": sorted(seed_unsafe),
            "candidate_functions": len(object_functions),
            "semantic_graph_nodes": len(semantic_graph.nodes),
            "semantic_graph_edges": sum(len(edges) for edges in semantic_graph.edges.values()),
            "semantic_leads": len(semantic_leads),
            "coverage": semantic_graph.coverage,
        })
    else:
        legacy_leads = match_all(skeletons, cfg=cfg_bundle(store))
        leads = legacy_leads
    finished = perf_counter()
    timings = {
        "dataflow_tier_seconds": round(tier_done - started, 6),
        "projection_seconds": round(projection_done - tier_done, 6),
        "legacy_summary_seconds": round(legacy_summaries_done - projection_done, 6),
        "skeleton_seconds": round(skeletons_done - legacy_summaries_done, 6),
        "matching_seconds": round(finished - skeletons_done, 6),
        "total_seconds": round(finished - started, 6),
    }
    if object_requested:
        timings.update({
            "semantic_build_seconds": round(
                locals().get("semantic_build_done", finished)
                - locals().get("semantic_build_started", finished), 6),
            "semantic_match_seconds": round(
                locals().get("semantic_match_done", finished)
                - locals().get("semantic_match_started", finished), 6),
        })
    return {"F": F, "succ": succ, "summaries": summaries,
            "skeletons": skeletons, "semantic_graph": locals().get("semantic_graph"),
            "coverage": locals().get("coverage"),
            "leads": leads, "lifetime": lifetime,
            "timings": timings}
