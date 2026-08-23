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
from .object_lifetime import analyze_object_lifetimes
from .semantic_graph import match_graph
from .fragment_store import Claus
from .coverage import CoverageScheduler


_LIFETIME_PATTERNS = {"double-free", "use-after-free"}
_DEFAULT_LIFETIME_ENGINE = "object"


def _lifetime_slice(F, succ):
    """Restrict object analysis to the call-graph region carrying lifecycle events."""
    seeds = {
        name for name, function in F.items()
        if any(event.get("kind") in {"alloc", "free", "escape"}
               for event in function.get("events", ()))
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
            if neighbour in F and neighbour not in region:
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


def run_pass(store, lang="c", lifetime_engine=None):
    """Return {F, succ, summaries, skeletons, leads, lifetime} for an opened GraphStore.

    The store's whole-graph value-flow tier is ensured once (cached to disk), then every
    later stage reads only the projected IR -- never the graph again. The one exception is
    the CFG bundle (successor edges + node resolver), projected once here so the typestate
    matcher's temporal shapes are path-sensitive over the real control-flow graph.

    C double-free/UAF leads use object identity by default. ``lifetime`` includes the
    bounded legacy differential and coverage diagnostics; functions with no complete
    object analysis retain legacy leads. Set ``LACHESIS_LIFETIME_ENGINE=shadow`` to run
    both without changing output, or ``legacy`` for an operational rollback."""
    started = perf_counter()
    store.ensure_dataflow_tier()
    tier_done = perf_counter()
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
    coverage = CoverageScheduler(F, succ).plan()
    projection_done = perf_counter()
    summaries = _summaries_for(F, succ)
    legacy_summaries_done = perf_counter()
    # The semantic graph is the production lifetime substrate.  Keep the old
    # typestate renderer for legacy/shadow operation and for an explicit
    # fallback only; object mode still uses its reach skeletons for Atropos's
    # non-lifetime evaluators.
    skeletons = build_skeletons(
        F, summaries, lang=lang, include_typestate=not object_requested or requested == "shadow")
    skeletons_done = perf_counter()

    lifetime = {"requested": requested, "active": "legacy", "available": False}
    legacy_leads = None
    leads = []
    if object_requested:
        object_functions = _lifetime_slice(F, succ)
        object_succ = {
            name: [callee for callee in succ.get(name, ()) if callee in object_functions]
            for name in object_functions
        }
        object_result = analyze_object_lifetimes(
            store, object_functions, object_succ, lang=lang, graph=analysis_graph)
        semantic_coverage = CoverageScheduler(F, succ).plan(object_functions)
        semantic_graph = Claus().build(
            store, F, succ, lang=lang, graph=analysis_graph,
            summaries=object_result.summaries, coverage=semantic_coverage)
        semantic_leads = match_graph(semantic_graph)
        # The projection already paid to materialize the disk graph. Reuse that same
        # in-memory index for the legacy coverage fallback instead of issuing another
        # whole-graph set of Kuzu scans merely to project CFG edges.
        if analysis_graph is not store.graph:
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
        if seed_unsafe and requested == "object":
            # Re-enable the compatibility typestate stream only for functions
            # whose semantic object analysis could not produce a trustworthy
            # graph. Healthy object-mode paths never depend on the old flow.
            skeletons = build_skeletons(F, summaries, lang=lang, include_typestate=True)
        object_flow = diagnostics.get("unsafe_object_flow", {})
        covered = set(F) - seed_unsafe
        if requested == "shadow":
            legacy_leads = match_all(skeletons, cfg=cfg_bundle(fallback_store))
            leads, differential = _select_lifetime_leads(
                legacy_leads, object_result.leads, requested, covered_entries=covered,
                object_flow=object_flow)
        else:
            fallback_cfg = cfg_bundle(fallback_store) if seed_unsafe else None
            legacy_leads = _match_object_mode_legacy(skeletons, fallback_cfg, seed_unsafe)
            # The frozen graph/matcher is now the production lifetime path.  Keep the old
            # matcher only for non-lifetime reach leads and as a diagnostic fallback for
            # functions whose object projection could not be emitted.
            reach_leads = [lead for lead in legacy_leads
                           if lead.get("pattern") in {"reachability", "relational", "presence"}]
            # Object mode is source-rooted semantic-graph production.  A failed
            # object projection is reported in diagnostics, not silently converted
            # back into the legacy name-keyed lifetime verdicts.
            leads = reach_leads + semantic_leads
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
            "diagnostics": diagnostics,
            "fallback_functions": sorted(seed_unsafe),
            "candidate_functions": len(object_functions),
            "semantic_graph_nodes": len(semantic_graph.nodes),
            "semantic_graph_edges": sum(len(edges) for edges in semantic_graph.edges.values()),
            "semantic_leads": len(semantic_leads),
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
    return {"F": F, "succ": succ, "summaries": summaries,
            "skeletons": skeletons, "semantic_graph": locals().get("semantic_graph"),
            "coverage": locals().get("coverage"),
            "leads": leads, "lifetime": lifetime,
            "timings": timings}
