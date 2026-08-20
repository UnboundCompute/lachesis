#!/usr/bin/env python3
"""Whole-graph driver -- run the flow pass over an already-loaded Lachesis store.

One call returns the full bundle so callers (the CLI in walk.py, the MCP tool) share a
single code path: translate -> traverse+order+summarise -> skeletons -> shape leads.
"""
import os
from time import perf_counter

from .translate import build_F
from .skeleton import build_skeletons, _summaries_for
from .match import match_all, match_leak, match_reach, match_typestate
from .cfg import cfg_bundle
from .object_lifetime import analyze_object_lifetimes


_LIFETIME_PATTERNS = {"double-free", "use-after-free"}
_DEFAULT_LIFETIME_ENGINE = "object"


def _apply_owned_return_contracts(F, contracts):
    """Turn opaque ``returns=owned`` facts into alloc events on assigned results.

    Function bodies remain authoritative: a contract whose name is defined in ``F`` is
    ignored here, matching the object summary rule.  The graph itself is untouched; this
    augments only the per-run flow IR consumed by summaries and skeletons.
    """
    owned = {
        contract.name for contract in contracts
        if getattr(contract.returns, "value", contract.returns) == "owned"
        and contract.name not in F
    }
    if not owned:
        return ()
    for function in F.values():
        events = function["events"]
        seen = {(event.get("kind"), event.get("var"), event.get("node"))
                for event in events}
        for assign in function.get("assigns", ()):
            if assign.get("callee") not in owned:
                continue
            key = ("alloc", assign.get("var"), assign.get("node"))
            if key not in seen:
                events.append({"kind": "alloc", "var": assign.get("var"),
                               "line": assign.get("line"), "node": assign.get("node")})
                seen.add(key)
    return tuple(sorted(owned))


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


def _manifest_config(manifest):
    """Extract the run knobs a manifest contributes, and an audit of each.

    Returns ``(engine, extra_alloc, extra_dealloc, max_disjuncts, contracts, applied)``
    where ``applied`` is a per-knob log so a run summary can show what the manifest changed
    and -- critically -- what it declared that has no effect yet (no silent truncation:
    a config knob that quietly does nothing is exactly the backdoor a facts-file must
    not become)."""
    applied = {}
    if manifest is None:
        return None, (), (), None, (), applied
    mem = manifest.project.memory
    analysis = manifest.analysis
    contracts = manifest.project.functions
    if mem.alloc:
        applied["memory.alloc"] = f"+{len(mem.alloc)} allocator name(s): {list(mem.alloc)}"
    if mem.free:
        applied["memory.free"] = f"+{len(mem.free)} free name(s): {list(mem.free)}"
    if contracts:
        applied["functions"] = (
            f"{len(contracts)} function contract(s): {[c.name for c in contracts]}")
    if analysis.engine:
        applied["analysis.engine"] = f"engine={analysis.engine} (manifest)"
    if analysis.disjunct_cap is not None:
        applied["analysis.disjunct_cap"] = f"solver disjunct cap -> {analysis.disjunct_cap}"
    if analysis.timeout_per_fn is not None:
        # Declared but not consumed: the object engine caps by disjunct/run counts, not
        # wall-clock. Surface it rather than silently ignore it.
        applied["analysis.timeout_per_fn"] = (
            f"declared {analysis.timeout_per_fn}s but NOT enforced "
            "(engine caps by disjunct/run count, no wall-clock timeout yet)")
    return (analysis.engine, mem.alloc, mem.free, analysis.disjunct_cap, contracts, applied)


def run_pass(store, lang="c", lifetime_engine=None, manifest=None):
    """Return {F, succ, summaries, skeletons, leads, lifetime} for an opened GraphStore.

    The store's whole-graph value-flow tier is ensured once (cached to disk), then every
    later stage reads only the projected IR -- never the graph again. The one exception is
    the CFG bundle (successor edges + node resolver), projected once here so the typestate
    matcher's temporal shapes are path-sensitive over the real control-flow graph.

    C double-free/UAF leads use object identity by default. ``lifetime`` includes the
    bounded legacy differential and coverage diagnostics; functions with no complete
    object analysis retain legacy leads. Set ``LACHESIS_LIFETIME_ENGINE=shadow`` to run
    both without changing output, or ``legacy`` for an operational rollback.

    A ``manifest`` (:class:`lachesis.manifest.Manifest`) contributes per-target facts and
    run config: ``memory.alloc``/``free`` extend the lifecycle vocabulary, and the
    ``analysis`` block can pick the engine and the solver disjunct cap. Every knob it
    applies is recorded in ``lifetime['applied_config']`` -- nothing is silently dropped.
    Explicit arguments still win over the manifest, which wins over the environment."""
    started = perf_counter()
    store.ensure_dataflow_tier()
    tier_done = perf_counter()
    (cfg_engine, extra_alloc, extra_dealloc,
     cfg_disjunct, contracts, applied_config) = _manifest_config(manifest)
    requested = lifetime_engine or cfg_engine or os.environ.get(
        "LACHESIS_LIFETIME_ENGINE", _DEFAULT_LIFETIME_ENGINE)
    if requested not in {"legacy", "shadow", "object"}:
        raise ValueError(
            "lifetime engine must be one of legacy, shadow, or object")
    object_requested = lang.lower() == "c" and requested != "legacy"
    if object_requested:
        F, succ, analysis_graph = build_F(
            store, lang=lang, return_graph=True,
            extra_alloc=extra_alloc, extra_dealloc=extra_dealloc)
    else:
        F, succ = build_F(
            store, lang=lang, extra_alloc=extra_alloc, extra_dealloc=extra_dealloc)
        analysis_graph = None
    owned_alloc = _apply_owned_return_contracts(F, contracts)
    projection_done = perf_counter()
    summaries = _summaries_for(F, succ)
    legacy_summaries_done = perf_counter()
    skeletons = build_skeletons(F, summaries, lang=lang)
    skeletons_done = perf_counter()

    lifetime = {"requested": requested, "active": "legacy", "available": False,
                "applied_config": applied_config}
    legacy_leads = None
    leads = []
    if object_requested:
        object_result = analyze_object_lifetimes(
            store, F, succ, lang=lang, graph=analysis_graph,
            extra_alloc=tuple(extra_alloc) + owned_alloc,
            extra_dealloc=extra_dealloc,
            max_disjuncts=cfg_disjunct, contracts=contracts)
        # The projection already paid to materialize the disk graph. Reuse that same
        # in-memory index for the legacy coverage fallback instead of issuing another
        # whole-graph set of Kuzu scans merely to project CFG edges.
        if analysis_graph is not store.graph:
            from lachesis.nav.graph_store import GraphStore
            fallback_store = GraphStore(analysis_graph)
        else:
            fallback_store = store
        diagnostics = object_result.diagnostics
        if manifest is not None:
            from lachesis.manifest.validate import validate_contract_effects
            effect_report = validate_contract_effects(manifest, object_result.summaries)
            lifetime["semantic_warnings"] = [
                {"location": check.location, "symbol": check.symbol,
                 "status": check.status.value, "detail": check.detail}
                for check in effect_report.warnings
            ]
        unsafe = set(diagnostics.get("unsafe_functions", ()))
        # Object mode is fully untrusted only where the function's OWN analysis failed
        # (seed-unsafe); propagation-only-unsafe functions keep their object leads and are
        # filtered per-object by the object-flow map. Legacy fallback covers seed-unsafe.
        seed_unsafe = set(diagnostics.get("seed_unsafe_functions", unsafe))
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
            leads, _ = _select_lifetime_leads(
                legacy_leads, object_result.leads, requested, covered_entries=covered,
                object_flow=object_flow)
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
            "skeletons": skeletons, "leads": leads, "lifetime": lifetime,
            "timings": timings}
