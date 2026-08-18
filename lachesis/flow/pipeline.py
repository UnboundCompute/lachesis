#!/usr/bin/env python3
"""Whole-graph driver -- run the flow pass over an already-loaded Lachesis store.

One call returns the full bundle so callers (the CLI in walk.py, the MCP tool) share a
single code path: translate -> traverse+order+summarise -> skeletons -> shape leads.
"""
import os

from .translate import build_F
from .skeleton import build_skeletons, _summaries_for
from .match import match_all
from .cfg import cfg_bundle
from .object_lifetime import analyze_object_lifetimes


_LIFETIME_PATTERNS = {"double-free", "use-after-free"}
_DEFAULT_LIFETIME_ENGINE = "object"


def _lead_key(lead):
    # The two engines encode object display names differently; a differential is
    # about whether they agree on the finding site, not renderer spelling.
    return (lead.get("pattern"), lead.get("entry"), lead.get("line"))


def _select_lifetime_leads(legacy, object_identity, mode, covered_entries=None):
    preserved = [lead for lead in legacy if lead.get("pattern") not in _LIFETIME_PATTERNS]
    legacy_lifetime = [lead for lead in legacy if lead.get("pattern") in _LIFETIME_PATTERNS]
    object_lifetime = list(object_identity)
    if mode == "object":
        covered = set(covered_entries) if covered_entries is not None else None
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
    store.ensure_dataflow_tier()
    F, succ = build_F(store, lang=lang)
    summaries = _summaries_for(F, succ)
    skeletons = build_skeletons(F, summaries, lang=lang)
    legacy_leads = match_all(skeletons, cfg=cfg_bundle(store))
    requested = lifetime_engine or os.environ.get(
        "LACHESIS_LIFETIME_ENGINE", _DEFAULT_LIFETIME_ENGINE)
    if requested not in {"legacy", "shadow", "object"}:
        raise ValueError(
            "LACHESIS_LIFETIME_ENGINE must be one of legacy, shadow, or object")

    lifetime = {"requested": requested, "active": "legacy", "available": False}
    leads = legacy_leads
    if lang.lower() == "c" and requested != "legacy":
        object_result = analyze_object_lifetimes(store, F, succ, lang=lang)
        diagnostics = object_result.diagnostics
        unsafe = (set(diagnostics.get("cfg_failures", {}))
                  | set(diagnostics.get("unplaced_functions", {}))
                  | set(diagnostics.get("capped", ())))
        covered = set(F) - unsafe
        leads, differential = _select_lifetime_leads(
            legacy_leads, object_result.leads, requested, covered_entries=covered)
        lifetime.update({
            "active": "object" if requested == "object" else "legacy",
            "available": True, "differential": differential,
            "diagnostics": diagnostics,
            "fallback_functions": sorted(unsafe),
        })
    return {"F": F, "succ": succ, "summaries": summaries,
            "skeletons": skeletons, "leads": leads, "lifetime": lifetime}
