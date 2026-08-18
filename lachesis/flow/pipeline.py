#!/usr/bin/env python3
"""Whole-graph driver -- run the flow pass over an already-loaded Lachesis store.

One call returns the full bundle so callers (the CLI in walk.py, the MCP tool) share a
single code path: translate -> traverse+order+summarise -> skeletons -> shape leads.
"""
from .translate import build_F
from .skeleton import build_skeletons, _summaries_for
from .match import match_all
from .cfg import cfg_bundle


def run_pass(store, lang="c"):
    """Return {F, succ, summaries, skeletons, leads} for an opened GraphStore.

    The store's whole-graph value-flow tier is ensured once (cached to disk), then every
    later stage reads only the projected IR -- never the graph again. The one exception is
    the CFG bundle (successor edges + node resolver), projected once here so the typestate
    matcher's temporal shapes are path-sensitive over the real control-flow graph."""
    store.ensure_dataflow_tier()
    F, succ = build_F(store, lang=lang)
    summaries = _summaries_for(F, succ)
    skeletons = build_skeletons(F, summaries, lang=lang)
    leads = match_all(skeletons, cfg=cfg_bundle(store))
    return {"F": F, "succ": succ, "summaries": summaries,
            "skeletons": skeletons, "leads": leads}
