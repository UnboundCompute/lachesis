#!/usr/bin/env python3
"""Native Pass-2/Pass-3 entrypoint.

The engine boundary is deliberately small: Rust consumes the binary Pass-1 substrate,
produces the semantic graph, and returns compact protobuf-derived objects. The former
Python graph translator, summary composer, typestate renderer, and compatibility
fallback are not part of this module anymore.
"""
from __future__ import annotations

from time import perf_counter

from .native_translate import (
    build_native_match_result, build_native_semantic_graph, native_match_leads,
    native_semantic_sidecar_path,
)


_DEFAULT_LIFETIME_ENGINE = "rust"


def run_pass(store, lang="mixed", *, workers=None,
             snapshot=None, deadline=None, progress=None):
    """Run the native semantic engine over a store-backed binary substrate.

    ``lang`` remains part of the internal catalog/report contract, but the substrate is
    language-neutral and is scanned once for mixed-language stores.  Engine selection is
    intentionally not an argument: the only engine is the native Rust engine.
    ``workers``, ``snapshot``, and ``deadline`` are accepted for API compatibility;
    scheduling and persistence belong to the Rust engine and its sidecars.
    """
    requested = _DEFAULT_LIFETIME_ENGINE

    started = perf_counter()
    if progress is not None:
        progress("native semantic graph", 0.0)
    semantic_graph = build_native_semantic_graph(store, lang=lang)
    if progress is not None:
        progress("native matching", perf_counter() - started)
    match_result = build_native_match_result(native_semantic_sidecar_path(store))
    leads = native_match_leads(match_result)
    finished = perf_counter()
    return {
        "F": None,
        "succ": {},
        "summaries": {},
        "skeletons": [],
        "semantic_graph": semantic_graph,
        "coverage": semantic_graph.coverage,
        "leads": leads,
        "lifetime": {
            "requested": requested,
            "active": "rust",
            "available": True,
            "timed_out": False,
            "diagnostics": {
                "backend": "rust-semantic",
                "analyzed": len(semantic_graph.nodes),
            },
            "semantic_graph_nodes": len(semantic_graph.nodes),
            "semantic_graph_edges": sum(
                len(edges) for edges in semantic_graph.edges.values()),
            "semantic_leads": len(leads),
            "coverage": semantic_graph.coverage,
        },
        "timings": {
            "dataflow_tier_seconds": 0.0,
            "projection_seconds": 0.0,
            "legacy_summary_seconds": 0.0,
            "skeleton_seconds": 0.0,
            "matching_seconds": round(finished - started, 6),
            "total_seconds": round(finished - started, 6),
        },
    }
