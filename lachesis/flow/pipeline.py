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
    build_native_match_result, ensure_native_semantic_sidecar,
    native_catalog_path, native_match_leads, native_semantic_sidecar_path,
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
    semantic_sidecar = ensure_native_semantic_sidecar(store, native_catalog_path(store))
    if progress is not None:
        progress("native matching", perf_counter() - started)
    match_result = build_native_match_result(semantic_sidecar, native_catalog_path(store))
    leads = native_match_leads(match_result)
    finished = perf_counter()
    # Completion is the Rust result's to report, not ours to assert. A function is
    # ``capped`` when its matcher exhausted the state budget (or its skeleton was
    # incomplete); any capped function means the semantic analysis did not fully
    # converge, so we must not stamp the run complete. ``timed_out`` is the honest
    # wall-clock signal: if the caller's cooperative budget expired by the time the
    # single native call returned, a more patient recompute may converge further --
    # the flow-bundle cache keys on exactly this to avoid inheriting a partial answer.
    capped_functions = sum(1 for function in match_result.functions
                           if getattr(function, "capped", False))
    converged = capped_functions == 0
    timed_out = bool(deadline is not None and deadline.expired())
    return {
        "F": None,
        "succ": {},
        "summaries": {},
        "skeletons": [],
        "semantic_graph": {
            "native_sidecar": str(native_semantic_sidecar_path(store)),
            "coverage": {"converged": converged},
        },
        "coverage": {"converged": converged},
        "leads": leads,
        "lifetime": {
            "requested": requested,
            "active": "rust",
            "available": True,
            "timed_out": timed_out,
            "diagnostics": {
                "backend": "rust-semantic",
                "analyzed_functions": len(match_result.functions),
                "capped_functions": capped_functions,
            },
            "semantic_graph_nodes": 0,
            "semantic_graph_edges": 0,
            "semantic_leads": len(leads),
            "coverage": {"converged": converged},
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
