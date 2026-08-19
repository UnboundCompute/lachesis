"""Project manifest (``lachesis.toml``): declared facts + run configuration.

A manifest lets a target declare ground truth the analysis cannot reliably infer —
its build variant, alloc/free vocabulary, entrypoints, trust boundaries, and expert
facts about opaque functions and dispatch seams — so the pipeline runs
deterministically instead of guessing.  Facts are validated against the graph where
possible (:mod:`lachesis.manifest.validate`); run configuration is applied and logged.
"""
from __future__ import annotations

from .loader import (
    MANIFEST_NAME,
    ManifestError,
    discover_manifest,
    load_manifest,
    load_or_discover,
    parse_manifest,
)
from .schema import (
    AliasFacts,
    AnalysisConfig,
    Build,
    FunctionContract,
    Manifest,
    Memory,
    Ownership,
    ProjectFacts,
    Source,
    Surface,
    Trust,
    UntrustedInput,
)

__all__ = [
    "MANIFEST_NAME",
    "ManifestError",
    "discover_manifest",
    "load_manifest",
    "load_or_discover",
    "parse_manifest",
    "AliasFacts",
    "AnalysisConfig",
    "Build",
    "FunctionContract",
    "Manifest",
    "Memory",
    "Ownership",
    "ProjectFacts",
    "Source",
    "Surface",
    "Trust",
    "UntrustedInput",
]
