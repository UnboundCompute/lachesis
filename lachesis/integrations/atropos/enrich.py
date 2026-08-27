"""Fold the Atropos taint catalog onto an already-built graph.

This is the one entry point a host (the query CLI, the MCP server, a test) calls
to turn a plain graph into a *taint-aware* one using the Atropos models. Rust owns
the binary graph projection and catalog matching; this module only exposes the
native result to existing Python consumers.

It preserves the repository boundary in both directions. The engine never takes a
hard dependency on Atropos: the catalog and its binder are *located* at runtime
(an env override, a sibling checkout, the default project path) and loaded by
path, so a tree without Atropos simply gets the graph back unchanged. And Atropos
never learns about the engine: all it ever sees is the neutral index dict.

The base graph -- its build, its store, its size -- is untouched. Everything here
is an additive :class:`GraphDelta` folded over a graph the caller already holds.
"""
from __future__ import annotations

import os
import sys
import tempfile
from time import perf_counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lachesis.integrations.atropos.overlay import (
    AtroposOverlay, stamps_from_report)

#: Frontend id token found in node ids -> the Atropos catalog languages that can
#: bind against that frontend's graph. A TypeScript graph accepts JS models too.
_FRONTEND_LANGUAGES = {
    ":clang-c:": ("c",),
    ":cpython-ast:": ("python",),
    ":typescript-compiler-api:": ("typescript", "javascript"),
}


def locate_atropos(explicit: Optional[str] = None) -> Optional[Path]:
    """Find an Atropos checkout without importing it. ``None`` if absent."""
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("ATROPOS_ROOT")
    if env:
        candidates.append(Path(env))
    # arachne/lachesis/integrations/atropos/enrich.py -> parents[3] is the repo,
    # its parent is the workspace that also holds a sibling ``atropos`` checkout.
    candidates.append(Path(__file__).resolve().parents[3].parent / "atropos")
    candidates.append(Path.home() / "project" / "unboundcompute" / "atropos")
    for candidate in candidates:
        if (candidate / "models").is_dir():
            return candidate
    return None


def _languages_present(graph: Dict[str, Any]) -> List[str]:
    """Which catalog languages can bind, inferred from frontend id tokens."""
    langs: List[str] = []
    seen_tokens = set()
    for node in graph.get("nodes", ()):
        node_id = node.get("id", "")
        for token, catalog_langs in _FRONTEND_LANGUAGES.items():
            if token in seen_tokens:
                continue
            if token in node_id:
                seen_tokens.add(token)
                for lang in catalog_langs:
                    if lang not in langs:
                        langs.append(lang)
        if len(seen_tokens) == len(_FRONTEND_LANGUAGES):
            break
    return langs


def _phase_timing(label: str, started: float) -> None:
    if os.environ.get("LACHESIS_ATROPOS_TIMINGS") == "1":
        print(f"[lachesis atropos] {label}: {perf_counter() - started:.3f}s",
              file=sys.stderr, flush=True)


def atropos_enrich(
    graph: Dict[str, Any], *, atropos_root: Optional[str] = None,
    complete_dataflow: bool = True, symbol_index_source: Any = None,
    compact_structural: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return ``(taint_aware_graph, summary)``; graph unchanged if Atropos absent.

    ``summary`` reports what happened -- the catalog root used, per-language bind
    counts, how many role nodes were stamped -- so a host can surface it and a
    silent no-op (no Atropos, nothing bound) is never mistaken for coverage.
    """
    root = locate_atropos(atropos_root)
    if root is None:
        return graph, {"applied": False, "reason": "atropos-not-found"}

    started = perf_counter()
    languages = _languages_present(graph)
    _phase_timing("language detection", started)
    if not languages:
        return graph, {"applied": False, "reason": "no-recognized-frontend",
                       "atropos_root": str(root)}

    started = perf_counter()
    from lachesis.integrations.atropos.models import load_models

    models = load_models(root / "models")
    models_by_id = {model["id"]: model for model in models}
    _phase_timing("catalog load", started)

    stamps: List[dict] = []
    per_language: Dict[str, Any] = {}
    native_path_report = None
    native_path_output = None
    if symbol_index_source is not None:
        # The complete Pass-1 stream is already the native binder's input. Use
        # it directly when available instead of first building a Python
        # canonical callsite index for the whole graph.
        base = (getattr(symbol_index_source, "_pass3_cache_base", None)
                or getattr(symbol_index_source, "_db_dir", None))
        if base:
            from lachesis.nav.dataflow.substrate import pass2_input_cache_path
            native_input = pass2_input_cache_path(base)
            if os.environ.get("LACHESIS_ATROPOS_TIMINGS") == "1":
                print(f"[lachesis atropos] native path candidate: {native_input}",
                      file=sys.stderr, flush=True)
            if native_input.is_file():
                try:
                    from .native_bind import bind_path
                    from .native_bind import compiled_catalog
                    catalog_path = compiled_catalog(root, base)
                    with tempfile.NamedTemporaryFile(prefix="lachesis-bind-",
                                                     suffix=".pb", delete=False) as output:
                        native_path_output = Path(output.name)
                    native_path_report = bind_path(native_input, catalog_path,
                                                   native_path_output)
                except (OSError, RuntimeError, ValueError) as error:
                    # A Pass-1 binary input is the current store contract. Do
                    # not silently re-enter the old Python canonical-index
                    # binder if the native implementation fails: that creates
                    # two production paths and hides native regressions.
                    raise RuntimeError(
                        f"native catalog binding failed for {native_input}: {error}"
                    ) from error
                finally:
                    if native_path_output is not None:
                        try:
                            native_path_output.unlink()
                        except OSError:
                            pass
    if native_path_report is not None:
        # The path report contains all catalog languages. Preserve the existing
        # summary shape while using the one Rust bind result for every language.
        stamps.extend(stamps_from_report(native_path_report, models_by_id))
        for language in languages:
            rows = [row for row in native_path_report.get("results", ())
                    if (models_by_id.get(row.get("model_id")) or {}).get("language")
                    == language]
            counts: Dict[str, int] = {}
            unbound: List[dict] = []
            for row in rows:
                status = row.get("status", "unknown")
                counts[status] = counts.get(status, 0) + 1
                if status != "bound":
                    model = models_by_id.get(row.get("model_id")) or {}
                    unbound.append({
                        "model_id": row.get("model_id"), "method": row.get("method"),
                        "access_path": row.get("access_path"), "role": row.get("role"),
                        "kind": model.get("kind"), "status": status,
                        "detail": row.get("detail"),
                    })
            per_language[language] = {
                "callsites": sum(node.get("kind") in {"call", "construct"}
                                  for node in graph.get("nodes", ())),
                "bind": counts, "unbound": unbound,
            }
        if compact_structural and not complete_dataflow:
            # The native binder has already resolved attachments against the
            # complete Pass-1 stream.  In compact mode the caller keeps the
            # projection as its base and only needs the additive delta here;
            # rebuilding a graph-sized membership set and copying every
            # projection record defeats the path-based native handoff.
            known_node_ids = {
                stamp.get("value_id")
                for stamp in stamps
                if stamp.get("value_id") is not None
            }
            known_node_ids.update(
                stamp.get(endpoint)
                for stamp in stamps
                for endpoint in ("from", "to")
                if stamp.get(endpoint) is not None
            )
            delta = AtroposOverlay(stamps).delta_for_node_ids(known_node_ids)
            # This branch is consumed by Session._structural_bind, which
            # combines the delta with its narrow structural projection.  Keep
            # the return value delta-only so no second graph-sized Python copy
            # is created on the native path.
            graph = {"nodes": delta.nodes, "edges": delta.edges}
            role_nodes: Dict[str, int] = {}
            for node in delta.nodes:
                kind = node.get("kind", "?")
                role_nodes[kind] = role_nodes.get(kind, 0) + 1
            return graph, {
                "applied": True, "atropos_root": str(root),
                "languages": languages, "per_language": per_language,
                "stamps": len(stamps), "role_nodes": role_nodes,
            }
    if native_path_report is None:
        raise RuntimeError("Atropos binding requires a fresh binary Pass-1 sidecar and the native Rust binder")
    # Native Rust owns catalog matching. This projection only exposes its additive
    # stamps to an existing Python SDK graph view; it does not re-run matching.
    enriched = AtroposOverlay(stamps).enrich(graph)
    role_nodes: Dict[str, int] = {}
    for node in enriched.get("nodes", ()):
        if node.get("properties", {}).get("fact_origin") == "atropos-model":
            kind = node.get("kind", "?")
            role_nodes[kind] = role_nodes.get(kind, 0) + 1
    return enriched, {
        "applied": True,
        "atropos_root": str(root),
        "languages": languages,
        "per_language": per_language,
        "stamps": len(stamps),
        "role_nodes": role_nodes,
    }
