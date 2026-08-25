"""Fold the Atropos taint catalog onto an already-built graph.

This is the one entry point a host (the query CLI, the MCP server, a test) calls
to turn a plain enriched graph into a *taint-aware* one using the Atropos models.
It is the composition of the seam's three engine-neutral steps -- project the
graph to the neutral symbol index (:func:`canonical_index`), let the catalog bind
its models against that index, and stamp each resolved fact back onto the exact
node (:class:`AtroposOverlay`). By default it also runs the core value-flow
completion the C frontend needs (:class:`CCallResultDataflow`); catalog-only
consumers such as the candidate registry disable that step.

It preserves the repository boundary in both directions. The engine never takes a
hard dependency on Atropos: the catalog and its binder are *located* at runtime
(an env override, a sibling checkout, the default project path) and loaded by
path, so a tree without Atropos simply gets the graph back unchanged. And Atropos
never learns about the engine: all it ever sees is the neutral index dict.

The base graph -- its build, its store, its size -- is untouched. Everything here
is an additive :class:`GraphDelta` folded over a graph the caller already holds.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lachesis.integrations.atropos import canonical_index
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
        if (candidate / "tools" / "bind.py").exists():
            return candidate
    return None


def _load_binder(atropos_root: Path):
    spec = importlib.util.spec_from_file_location(
        "atropos_bind", str(atropos_root / "tools" / "bind.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def atropos_enrich(
    graph: Dict[str, Any], *, atropos_root: Optional[str] = None,
    complete_dataflow: bool = True, symbol_index_source: Any = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return ``(taint_aware_graph, summary)``; graph unchanged if Atropos absent.

    ``summary`` reports what happened -- the catalog root used, per-language bind
    counts, how many role nodes were stamped -- so a host can surface it and a
    silent no-op (no Atropos, nothing bound) is never mistaken for coverage.
    """
    from lachesis.core.overlays.registry import OverlayRegistry
    from lachesis.core.overlays.c_call_dataflow import CCallResultDataflow
    from lachesis.core.overlays.c_out_param_dataflow import COutParamWriteback
    from lachesis.core.overlays.c_return_dataflow import CReturnToCallsite

    root = locate_atropos(atropos_root)
    if root is None:
        return graph, {"applied": False, "reason": "atropos-not-found"}

    languages = _languages_present(graph)
    if not languages:
        return graph, {"applied": False, "reason": "no-recognized-frontend",
                       "atropos_root": str(root)}

    binder = _load_binder(root)
    models = list(binder.load_models(root / "models"))
    models_by_id = {model["id"]: model for model in models}

    stamps: List[dict] = []
    per_language: Dict[str, Any] = {}
    projection = None
    if symbol_index_source is not None:
        projection_fn = getattr(symbol_index_source, "atropos_projection", None)
        if projection_fn is not None:
            projection = projection_fn()
    canonical_projection = None
    for language in languages:
        lang_models = [m for m in models if m.get("language") == language]
        if not lang_models:
            continue
        # The graph projection is language-neutral: canonical_index's language argument
        # only stamps the output envelope, while the calls/edges scan is identical for
        # every catalog language. Build that million-node/two-million-edge projection
        # once and share its immutable callsite lists across the per-language binders.
        if canonical_projection is None:
            canonical_projection = canonical_index(
                projection if projection is not None else graph,
                language=language, source="lachesis",
            )
        index = {**canonical_projection, "language": language}
        report = None
        if os.environ.get("LACHESIS_NATIVE_ATROPOS") == "1":
            from lachesis.integrations.atropos.native_bind import bind_all as native_bind_all
            report = native_bind_all(lang_models, index)
        if report is None:
            report = binder.bind_all(lang_models, index)
        stamps.extend(stamps_from_report(report, models_by_id))
        counts: Dict[str, int] = {}
        unbound: List[dict] = []
        for row in report.get("results", []):
            status = row.get("status", "unknown")
            counts[status] = counts.get(status, 0) + 1
            if status != "bound":
                # Keep the exact model that failed to attach so the tool can *show*
                # every sink the catalog knows, not just a headcount of misses. This
                # is the worklist for strengthening the Atropos knowledge base.
                unbound.append({
                    "model_id": row.get("model_id"), "method": row.get("method"),
                    "access_path": row.get("access_path"), "role": row.get("role"),
                    # The catalog kind of the model that failed to attach, so a
                    # per-family constructor can scope its unbound-sink frontier to
                    # exactly its own kinds rather than the whole global roster.
                    "kind": (models_by_id.get(row.get("model_id")) or {}).get("kind"),
                    "status": status, "detail": row.get("detail"),
                })
        per_language[language] = {
            "callsites": len(index["callsites"]),
            "bind": counts,
            "unbound": unbound,
        }

    if not complete_dataflow:
        # Structural binding is additive: the catalog contributes only role nodes,
        # taint edges, and summary flow edges.  Every endpoint came from this
        # bounded neutral callsite projection, so validate against that projection
        # rather than constructing a million-entry GraphIndex and copying/sorting
        # the entire base graph just to append a tiny delta.
        known_node_ids = set()
        for callsite in (canonical_projection or {}).get("callsites", ()):
            known_node_ids.add(callsite.get("id"))
            known_node_ids.add(callsite.get("call_value_id"))
            known_node_ids.add(callsite.get("receiver_value_id"))
            known_node_ids.update(callsite.get("arg_value_ids") or ())
        known_node_ids.discard(None)
        delta = AtroposOverlay(stamps).delta_for_node_ids(known_node_ids)
        # Preserve the generic registry's idempotence when a caller reuses the
        # same in-memory graph.  Probe only the tiny delta identity set; do not
        # materialize a second graph-sized node/edge index.
        candidate_node_ids = {node["id"] for node in delta.nodes}
        existing_node_ids = {
            node.get("id") for node in graph.get("nodes", ())
            if node.get("id") in candidate_node_ids
        }
        delta.nodes = [node for node in delta.nodes
                       if node["id"] not in existing_node_ids]
        candidate_edge_keys = {
            (edge["kind"], edge["source"], edge["target"])
            for edge in delta.edges
        }
        existing_edge_keys = {
            (edge.get("kind"), edge.get("source"), edge.get("target"))
            for edge in graph.get("edges", ())
            if (edge.get("kind"), edge.get("source"), edge.get("target"))
            in candidate_edge_keys
        }
        delta.edges = [edge for edge in delta.edges
                       if (edge["kind"], edge["source"], edge["target"])
                       not in existing_edge_keys]
        if isinstance(graph.get("nodes"), list):
            graph["nodes"].extend(delta.nodes)
        else:
            graph["nodes"] = [*graph.get("nodes", ()), *delta.nodes]
        if isinstance(graph.get("edges"), list):
            graph["edges"].extend(delta.edges)
        else:
            graph["edges"] = [*graph.get("edges", ()), *delta.edges]
        role_nodes: Dict[str, int] = {}
        for node in delta.nodes:
            kind = node.get("kind", "?")
            role_nodes[kind] = role_nodes.get(kind, 0) + 1
        return graph, {
            "applied": True,
            "atropos_root": str(root),
            "languages": languages,
            "per_language": per_language,
            "stamps": len(stamps),
            "role_nodes": role_nodes,
        }

    registry = OverlayRegistry()
    if "c" in languages and complete_dataflow:
        # The C frontend links a call result to the variable it initializes by AST
        # only; without this the return-value sources/summaries can never flow.
        registry.register(CCallResultDataflow())
        # An argument the catalog marks as a *source* is an out-parameter the call
        # fills; the frontend wires only variable->use, so that write would strand
        # on the argument node. Flow it back into the buffer's other uses.
        out_param_sources = [
            s["value_id"] for s in stamps
            if s.get("role") == "source" and "value_id" in s
            and str(s.get("access_path") or "").startswith("Argument[")
        ]
        registry.register(COutParamWriteback(out_param_sources))
        # The frontend records what a function returns and what each callsite
        # invokes, but never links them, so a source obtained inside a wrapper
        # dies at its return. Flow every returned value to its callers' results.
        registry.register(CReturnToCallsite())
        # NB: the opt-in field-sensitive reaching-def tier (REACHING_DEF) is folded
        # by the canonical dataflow-tier builder (pipeline.enrich_graph), not here --
        # the taint tool reaches it via ensure_dataflow_tier before this fold, so
        # registering it again would double the edges.
    registry.register(AtroposOverlay(stamps))
    enriched = registry.enrich(graph)

    stamped = [n for n in enriched["nodes"]
               if n.get("properties", {}).get("fact_origin") == "atropos-model"]
    role_nodes: Dict[str, int] = {}
    for node in stamped:
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
