"""Atropos taint-model overlay: stamp resolved catalog facts onto exact nodes.

This is the *enrich* half of the seam. The base graph is built exactly as it is
today; a separate enrich flow takes that already-built graph and folds this
overlay in as one additive :class:`GraphDelta` -- a handful of ``source``/``sink``
role nodes plus precise summary flow edges, each attached to the exact value node
a model resolved to. It never rewrites an existing node, so folding it costs only
what the delta is worth and leaves the base graph, its build time, and its size
untouched. It is meant to run after core value-flow enrichment and before
``TaintPropagation``, whose vocabulary it speaks.

The overlay does not resolve models and never imports the Atropos binder:
resolution is the catalog's own contract (a model + a neutral symbol index -> a
binding report with a per-model status). The engine's only job here is to
translate each *bound* fact into the graph vocabulary ``TaintPropagation``
already consumes:

* a ``kind="source"`` / ``kind="sink"`` node keyed by ``value_id`` (the exact
  resolved node), which taint reads directly; and
* a ``VALUE_FLOWS_TO`` edge for a summary's documented in->out flow, which taint
  traverses as an ordinary flow edge -- the precise replacement for the engine's
  conservative every-argument-flows-to-return default.

An unbound model stamps nothing: the report already recorded why (symbol-not-
found, ambiguous, arity-mismatch, unsupported-path), and a fact that did not
resolve to a verified node must never decorate the graph.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

from lachesis.core.composition import GraphDelta
from lachesis.core.identities import stable_id

#: Summary edges must be a flow kind TaintPropagation walks (see taint.py).
FLOW_KIND = "VALUE_FLOWS_TO"

#: All Atropos facts are stamped under one identity owner/namespace so they can
#: never collide with a frontend or core node id.
_OWNER = "runtime-model"


def stamps_from_report(report: Dict[str, Any],
                       models_by_id: Dict[str, dict]) -> List[dict]:
    """Translate a binder report's *bound* rows into engine-neutral stamps.

    A stamp is the minimal fact the overlay needs: the role, the model's
    ``kind``/``cwe``/``confidence`` for provenance, and either a target value
    node (source/sink) or a ``from``/``to`` pair (summary). This is the only
    place that reads the neutral attachment shape, which is part of the seam's
    documented contract, not of the engine's internals.
    """
    stamps: List[dict] = []
    for row in report.get("results", []):
        if row.get("status") != "bound":
            continue
        model = models_by_id.get(row["model_id"])
        if not model:
            continue
        role = model.get("role")
        for attachment in row.get("attachments", []):
            base = {
                "model_id": row["model_id"], "role": role,
                "kind": model.get("kind"), "cwe": model.get("cwe", []),
                "confidence": model.get("confidence", "medium"),
                "access_path": model.get("access_path"),
                # Allocation metadata is retained on the stamp so planners can
                # recover element counts without maintaining a second catalog.
                "element_count_arg": model.get("element_count_arg"),
            }
            edge = attachment.get("edge")
            if role == "summary" or edge:
                if not edge:
                    continue
                stamps.append({**base, "role": "summary",
                               "from": edge["from"], "to": edge["to"]})
            else:
                node = attachment.get("node")
                if not node:
                    continue
                stamps.append({**base, "value_id": node,
                               "callsite_id": attachment.get("callsite")})
    return stamps


class AtroposOverlay:
    """Fold resolved Atropos facts into a graph as one additive delta."""

    overlay_id = "atropos-taint-model"

    def __init__(self, stamps: Iterable[dict]) -> None:
        self._stamps: List[dict] = list(stamps)

    def minimal_index(self, graph: dict):
        """Build only the index surface this one-overlay fold needs.

        The generic registry index also builds by-kind and incoming adjacency
        buckets for arbitrary overlays. Atropos only validates node membership
        and deduplicates outgoing edges from resolved source values, so retaining
        those unrelated buckets is pure peak-RSS overhead.
        """
        from lachesis.core.overlays.registry import _MinimalOverlayIndex
        sources = {
            stamp.get("value_id") or stamp.get("from")
            for stamp in self._stamps
        }
        sources.update(stamp.get("from") for stamp in self._stamps
                       if stamp.get("from") is not None)
        # A repeated fold may encounter the role edges emitted by an earlier
        # fold. Include their deterministic role-node sources so the bounded
        # seed lookup preserves the generic registry's deduplication behavior.
        for stamp in self._stamps:
            if stamp.get("role") in ("source", "sink") and stamp.get("value_id"):
                sources.add(stable_id(
                    _OWNER, self.overlay_id, stamp["role"],
                    stamp["model_id"], stamp["value_id"],
                ))
        return _MinimalOverlayIndex(graph, sources)

    def applies(self, graph: dict, index: Any = None) -> bool:
        # Nothing resolved -> nothing to fold, and the registry then charges the
        # caller nothing for a pass that would add no node.
        return bool(self._stamps)

    def enrich(self, graph: dict, index: Any = None) -> GraphDelta:
        # OverlayRegistry already owns a node map for this graph. Reusing it avoids
        # allocating a second million-entry set just to validate resolved endpoints.
        # Keep the standalone fallback for direct overlay callers and tests.
        node_ids = (index.nodes if index is not None and hasattr(index, "nodes")
                    else {node["id"] for node in graph.get("nodes", ())})
        return self.delta_for_node_ids(node_ids)

    def delta_for_node_ids(self, node_ids: Iterable[str]) -> GraphDelta:
        """Build the additive delta against a caller-owned bounded membership set.

        Structural catalog binding already resolved every endpoint from the neutral
        callsite projection.  Its endpoint set is therefore much smaller than the
        full CPG.  This seam lets the disk-backed Pass 2 path validate those exact
        endpoints without constructing a million-entry graph index solely to fold a
        few role nodes and summary edges.
        """
        nodes: List[dict] = []
        edges: List[dict] = []
        # A model can bind the same value node at more than one callsite; those
        # stamps collapse to one identical role id. Emit each distinct node/edge
        # exactly once so the additive fold never sees a self-conflict.
        seen_nodes: set = set()
        seen_edges: set = set()

        def _add_edge(edge: dict) -> None:
            key = (edge["kind"], edge["source"], edge["target"])
            if key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(edge)

        for stamp in self._stamps:
            role = stamp.get("role")
            if role in ("source", "sink"):
                value_id = stamp.get("value_id")
                if value_id not in node_ids:
                    continue  # resolved node is not in this graph: skip, never dangle
                fact = {
                    "fact_origin": "atropos-model",
                    "confidence": stamp.get("confidence", "medium"),
                    "evidence_ids": [value_id],
                    "model_id": stamp["model_id"],
                    "cwe": stamp.get("cwe", []),
                }
                role_id = stable_id(_OWNER, self.overlay_id, role,
                                    stamp["model_id"], value_id)
                if role_id in seen_nodes:
                    continue
                seen_nodes.add(role_id)
                nodes.append({
                    "id": role_id,
                    "kind": role,
                    "label": f"{role}:{stamp.get('kind') or stamp['model_id']}",
                    "properties": {
                        **fact,
                        "value_id": value_id,
                        f"{role}_kind": stamp.get("kind") or "atropos",
                        "callsite_id": stamp.get("callsite_id"),
                        "access_path": stamp.get("access_path"),
                    },
                })
                _add_edge({
                    "kind": "TAINT_SOURCE" if role == "source" else "TAINT_SINK",
                    "source": role_id, "target": value_id, "properties": fact,
                })
            elif role == "summary":
                src, dst = stamp.get("from"), stamp.get("to")
                if src not in node_ids or dst not in node_ids:
                    continue
                _add_edge({
                    "kind": FLOW_KIND, "source": src, "target": dst,
                    "properties": {
                        "fact_origin": "atropos-model",
                        "confidence": stamp.get("confidence", "medium"),
                        "evidence_ids": [src, dst],
                        "model_id": stamp["model_id"],
                        "summary_kind": stamp.get("kind") or "flow",
                    },
                })
            # sanitizer: no taint-suppression consumer yet -> deliberately not stamped.
        return GraphDelta(self.overlay_id, nodes, edges)
