"""Catalogue-backed lifecycle operation candidates.

These are structural facts, not findings.  Release candidates come directly from
the per-language lifecycle catalogue.  Use candidates are restricted to graph
``read`` nodes whose definition/value lineage is rooted in an acquisition,
release, or configured source; an untracked property read is deliberately absent.
"""
from __future__ import annotations

import hashlib
import os

from ..flow import atropos


class LifecycleOperation:
    metadata = {}
    operation = ""

    def __init__(self, graph, bind_summary=None):
        self.graph = graph
        self.nodes = {n["id"]: n for n in graph.get("nodes", ())}
        self.edges = graph.get("edges", ())

    def _language(self, node):
        path = (node.get("properties") or {}).get("absolute_file") or ""
        return atropos.lang_of(path)

    def _callee(self, node):
        props = node.get("properties") or {}
        return props.get("callee") or props.get("method_name")

    def _matches_release(self, node, lang):
        callee = self._callee(node)
        if not callee:
            return False
        from ..flow.normalize import normalizer
        return normalizer(lang).is_release(callee)

    def _tracked_reads(self):
        # Track values by explicit lifecycle/source call participation.  This is
        # intentionally conservative: no proof of lineage means no lifecycle.use.
        tracked = set()
        for node in self.nodes.values():
            if node.get("kind") not in ("call", "construct"):
                continue
            lang = self._language(node)
            callee = self._callee(node)
            if not callee:
                continue
            from ..flow.normalize import normalizer
            norm = normalizer(lang)
            if norm.is_acquire(callee) or norm.is_release(callee) or \
                    callee in atropos.source_catalog(lang):
                props = node.get("properties") or {}
                for key in ("return_value_id", "value_id", "assigned_value_id"):
                    if props.get(key):
                        tracked.add(props[key])
                if props.get("receiver_value_id"):
                    tracked.add(props["receiver_value_id"])
                tracked.update(props.get("argument_value_ids") or ())
        return tracked

    def _candidate(self, node, family, expression=None):
        p = node.get("properties") or {}
        site = node.get("id", "")
        raw = f"{family}\0{site}"
        return {
            "candidate_id": "life_" + hashlib.sha256(raw.encode()).hexdigest()[:20],
            "constructor": family, "domain": "lifecycle",
            "language": self._language(node),
            "obligation": "resource lifetime operation",
            "handles": {"site_node_id": site,
                        "enclosing_function_id": p.get("owner_function_id"),
                        "obligation_value_ids": [p.get("target_id")] if p.get("target_id") else []},
            "observations": {
                "callee": self._callee(node), "site": node.get("label"),
                "file": p.get("absolute_file") or p.get("file"),
                "line": p.get("start_line"), "expression": expression or node.get("label"),
                "lifecycle_family": family,
            },
            "inferences": {"tainted": "not-applicable", "cap": "not-applicable",
                            "dom": "not-applicable"},
            # Lifecycle emission is a structural census, not a triage/ranking
            # decision.  Keep the common capsule field present but unscored.
            "rank": None, "rank_reasons": [], "completeness": "PARTIAL",
            "next_op": {"tool": "skeleton", "why": "inspect lifecycle context"},
        }

    def enumerate(self):
        rows = []
        tracked = self._tracked_reads() if self.operation == "use" else set()
        for node in self.nodes.values():
            lang = self._language(node)
            if self.operation == "release":
                if node.get("kind") == "release" or \
                        (node.get("kind") in ("call", "construct") and
                         self._matches_release(node, lang)):
                    rows.append(self._candidate(node, self.metadata["id"]))
            elif self.operation == "use" and node.get("kind") == "read":
                p = node.get("properties") or {}
                if p.get("target_id") in tracked or p.get("definition_id") in tracked:
                    rows.append(self._candidate(node, self.metadata["id"], node.get("label")))
        rows.sort(key=lambda r: (r["observations"].get("file") or "", r["observations"].get("line") or 0))
        return {"constructor": self.metadata["id"], "domain": "lifecycle",
                "metadata": dict(self.metadata), "candidates": rows,
                "census": {"enumerated": len(rows), "by_status": {"not-queried": len(rows)}},
                "frontiers": {"unresolved_calls": 0, "unbound_models": 0,
                               "unbound_sinks": [], "truncated_walks": 0,
                               "missing_optional_capabilities": [], "unselected_configs": []},
                "complete_for_observable_graph": True}


def constructors():
    out = {}
    for operation in ("acquire", "release", "use", "escape"):
        # acquire/escape are already represented by the typestate stream; their
        # candidate rows are intentionally empty until a frontend supplies a
        # concrete operation node. Release/use are catalogue/read-backed here.
        cls = type("Lifecycle_" + operation, (LifecycleOperation,),
                   {"operation": operation,
                    "metadata": {"id": "lifecycle." + operation,
                                 "domain": "lifecycle", "family": operation,
                                 "languages": ("c", "python", "javascript", "typescript"),
                                 "required_capabilities": ("calls",),
                                 "optional_capabilities": ("value-flow",)}})
        out[cls.metadata["id"]] = cls
    return out
