"""Catalogue-backed lifecycle operation candidates.

These are structural facts, not findings.  Release candidates come directly from
the per-language lifecycle catalogue.  Use candidates are restricted to graph
``read`` nodes whose definition/value lineage is rooted in an acquisition,
release, or configured source; an untracked property read is deliberately absent.
"""
from __future__ import annotations

import hashlib
import os
import re

from ..flow import atropos
from ..flow.normalize import normalizer


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
        return normalizer(lang).is_release(callee)

    @staticmethod
    def _is_structural_use(node):
        """Keep bare variable reads out of the lifecycle-use census."""
        p = node.get("properties") or {}
        syntax = p.get("syntax_kind")
        if syntax in {"MemberExpr", "ArraySubscriptExpr", "UnaryOperator",
                      "property-path", "index", "member"}:
            return True
        if node.get("kind") != "read":
            return False
        label = str(node.get("label") or "")
        return any(mark in label for mark in ("->", ".", "["))

    def _tracked_reads(self):
        # Track values by explicit lifecycle/source call participation.  This is
        # intentionally conservative: no proof of lineage means no lifecycle.use.
        tracked = set()
        for node in self.nodes.values():
            if node.get("kind") == "release":
                target_id = (node.get("properties") or {}).get("target_id")
                if target_id:
                    tracked.add(target_id)
            if node.get("kind") not in ("call", "construct"):
                continue
            lang = self._language(node)
            callee = self._callee(node)
            if not callee:
                continue
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
        # Member/index reads target a property-path node, while lifecycle calls
        # usually identify the base value. Promote only paths whose base is
        # already tracked; ordinary property reads remain out of scope.
        for node in self.nodes.values():
            if node.get("kind") == "property-path" and \
                    (node.get("properties") or {}).get("base_value_id") in tracked:
                tracked.add(node.get("id"))
        return tracked

    def _tracked_labels(self, tracked):
        labels = set()
        for node_id in tracked:
            node = self.nodes.get(node_id) or {}
            label = node.get("label")
            if label:
                labels.add(label)
        return labels

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
                "line": p.get("release_line") or p.get("start_line"),
                "expression": expression or node.get("label"),
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
        tracked_labels = self._tracked_labels(tracked)
        for node in self.nodes.values():
            lang = self._language(node)
            if self.operation == "acquire":
                if node.get("kind") not in ("call", "construct"):
                    continue
                callee = self._callee(node)
                if not callee:
                    continue
                norm = normalizer(lang)
                if norm.is_acquire(callee) or callee in atropos.source_catalog(lang):
                    rows.append(self._candidate(node, self.metadata["id"]))
            elif self.operation == "release":
                if node.get("kind") == "release" or \
                        (node.get("kind") in ("call", "construct") and
                         (self._matches_release(node, lang) or
                          normalizer(lang).is_realloc(self._callee(node)))) or \
                        (lang == "c" and
                         ((node.get("properties") or {}).get("syntax_kind") == "CXXDeleteExpr" or
                          str(node.get("label") or "").lstrip().startswith("delete"))):
                    rows.append(self._candidate(node, self.metadata["id"]))
            elif self.operation == "use" and node.get("kind") in ("read", "expression"):
                p = node.get("properties") or {}
                syntax = p.get("syntax_kind")
                label = node.get("label") or ""
                base = re.match(r"\s*(?:\*\s*)?([A-Za-z_]\w*)", label)
                is_structural = self._is_structural_use(node)
                rooted = base and base.group(1) in tracked_labels
                if is_structural and (p.get("target_id") in tracked
                                      or p.get("definition_id") in tracked or rooted):
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
