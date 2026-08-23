"""Candidate census for graph-temporal lifecycle patterns.

Temporal candidates are deliberately not findings.  They are the semantic
operation sites that a graph matcher must relate across compatible paths.  The
pattern identity and required event vocabulary come from Atropos; this module
only turns observable graph facts into the common candidate capsule shape.
"""
from __future__ import annotations

import hashlib

from ..flow import atropos


def _event_kind(node):
    props = node.get("properties") or {}
    event = node.get("event") or {}
    return str(props.get("event_kind") or event.get("kind") or
               node.get("kind") or "").lower().replace("eventkind.", "")


def _object_id(node):
    props = node.get("properties") or {}
    event = node.get("event") or {}
    for source in (props, event):
        for key in ("object_id", "target_id", "value_id", "obj", "base"):
            if source.get(key):
                return source[key]
    return None


class TemporalLifecycle:
    metadata = {}
    trigger = ()

    def __init__(self, graph, bind_summary=None):
        self.graph = graph
        self.bind_summary = bind_summary or {}
        raw_nodes = graph.get("nodes", ())
        if isinstance(raw_nodes, dict):
            self.nodes = [{"id": node_id, **(node or {})}
                          for node_id, node in raw_nodes.items()]
        else:
            self.nodes = list(raw_nodes)
        # Some callers attach the materialized semantic graph under this key;
        # accepting it keeps the registry useful before and after graph
        # publication without coupling it to the C frontend.
        semantic = graph.get("semantic_graph") or {}
        if isinstance(semantic, dict):
            semantic_nodes = semantic.get("nodes", ())
            if isinstance(semantic_nodes, dict):
                self.nodes.extend([{"id": node_id, **(node or {})}
                                   for node_id, node in semantic_nodes.items()])
            else:
                self.nodes.extend(semantic_nodes)

    def _language(self, node):
        props = node.get("properties") or {}
        path = props.get("absolute_file") or props.get("file") or node.get("file") or ""
        return atropos.lang_of(path)

    def _candidate(self, node):
        props = node.get("properties") or {}
        metadata = node.get("metadata") or {}
        event = node.get("event") or {}
        site = node.get("id", "")
        pattern_id = self.metadata["id"]
        raw = f"{pattern_id}\0{site}"
        return {
            "candidate_id": "temporal_" + hashlib.sha256(raw.encode()).hexdigest()[:20],
            "constructor": pattern_id,
            "domain": "lifecycle",
            "language": self._language(node),
            "obligation": self.metadata["obligation"],
            "handles": {
                "site_node_id": site,
                "enclosing_function_id": (props.get("owner_function_id") or
                                            metadata.get("owner_function_id") or
                                            node.get("fragment")),
                "obligation_value_ids": ([obj] if (obj := _object_id(node)) else []),
            },
            "observations": {
                "site": node.get("label"),
                "event_kind": _event_kind(node),
                "object_id": _object_id(node),
                "file": (props.get("absolute_file") or props.get("file") or
                         node.get("file")),
                "line": (props.get("start_line") or props.get("line") or
                         event.get("line")),
                "pattern": self.metadata["matcher_pattern"],
                "requires": list(self.metadata["requires"]),
            },
            "inferences": {
                "path_relation": "not-queried",
                "same_object": "not-queried",
                "same_generation": "not-queried",
            },
            "rank": None,
            "rank_reasons": [],
            "completeness": "PARTIAL",
            "next_op": {"tool": "skeleton", "why": "inspect compatible temporal context"},
        }

    def enumerate(self):
        rows = [self._candidate(node) for node in self.nodes
                if _event_kind(node) in self.trigger]
        rows.sort(key=lambda row: (row["observations"].get("file") or "",
                                   row["observations"].get("line") or 0,
                                   row["handles"]["site_node_id"]))
        return {
            "constructor": self.metadata["id"],
            "domain": "lifecycle",
            "metadata": dict(self.metadata),
            "candidates": rows,
            "census": {"enumerated": len(rows),
                       "by_status": {"not-queried": len(rows)}},
            "frontiers": {"unresolved_calls": 0, "unbound_models": 0,
                           "unbound_sinks": [], "truncated_walks": 0,
                           "missing_optional_capabilities": [],
                           "unselected_configs": []},
            "complete_for_observable_graph": True,
        }


def temporal_constructor(spec):
    """Build a constructor directly from one Atropos candidate declaration."""
    entry = next((item for item in atropos.pattern_catalog()
                  if item.get("id") == spec["id"]), {})
    matcher = entry.get("matcher") or {}
    pattern = matcher.get("pattern") or spec.get("matcher_pattern")
    # Event vocabulary is intentionally described by the catalog requirement;
    # the two standard temporal patterns map to their semantic trigger kinds.
    # Candidate rows are intentionally broad observation sites.  They are not
    # findings; the graph matcher still has to prove the temporal relation.  Keep
    # this vocabulary in one generic routing table so every catalog-declared
    # lifecycle pattern can enter candidate_census without a constructor per bug.
    triggers = {
        "double-free": ("release",),
        "uaf.deref": ("read", "write", "read_storage", "write_storage"),
        "leak": ("origin",),
        "use.dangling": ("pass_value", "compare_value", "return_value"),
        "mem.lifetime.realloc-failure-leak": ("realloc_failed",),
        "null-deref": ("read", "write", "read_storage", "write_storage"),
        "use-after-return": ("return_value",),
    }.get(pattern, ())
    return type("Temporal_" + spec["family"].replace("-", "_"),
                (TemporalLifecycle,), {
                    "trigger": triggers,
                    "metadata": {
                        "id": spec["id"], "domain": "lifecycle",
                        "family": spec["family"], "languages": spec["languages"],
                        "required_capabilities": ("semantic-events",),
                        "optional_capabilities": ("value-flow", "calls"),
                        "obligation": spec["obligation"],
                        "matcher_pattern": pattern,
                        "requires": spec.get("requires", ()),
                    },
                })
