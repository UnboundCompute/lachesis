"""Canonical callsite adapter: project a Lachesis CodeGraph onto the neutral
``atropos-symbol-index`` view that the Atropos binder consumes.

This is the single, frontend-agnostic seam. The binder never imports Lachesis;
Lachesis never imports the binder. They agree only on this JSON-shaped dict:

    {
      "format": "atropos-symbol-index", "version": 1,
      "language": ..., "source": ...,
      "callsites": [
        {"id", "callee": {"name","module","receiver_type","arity","static"},
         "call_value_id", "receiver_value_id", "arg_value_ids": [...],
         "file", "line"}
      ]
    }

Arguments are ordered by the explicit ``position`` on each ``HAS_ARGUMENT``
edge, not by source offset or node kind, so the same code works for any
frontend that emits that semantic edge. The call-result handle is the call
node's own ``value_id`` when core enrichment has synthesized one, and the call
node id otherwise -- a stable handle either way for ``ReturnValue`` endpoints.
"""
from __future__ import annotations

from typing import Any, Dict, List


def canonical_index(graph: Dict[str, Any], *, language: str,
                    source: str = "lachesis") -> Dict[str, Any]:
    """Build the neutral symbol-index dict from an (enriched or core) CodeGraph."""
    args_by_call: Dict[str, List] = {}
    for edge in graph.get("edges", ()):
        if edge.get("kind") == "HAS_ARGUMENT":
            pos = edge.get("properties", {}).get("position", 0)
            args_by_call.setdefault(edge["source"], []).append((pos, edge["target"]))

    callsites: List[Dict[str, Any]] = []
    for node in graph.get("nodes", ()):
        if node.get("kind") != "call":
            continue
        props = node.get("properties", {})
        name = props.get("callee") or props.get("method_name")
        if not name:
            continue
        ordered = [target for _, target in sorted(args_by_call.get(node["id"], []))]
        callsites.append({
            "id": node["id"],
            "callee": {
                "name": name,
                "module": props.get("module"),
                "receiver_type": props.get("receiver_type"),
                "arity": len(ordered),
                "static": props.get("receiver_value_id") is None,
            },
            "call_value_id": props.get("value_id") or node["id"],
            "receiver_value_id": props.get("receiver_value_id"),
            "arg_value_ids": ordered,
            "file": props.get("absolute_file") or props.get("file"),
            "line": props.get("start_line"),
        })

    return {
        "format": "atropos-symbol-index", "version": 1,
        "language": language, "source": source,
        "callsites": callsites,
    }
