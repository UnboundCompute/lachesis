"""Canonical callsite adapter: project a Lachesis CodeGraph onto the neutral
``atropos-symbol-index`` view that the Atropos binder consumes.

This is the single, frontend-agnostic seam. The binder never imports Lachesis;
Lachesis never imports the binder. They agree only on this JSON-shaped dict:

    {
      "format": "atropos-symbol-index", "version": 1,
      "language": ..., "source": ...,
      "callsites": [
         {"id", "callee": {"name","module","receiver_type","arity","static"},
         "call_value_id", "receiver_value_id", "receiver_expression",
         "receiver_name", "receiver_provenance", "arg_value_ids": [...],
         "file", "line"}
      ]
    }

Frontends disagree on how a call's arguments are wired, so the adapter accepts
both shapes and normalises them to one ordered list of per-argument handles:

* **C** (clang) emits no ``kind="argument"`` nodes; it links the call node to
  each argument expression with a ``HAS_ARGUMENT`` edge carrying an explicit
  ``position``. Keyed by the edge *source* (the call node).
* **Python / TypeScript** emit a ``kind="argument"`` node per slot, tagged with
  ``callsite_id`` and ``position``; the concrete value flows into that node via
  ``VALUE_FLOWS_TO(reason="argument-value")``. The argument node id is a stable
  handle taint reaches (the value is upstream of it), so it is what we hand back.

The callee *name* is likewise spelled differently per frontend (``callee`` in C,
``callee_name`` in the Python/TS frontends, ``method_name`` elsewhere); all three
are accepted. The call-result handle is the call node's own ``value_id`` when the
frontend/enrichment synthesised one, and the call node id otherwise -- a stable
handle either way for ``ReturnValue`` endpoints.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List


def canonical_index(graph: Dict[str, Any], *, language: str,
                    source: str = "lachesis") -> Dict[str, Any]:
    """Build the neutral symbol-index dict from an (enriched or core) CodeGraph."""
    # Route 1 (Python/TS): kind="argument" nodes keyed by callsite_id.
    arg_nodes_by_call: Dict[str, List] = {}
    for node in graph.get("nodes", ()):
        if node.get("kind") != "argument":
            continue
        props = node.get("properties", {})
        cid = props.get("callsite_id")
        if cid is None:
            continue
        pos = props.get("position", props.get("index", 0))
        arg_nodes_by_call.setdefault(cid, []).append((pos, node["id"]))

    # Route 2 (C/clang): HAS_ARGUMENT edges keyed by the call node (edge source).
    has_arg_by_call: Dict[str, List] = {}
    for edge in graph.get("edges", ()):
        if edge.get("kind") == "HAS_ARGUMENT":
            pos = edge.get("properties", {}).get("position", 0)
            has_arg_by_call.setdefault(edge["source"], []).append((pos, edge["target"]))

    callsites: List[Dict[str, Any]] = []
    # A Python value returned by ``connection.cursor()`` often has no static
    # type in a framework application.  Retain the lexical evidence needed by
    # Atropos's DB-API fallback without making the binder inspect Lachesis nodes.
    cursor_result_ids = set()
    cursor_target_names = set()
    for node in graph.get("nodes", ()):
        if node.get("kind") not in {"call", "construct"}:
            continue
        props = node.get("properties", {})
        if (props.get("callee_name") or props.get("method_name")
                or props.get("callee")) == "cursor":
            cursor_result_ids.add(props.get("value_id") or node.get("id"))
    for node in graph.get("nodes", ()):
        if node.get("kind") != "write":
            continue
        props = node.get("properties", {})
        if props.get("value_id") not in cursor_result_ids:
            continue
        target = next((candidate for candidate in graph.get("nodes", ())
                       if candidate.get("id") == props.get("target_id")), None)
        if target and target.get("label"):
            cursor_target_names.add(str(target["label"]))

    for node in graph.get("nodes", ()):
        if node.get("kind") != "call":
            continue
        props = node.get("properties", {})
        name = (props.get("callee") or props.get("method_name")
                or props.get("callee_name"))
        if not name:
            continue
        raw = arg_nodes_by_call.get(node["id"]) or has_arg_by_call.get(node["id"], [])
        ordered = [target for _, target in sorted(raw, key=lambda t: t[0])]
        receiver_expression = props.get("receiver")
        receiver_name = None
        if receiver_expression:
            receiver_name = re.search(r"([A-Za-z_]\w*)\s*$",
                                       str(receiver_expression))
            receiver_name = receiver_name.group(1) if receiver_name else None
        receiver_provenance = None
        if receiver_name in cursor_target_names:
            receiver_provenance = "cursor-factory"
        elif receiver_expression and re.search(r"\.cursor\s*\(\s*\)\s*$",
                                                str(receiver_expression)):
            receiver_provenance = "cursor-factory"
        # Python records ``os.makedirs`` as method=makedirs, receiver=os.
        # Preserve that module spelling for package-qualified Atropos models;
        # object receivers such as self.connection intentionally remain null.
        receiver_root = re.fullmatch(r"[A-Za-z_]\w*", str(receiver_expression or ""))
        module = props.get("module")
        if module is None and receiver_root:
            module = receiver_root.group(0)
        callsites.append({
            "id": node["id"],
            "callee": {
                "name": name,
                "module": module,
                "receiver_type": props.get("receiver_type"),
                "arity": len(ordered),
                "static": props.get("receiver_value_id") is None,
            },
            "call_value_id": props.get("value_id") or node["id"],
            "receiver_value_id": props.get("receiver_value_id"),
            "receiver_expression": receiver_expression,
            "receiver_name": receiver_name,
            "receiver_provenance": receiver_provenance,
            "arg_value_ids": ordered,
            "file": props.get("absolute_file") or props.get("file"),
            "line": props.get("start_line"),
        })

    return {
        "format": "atropos-symbol-index", "version": 1,
        "language": language, "source": source,
        "callsites": callsites,
    }
