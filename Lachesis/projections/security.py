"""Graph-only security annotations used by presentation projections.

This module does not discover syntax or data flow. It summarizes canonical
source, sink, route, call, state, and dynamic-boundary facts that have already
been emitted by frontends and semantic/ecosystem overlays.
"""
from __future__ import annotations

from collections import defaultdict

from ..core.query import GraphIndex


AUTHZ_ACCESSORS = frozenset({
    "currentTenant", "verifyInbound", "principalKey", "currentUser",
    "requireUser", "currentSession", "authorize", "checkPermission", "can",
})

STATE_KINDS = frozenset({
    "singleton", "module-state", "static-initializer", "module-initializer",
    "import-cycle",
})


def _call_name(call: dict) -> str:
    properties = call.get("properties", {})
    return str(
        properties.get("method_name")
        or properties.get("callee")
        or call.get("label", "")
    ).split("(", 1)[0].rsplit(".", 1)[-1]


def _annotate(role_of, node_id, role, subtype=None, confidence="high", witnesses=()):
    if not node_id:
        return
    role_of[node_id].append({
        "role": role,
        "subtype": subtype,
        "confidence": confidence,
        "witnesses": sorted({item for item in witnesses if item}),
    })


def classify_sinks(graph: dict) -> dict[str, dict]:
    """Return canonical call-site sinks indexed by call node ID."""
    index = GraphIndex(graph)
    result = {}
    for sink in index.nodes_of_kind("sink"):
        properties = sink.get("properties", {})
        call_id = properties.get("callsite_id")
        call = index.nodes.get(call_id)
        if not call:
            continue
        result[call_id] = {
            "callee": _call_name(call),
            "subtype": properties.get("sink_kind", "sensitive-operation"),
            "evidence": sink["id"],
        }
    return result


def derive_roles(graph: dict) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    """Derive presentation roles exclusively from canonical graph facts."""
    index = GraphIndex(graph)
    role_of = defaultdict(list)
    sinks = classify_sinks(graph)

    for source in index.nodes_of_kind("source"):
        properties = source.get("properties", {})
        _annotate(
            role_of, source["id"], "Source",
            properties.get("source_kind"), properties.get("confidence", "high"),
            (properties.get("value_id"),),
        )
        _annotate(
            role_of, properties.get("function_id"), "EntryPoint",
            "request-handler", "conservative", (source["id"],),
        )

    for call_id, sink in sinks.items():
        _annotate(
            role_of, call_id, "Sink", sink["subtype"], "high",
            (sink["evidence"],),
        )

    for route in index.nodes_of_kind("route"):
        properties = route.get("properties", {})
        _annotate(
            role_of, route["id"], "EntryPoint", "route",
            properties.get("confidence", "high"),
            (properties.get("callsite_id"),),
        )
        for handler in index.targets(route["id"], "ROUTE_HANDLED_BY", "ENTRY_POINT_OF"):
            _annotate(
                role_of, handler["id"], "EntryPoint", "route", "high",
                (route["id"],),
            )

    for boundary in index.nodes_of_kind("boundary", "wiring-boundary"):
        properties = boundary.get("properties", {})
        _annotate(
            role_of, boundary["id"], "Boundary",
            properties.get("boundary_kind") or properties.get("wiring_kind"),
            properties.get("confidence", "high"),
            properties.get("evidence_ids", ()),
        )
    for dynamic in index.nodes_of_kind("dynamic-behavior"):
        _annotate(
            role_of, dynamic["id"], "Boundary",
            dynamic.get("properties", {}).get("behavior_kind"), "high",
            dynamic.get("properties", {}).get("evidence_ids", ()),
        )
    for state in index.nodes_of_kind(*STATE_KINDS):
        _annotate(role_of, state["id"], "State", state["kind"])

    return role_of, sinks


def detect_guards(graph: dict, sinks: dict[str, dict]) -> list[dict]:
    """Summarize guard signals for functions containing canonical sink calls.

    Accessor recognition is deliberately a policy over compiler-resolved call
    metadata. It never scans or tokenizes source text.
    """
    index = GraphIndex(graph)
    calls_by_function = defaultdict(list)
    for call in index.nodes_of_kind("call", "construct"):
        owner = call.get("properties", {}).get("owner_function_id")
        if owner:
            calls_by_function[owner].append(call)

    verdicts = []
    function_sinks = {}
    function_status = {}
    for function_id, calls in calls_by_function.items():
        sink_calls = [call for call in calls if call["id"] in sinks]
        if not sink_calls:
            continue
        function = index.nodes.get(function_id)
        if not function:
            continue
        guards = [call for call in calls if _call_name(call) in AUTHZ_ACCESSORS]
        sink_names = {sinks[call["id"]]["callee"] for call in sink_calls}
        status = "GUARDED" if guards else "UNGUARDED"
        function_sinks[function_id] = sink_names
        function_status[function_id] = status
        properties = function.get("properties", {})
        verdicts.append({
            "handler_id": function_id,
            "handler_label": function.get("label", function_id),
            "file": properties.get("absolute_file") or properties.get("file"),
            "line": properties.get("start_line"),
            "sink_names": sorted(sink_names),
            "sink_call_ids": sorted(call["id"] for call in sink_calls),
            "status": status,
            "guard_signal": "resolved-authz-call" if guards else None,
            "confidence": "high" if guards else "conservative",
            "witnesses": sorted(call["id"] for call in guards),
        })

    for verdict in verdicts:
        if verdict["status"] != "UNGUARDED":
            verdict["differential_siblings"] = []
            continue
        sinks_here = set(verdict["sink_names"])
        verdict["differential_siblings"] = sorted(
            index.nodes[function_id].get("label", function_id)
            for function_id, names in function_sinks.items()
            if function_id != verdict["handler_id"]
            and names.intersection(sinks_here)
            and function_status.get(function_id) == "GUARDED"
        )
    return verdicts
