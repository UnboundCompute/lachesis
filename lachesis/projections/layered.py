"""Layered-v2 LLM exposure over the completed canonical project graph."""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from typing import Iterable, Optional

from ..core.capabilities import ALL_CAPABILITIES
from ..core.query import GraphIndex
from .security import derive_roles, detect_guards


SCHEMA_VERSION = 2
TIER_NAMES = {
    "T0": "perimeter", "T1": "reachability", "T2": "path",
    "T3": "body", "T4": "proof",
}
TIER_PURPOSES = {
    "T0": "Project components, packages, files, and dependency perimeter.",
    "T1": "Callable/type reachability, entry points, state, effects, and guards.",
    "T2": "Security source-to-sink paths with ordered evidence witnesses.",
    "T3": "Function bodies, calls, expressions, scopes, and control flow.",
    "T4": "Definitions, reads, contexts, heap identity, tokens, and source proof.",
}
TIER_OPERATIONS = {
    "T0": ["overview", "locate", "expand", "find-entity"],
    "T1": ["expand", "function", "handler-security", "unresolved"],
    "T2": ["security-path", "handler-security", "expand"],
    "T3": ["function", "call", "expand", "unresolved"],
    "T4": ["value-history", "locate", "expand"],
}
TIER_ORDER = tuple(TIER_NAMES)
STRUCTURAL_RANK = {"T0": 0, "T1": 1, "T2": 1, "T3": 2, "T4": 3}

NODE_KIND_TIER = {
    "project": "T0", "package": "T0", "module": "T0", "file": "T0",
    "external-module": "T0", "import-cycle": "T0",
    "function": "T1", "method": "T1", "constructor": "T1", "class": "T1",
    "interface": "T1", "type": "T1", "enum": "T1", "record": "T1",
    "type-reference": "T1", "dispatch-member": "T1", "wiring-boundary": "T1",
    "dynamic-behavior": "T1", "singleton": "T1", "module-state": "T1",
    "module-initializer": "T1", "static-initializer": "T1", "effect-summary": "T1",
    "function-effect": "T1", "runtime-model-application": "T1", "route": "T1",
    "boundary": "T1", "decorator": "T1",
    "source": "T2", "sink": "T2", "taint-reach": "T2",
    "statement": "T3", "expression": "T3", "identifier": "T3",
    "operation": "T3", "call": "T3", "construct": "T3", "argument": "T3",
    "return-value": "T3", "call-return": "T3", "cfg-node": "T3",
    "cfg-entry": "T3", "cfg-exit": "T3", "cfg-condition": "T3", "cfg-merge": "T3",
    "cfg-block": "T3", "unreachable-region": "T3", "phi": "T3",
    "exception-site": "T3", "catch-handler": "T3", "finally-block": "T3",
    "promise-rejection": "T3", "type-refinement": "T3",
    "dispatch-candidate": "T3", "scope": "T3",
    "definition": "T4", "read": "T4", "write": "T4", "parameter": "T4",
    "property": "T4", "heap-object": "T4", "heap-location": "T4",
    "heap-access": "T4", "heap-effect": "T4", "context-heap-effect": "T4",
    "call-context": "T4", "context-return": "T4", "context-parameter": "T4",
    "context-receiver": "T4", "context-dispatch": "T4", "applied-effect": "T4",
    "type-parameter": "T4", "generic-substitution": "T4", "overload": "T4",
    "type-compatibility": "T4", "async-event": "T4", "runtime-symbol": "T4",
    "receiver-type": "T4", "unresolved-symbol": "T4", "dynamic-type-reference": "T4",
    "token": "T4", "source-line": "T4", "data-context": "T4",
    "source-span": "T4", "value": "T4", "variable": "T4", "binding": "T4",
    "call-value": "T4", "property-path": "T4", "allocation": "T4",
    "diagnostic": "T4", "constant": "T4", "literal": "T4",
}

STRUCTURAL_DRILL_KINDS = frozenset({
    "CONTAINS", "DECLARES", "DECLARES_MEMBER", "DECLARES_VALUE",
    "DECLARES_SCOPE", "CONTAINS_BODY", "AST_CHILD", "HAS_SCOPE", "CONTAINS_SCOPE",
    "HAS_ARGUMENT", "HAS_RETURN_VALUE", "HAS_CALL_CONTEXT", "HAS_TOKEN",
    "HAS_DIAGNOSTIC", "HAS_PROPERTY_PATH", "HAS_TYPE_PARAMETER", "HAS_SINGLETON",
    "HAS_MODULE_STATE", "EVIDENCED_BY", "READ_EVIDENCED_BY", "RETURN_EVIDENCED_BY",
    "DEFINES", "ALLOCATES", "POINTS_TO", "PHI_AT", "HAS_EFFECT_SUMMARY",
    "HAS_FUNCTION_EFFECT", "HAS_WIRING_BOUNDARY",
})

COMMON_PROPERTY_KEYS = frozenset({
    "fact_origin", "confidence", "evidence_ids", "absolute_file", "file",
    "start_offset", "end_offset", "start_line", "start_column", "end_line",
    "end_column", "frontend_id", "frontend_tier", "language", "content_hash", "roles",
})

CAPABILITY_LEVEL = {"none": 0, "partial": 1, "complete": 2}
CANONICAL_CAPABILITY_SIGNALS = {
    "lexical": ({"token", "source-span"}, {"HAS_TOKEN"}),
    "syntax": (
        {"statement", "expression", "function", "class", "interface"},
        {"AST_CHILD", "DECLARES"},
    ),
    "modules": (
        {"module", "external-module"},
        {"DEPENDS_ON", "RUNTIME_DEPENDS_ON", "RE_EXPORTS", "EXPORTS"},
    ),
    "dependency_sources": ({"package", "external-module"}, {"PACKAGE_CONTAINS"}),
    "scopes": ({"scope"}, {"DECLARES_SCOPE"}),
    "symbols": ({"symbol", "identifier"}, {"DECLARES_SYMBOL", "REFERS_TO"}),
    "types": (
        {"type", "interface", "type-refinement", "generic-substitution"},
        {"TYPE_REFERS_TO", "NARROWS_TYPE", "SUBSTITUTES_TYPE"},
    ),
    "calls": ({"call", "construct"}, {"CALLS", "INVOKES", "MAY_INVOKE"}),
    "control_flow": (
        {"cfg-entry", "cfg-condition", "cfg-merge", "cfg-exit"},
        {"CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH"},
    ),
    "direct_data_flow": (
        {"definition", "read", "write", "argument", "return-value"},
        {"DEFINES", "READS_FROM", "WRITES_TO", "VALUE_FLOWS_TO"},
    ),
    "heap_identity": (
        {"allocation", "heap-object", "heap-location", "heap-access"},
        {"ALLOCATES", "POINTS_TO", "READS_HEAP", "WRITES_HEAP"},
    ),
    "context_sensitivity": (
        {"call-context", "context-parameter", "context-return", "context-receiver"},
        {"HAS_CALL_CONTEXT", "CONTEXTUALIZES", "BINDS_PARAMETER", "CONTEXT_RETURNS"},
    ),
    "branch_histories": (
        {"phi"},
        {"PHI_INPUT", "PHI_FOR_SYMBOL", "BRANCH_PREVIOUS", "BRANCH_READS_FROM"},
    ),
    # Only claim a taint policy once taint actually REACHED a sink. TAINT_SOURCE /
    # TAINT_FLOWS_TO / source / sink are minted the moment any source or sensitive
    # call exists — they are present on graphs with 0 witnesses, so keying on them
    # made the manifest self-disagree (frontend "none" vs composed "partial") while
    # `security-path` had nothing to answer. Require the materialized reach so
    # "partial" is consistent with a witness existing.
    "taint_policy": (
        {"taint-reach"},
        {"TAINT_REACHES"},
    ),
    "runtime_models": (
        {"runtime-model-application"},
        {"APPLIES_EFFECT", "MODELED_BY"},
    ),
    "effects": (
        {"function-effect", "effect-summary", "heap-effect", "context-heap-effect"},
        {"APPLIES_EFFECT", "MUTATES", "WRITES_HEAP", "HAS_FUNCTION_EFFECT"},
    ),
    "async_events": (
        {"async-event", "promise-rejection"},
        {"SCHEDULES", "REGISTERS_CALLBACK", "ASYNC_CONTINUES_AT", "HANDLED_BY"},
    ),
    "framework_wiring": (
        {"route", "wiring-boundary", "decorator"},
        {"ROUTE_HANDLED_BY", "WIRES_TO", "REGISTERED_AT"},
    ),
    "security_roles": (
        {"source", "sink", "boundary", "route"},
        {"TAINT_SOURCE", "TAINT_SINK", "ROUTE_HANDLED_BY"},
    ),
    "dynamic_behavior": (
        {"dynamic-behavior", "boundary"},
        {"DYNAMIC_BEHAVIOR_AT", "DYNAMIC_INPUT"},
    ),
}


def _edge_id(edge: dict, semantic_kind: str) -> str:
    raw = json.dumps([
        semantic_kind, edge["source"], edge["target"], edge.get("properties", {}),
    ], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "layered-edge:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _project_id(graph: dict) -> str:
    files = sorted(
        (node.get("properties", {}).get("absolute_file") or node.get("label", ""),
         node.get("properties", {}).get("content_hash", ""))
        for node in graph.get("nodes", []) if node.get("kind") == "file"
    )
    raw = json.dumps(files, separators=(",", ":"), ensure_ascii=False)
    return "layered-project:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _effective_capabilities(
    index: GraphIndex, frontend_capabilities: dict[str, dict[str, str]],
) -> dict[str, str]:
    """Combine compiler declarations with facts present after canonical overlays."""
    effective = {name: "none" for name in ALL_CAPABILITIES}
    for capabilities in frontend_capabilities.values():
        for name, level in capabilities.items():
            if name not in effective or level not in CAPABILITY_LEVEL:
                continue
            if CAPABILITY_LEVEL[level] > CAPABILITY_LEVEL[effective[name]]:
                effective[name] = level
    graph_edge_kinds = {
        GraphIndex.semantic_edge_kind(edge)
        for edges in index.outgoing.values() for edge in edges
    }
    graph_node_kinds = set(index.by_kind)
    for name, (node_kinds, edge_kinds) in CANONICAL_CAPABILITY_SIGNALS.items():
        if graph_node_kinds.intersection(node_kinds) \
                or graph_edge_kinds.intersection(edge_kinds):
            if effective[name] == "none":
                effective[name] = "partial"
    return dict(sorted(effective.items()))


def _tier_assignments(index: GraphIndex) -> tuple[dict[str, str], list[str]]:
    local_scopes = {
        node["id"] for node in index.nodes_of_kind("scope")
        if node.get("properties", {}).get("owner_function_id")
    }
    symbol_scopes = {
        edge["target"]: edge["source"]
        for edge in index.edges_of_kind("DECLARES_SYMBOL")
    }
    tiers, unknown = {}, set()
    for node_id, node in index.nodes.items():
        if node["kind"] == "symbol":
            tiers[node_id] = "T3" if symbol_scopes.get(node_id) in local_scopes else "T1"
            continue
        tier = NODE_KIND_TIER.get(node["kind"])
        if tier is None:
            unknown.add(node["kind"])
            tier = "T4"
        tiers[node_id] = tier
    return tiers, sorted(unknown)


def _file_owners(index: GraphIndex) -> tuple[dict[str, str], dict[str, str]]:
    by_absolute, by_label = {}, {}
    for node in index.nodes_of_kind("file"):
        properties = node.get("properties", {})
        if properties.get("absolute_file"):
            by_absolute[properties["absolute_file"]] = node["id"]
        by_label[node.get("label", "")] = node["id"]
        if properties.get("file"):
            by_label[properties["file"]] = node["id"]
    return by_absolute, by_label


def _ownership(
    graph: dict, index: GraphIndex, tier_of: dict[str, str], project_id: str,
) -> dict[str, list[dict]]:
    by_absolute, by_label = _file_owners(index)
    body_owner = {}
    for edge in graph.get("edges", []):
        source_tier, target_tier = tier_of.get(edge["source"]), tier_of.get(edge["target"])
        if source_tier == "T3" and target_tier == "T4":
            body_owner.setdefault(edge["target"], edge["source"])
        elif source_tier == "T4" and target_tier == "T3":
            body_owner.setdefault(edge["source"], edge["target"])

    result = {}
    for node_id, node in index.nodes.items():
        properties = node.get("properties", {})
        chain = [{"kind": "project", "id": project_id, "label": "project"}]
        file_id = by_absolute.get(properties.get("absolute_file")) \
            or by_label.get(properties.get("file"))
        if node["kind"] == "file":
            file_id = node_id
        if file_id:
            file_node = index.nodes[file_id]
            chain.append({"kind": "file", "id": file_id, "label": file_node["label"]})
        function_id = properties.get("owner_function_id") or properties.get("function_id")
        body_id = body_owner.get(node_id)
        if not function_id and body_id:
            function_id = index.nodes[body_id].get("properties", {}).get("owner_function_id")
        if node["kind"] in {"function", "method", "constructor"}:
            function_id = node_id
        if function_id and function_id in index.nodes:
            function = index.nodes[function_id]
            chain.append({"kind": function["kind"], "id": function_id, "label": function["label"]})
        if body_id and body_id != node_id and body_id in index.nodes:
            body = index.nodes[body_id]
            chain.append({"kind": body["kind"], "id": body_id, "label": body["label"]})
        result[node_id] = chain
    return result


def _location(node: dict) -> Optional[dict]:
    properties = node.get("properties", {})
    # Prefer the repo-relative `file` so a locator never leaks a temp build/staging
    # absolute path as its primary location; keep the absolute as a side field.
    relative = properties.get("file")
    absolute = properties.get("absolute_file")
    path = relative or absolute
    if not path:
        return None
    return {
        key: value for key, value in {
            "file": path, "absolute_file": absolute if absolute != path else None,
            "start_line": properties.get("start_line"),
            "start_column": properties.get("start_column"),
            "end_line": properties.get("end_line"),
            "end_column": properties.get("end_column"),
        }.items() if value is not None
    }


def _unresolved_reason(node: dict) -> Optional[str]:
    properties = node.get("properties", {})
    if node["kind"] == "diagnostic":
        return "compiler-diagnostic"
    if node["kind"] == "boundary":
        return properties.get("boundary_kind") or "runtime-boundary"
    if node["kind"] == "dynamic-behavior":
        return properties.get("behavior_kind") or "dynamic-runtime"
    resolution = properties.get("resolution")
    if resolution in {"unresolved", "dynamic-or-unresolved", "external"}:
        return "unresolved-call" if node["kind"] in {"call", "construct"} else resolution
    if properties.get("confidence") == "unresolved":
        return "unresolved-fact"
    return None


def _locator(node: dict, tier: str, owners: list[dict]) -> dict:
    return {
        "tier": tier,
        "artifact": f"{tier.lower()}_{TIER_NAMES[tier]}.json",
        "kind": node["kind"], "label": node.get("label", node["id"]),
        "owner_chain": owners, "location": _location(node),
    }


def build_security_query_projection(
    graph: dict, project_metadata: Optional[dict] = None,
) -> dict:
    """Build only the projection state needed by security-path queries.

    ``ReasoningQuery`` normally constructs every layered-v2 tier.  The Action's
    batch ``security-paths`` command only needs canonical node locators and the
    path-query manifest; emitting every exposed node and edge is redundant.  Keep
    tier assignment and ownership identical to :func:`build_layered_graph` so the
    locators are byte-for-byte compatible, but omit the presentation payload.
    """
    index = GraphIndex(graph, compact=True)
    project_id = _project_id(graph)
    tier_of, _untiered = _tier_assignments(index)
    owners = _ownership(graph, index, tier_of, project_id)
    node_index = {
        node_id: _locator(node, tier_of[node_id], owners[node_id])
        for node_id, node in index.nodes.items()
    }
    reaches = sorted(index.nodes_of_kind("taint-reach"), key=lambda item: item["id"])
    return {
        "manifest": {
            "security": {
                "path_queries": [
                    {"id": reach["id"], "label": reach["label"],
                     "query": {"operation": "security-path", "node_id": reach["id"]}}
                    for reach in reaches[:50]
                ],
            },
        },
        "node_index": node_index,
        # ReasoningQuery indexes these collections during construction.  Security
        # queries do not traverse the layered payload, so empty tiers are enough.
        "tiers": {},
    }


def _path_steps(
    reach: dict, index: GraphIndex, node_index: dict[str, dict],
) -> list[dict]:
    properties = reach.get("properties", {})
    witness_ids = properties.get("witness_ids", [])
    steps = []
    for position, node_id in enumerate(witness_ids):
        node = index.nodes.get(node_id)
        if not node:
            steps.append({"position": position, "id": node_id, "missing": True})
            continue
        transition = None
        context_id = None
        if position:
            previous = witness_ids[position - 1]
            candidates = [
                edge for edge in index.outgoing.get(previous, [])
                if edge.get("target") == node_id
            ]
            if candidates:
                edge = candidates[0]
                transition = GraphIndex.semantic_edge_kind(edge)
                context_id = edge.get("properties", {}).get("context_id")
        steps.append({
            "position": position, "id": node_id, "kind": node["kind"],
            "label": node.get("label", node_id), "locator": node_index[node_id],
            "transition": transition, "context_id": context_id,
            "confidence": node.get("properties", {}).get("confidence", "exact"),
        })
    return steps


def _exposed_node(
    node: dict, tier: str, owners: list[dict], roles: list[dict],
    path_steps: Optional[list[dict]] = None,
) -> dict:
    properties = node.get("properties", {})
    reason = _unresolved_reason(node)
    details = {
        key: value for key, value in properties.items()
        if key not in COMMON_PROPERTY_KEYS and value is not None
    }
    if path_steps is not None:
        details["steps"] = path_steps
    return {
        "id": node["id"], "kind": node["kind"], "label": node.get("label", node["id"]),
        "tier": tier, "location": _location(node), "owner_chain": owners,
        "fact": {
            "origin": properties.get("fact_origin", "unknown"),
            "confidence": properties.get("confidence", "unresolved"),
            "evidence_ids": properties.get("evidence_ids", []),
        },
        "roles": roles, "tags": sorted({role.get("role") for role in roles if role.get("role")}),
        "unresolved": {"is_unresolved": bool(reason), "reason": reason},
        "details": details, "canonical_ref": node["id"],
    }


def _exposed_edge(edge: dict, tier_of: dict[str, str]) -> dict:
    semantic = GraphIndex.semantic_edge_kind(edge) or edge.get("kind", "UNKNOWN")
    properties = dict(edge.get("properties", {}))
    properties.pop("via", None)
    return {
        "id": _edge_id(edge, semantic), "kind": semantic,
        "canonical_kind": edge.get("kind"), "source": edge["source"],
        "target": edge["target"], "source_tier": tier_of[edge["source"]],
        "target_tier": tier_of[edge["target"]], "properties": properties,
    }


def _derived_edge(kind: str, source: str, target: str, properties: dict) -> dict:
    raw = {"kind": kind, "source": source, "target": target, "properties": properties}
    return {"id": _edge_id(raw, kind), **raw, "derived": True}


def _rollups(
    graph: dict, index: GraphIndex, tier_of: dict[str, str], verdicts: list[dict],
) -> list[tuple[str, dict]]:
    result = []
    dependencies = defaultdict(list)
    calls = defaultdict(list)
    for edge in graph.get("edges", []):
        semantic = GraphIndex.semantic_edge_kind(edge)
        if semantic in {"DEPENDS_ON", "RUNTIME_DEPENDS_ON", "RE_EXPORTS"} \
                and tier_of.get(edge["source"]) == tier_of.get(edge["target"]) == "T0":
            dependencies[(edge["source"], edge["target"])].append(_edge_id(edge, semantic))
        if semantic == "CALLS" and tier_of.get(edge["source"]) == tier_of.get(edge["target"]) == "T1":
            calls[(edge["source"], edge["target"])].append(
                edge.get("properties", {}).get("callsite") or _edge_id(edge, semantic)
            )
    for (source, target), witnesses in dependencies.items():
        result.append(("T0", _derived_edge(
            "DEPENDS_ON_SUMMARY", source, target,
            {"weight": len(witnesses), "witnesses": sorted(witnesses)},
        )))
    for (source, target), witnesses in calls.items():
        result.append(("T1", _derived_edge(
            "CALLS_SUMMARY", source, target,
            {"weight": len(witnesses), "witnesses": sorted(witnesses)},
        )))
    function_by_name = defaultdict(list)
    for function in index.nodes_of_kind("function", "method"):
        function_by_name[function["label"]].append(function["id"])
    for verdict in verdicts:
        for sink_name in verdict["sink_names"]:
            for target in function_by_name.get(sink_name, []):
                kind = "GUARDED_BY" if verdict["status"] == "GUARDED" else "UNGUARDED"
                result.append(("T1", _derived_edge(
                    kind, verdict["handler_id"], target, {
                        "status": verdict["status"], "confidence": verdict["confidence"],
                        "guard_signal": verdict["guard_signal"],
                        "witnesses": sorted(set(verdict["witnesses"] + verdict["sink_call_ids"])),
                        "differential_siblings": verdict.get("differential_siblings", []),
                    },
                )))
    return result


def _entry_points(index: GraphIndex, role_of: dict[str, list[dict]]) -> list[dict]:
    result = []
    exported = {edge["target"] for edge in index.edges_of_kind("EXPORTS")}
    for node in index.nodes.values():
        roles = role_of.get(node["id"], [])
        is_entry = any(role.get("role") == "EntryPoint" for role in roles)
        if not is_entry and node["id"] not in exported and node["kind"] != "route":
            continue
        if node["kind"] not in {"route", "function", "method", "constructor"}:
            continue
        result.append({
            "id": node["id"], "kind": node["kind"], "label": node["label"],
            "location": _location(node),
            "query": {"operation": "function" if node["kind"] != "route" else "expand",
                      "node_id": node["id"]},
        })
    return sorted(result, key=lambda item: (item["kind"], item["label"], item["id"]))


def _unresolved_summary(index: GraphIndex) -> tuple[dict[str, int], list[dict]]:
    records = []
    for node in index.nodes.values():
        reason = _unresolved_reason(node)
        if reason:
            records.append({
                "id": node["id"], "kind": node["kind"], "label": node["label"],
                "reason": reason, "location": _location(node),
                "query": {"operation": "unresolved", "node_id": node["id"]},
            })
    return dict(sorted(Counter(item["reason"] for item in records).items())), records[:50]


def _component_summaries(
    index: GraphIndex, role_of: dict[str, list[dict]], owners: dict[str, list[dict]],
) -> list[dict]:
    counts = defaultdict(Counter)
    for node_id, chain in owners.items():
        file_owner = next((item for item in chain if item["kind"] == "file"), None)
        if not file_owner:
            continue
        counts[file_owner["id"]]["nodes"] += 1
        for role in role_of.get(node_id, []):
            counts[file_owner["id"]][role.get("role", "Unknown")] += 1
        if _unresolved_reason(index.nodes[node_id]):
            counts[file_owner["id"]]["unresolved"] += 1
    result = []
    for file_id, summary in counts.items():
        file_node = index.nodes[file_id]
        score = summary["Source"] + summary["Sink"] * 2 + summary["EntryPoint"] * 3 \
            + summary["Boundary"] + summary["unresolved"]
        result.append({
            "id": file_id, "label": file_node["label"], "score": score,
            "counts": dict(summary),
            "query": {"operation": "expand", "node_id": file_id},
        })
    return sorted(result, key=lambda item: (-item["score"], item["label"]))[:25]


def build_layered_graph(graph: dict, project_metadata: Optional[dict] = None) -> dict:
    """Create layered-v2 artifacts without changing canonical graph facts."""
    index = GraphIndex(graph, compact=True)
    tier_of, untiered = _tier_assignments(index)
    project_id = _project_id(graph)
    owners = _ownership(graph, index, tier_of, project_id)
    role_of, sinks = derive_roles(graph)
    verdicts = detect_guards(graph, sinks)
    for verdict in verdicts:
        if verdict["status"] == "GUARDED":
            for witness in verdict["witnesses"]:
                role_of[witness].append({
                    "role": "Guard", "subtype": "authz", "confidence": "high",
                    "witnesses": [verdict["handler_id"]],
                })

    node_index = {
        node_id: _locator(node, tier_of[node_id], owners[node_id])
        for node_id, node in index.nodes.items()
    }
    tiers = {
        tier: {
            "schema_version": SCHEMA_VERSION, "tier": tier, "name": TIER_NAMES[tier],
            "purpose": TIER_PURPOSES[tier], "nodes": [], "edges": [],
            "expands_to": [], "links": [],
        } for tier in TIER_ORDER
    }

    verdict_by_call = {
        call_id: verdict for verdict in verdicts for call_id in verdict["sink_call_ids"]
    }
    for node_id, node in index.nodes.items():
        tier = tier_of[node_id]
        roles = list(role_of.get(node_id, []))
        exposed = _exposed_node(
            node, tier, owners[node_id], roles,
            _path_steps(node, index, node_index) if node["kind"] == "taint-reach" else None,
        )
        if node["kind"] == "sink":
            verdict = verdict_by_call.get(node.get("properties", {}).get("callsite_id"))
            if verdict:
                exposed["details"]["guard"] = {
                    "status": verdict["status"], "signal": verdict["guard_signal"],
                    "handler_id": verdict["handler_id"],
                    "differential_siblings": verdict.get("differential_siblings", []),
                }
        tiers[tier]["nodes"].append(exposed)

    cross_count = 0
    for edge in graph.get("edges", []):
        if edge["source"] not in tier_of or edge["target"] not in tier_of:
            continue
        exposed = _exposed_edge(edge, tier_of)
        source_tier, target_tier = exposed["source_tier"], exposed["target_tier"]
        if source_tier == target_tier:
            tiers[source_tier]["edges"].append(exposed)
            continue
        cross_count += 1
        semantic = exposed["kind"]
        if semantic in STRUCTURAL_DRILL_KINDS and (
            STRUCTURAL_RANK[target_tier] - STRUCTURAL_RANK[source_tier] == 1
        ):
            drill = dict(exposed)
            drill["kind"] = "EXPANDS_TO"
            drill["relationship"] = semantic
            tiers[source_tier]["expands_to"].append(drill)
        else:
            tiers[source_tier]["links"].append(exposed)

    # A taint reach is a derived T2 path entity. Materialize direct drills to
    # every ordered witness so consumers never need to scan lower-tier files by
    # opaque ID. These are projection edges, not additional canonical facts.
    for reach in (node for node in index.nodes_of_kind("taint-reach")):
        for position, witness_id in enumerate(
            reach.get("properties", {}).get("witness_ids", [])
        ):
            if witness_id not in tier_of or tier_of[witness_id] == "T2":
                continue
            edge = _derived_edge("PATH_STEP", reach["id"], witness_id, {
                "position": position, "target_tier": tier_of[witness_id],
            })
            edge.update({
                "kind": "EXPANDS_TO", "relationship": "PATH_STEP",
                "source_tier": "T2", "target_tier": tier_of[witness_id],
            })
            tiers["T2"]["expands_to"].append(edge)

    for tier, edge in _rollups(graph, index, tier_of, verdicts):
        tiers[tier]["edges"].append(edge)

    for payload in tiers.values():
        payload["nodes"].sort(key=lambda item: item["id"])
        for collection in ("edges", "expands_to", "links"):
            payload[collection].sort(key=lambda item: item["id"])

    languages = sorted({
        node.get("properties", {}).get("language") for node in index.nodes.values()
        if node.get("properties", {}).get("language")
    })
    frontends = sorted({
        node.get("properties", {}).get("frontend_id") for node in index.nodes.values()
        if node.get("properties", {}).get("frontend_id")
    })
    frontend_capabilities = (
        project_metadata or {}
    ).get("frontend_capabilities", {})
    effective_capabilities = _effective_capabilities(index, frontend_capabilities)
    unresolved_counts, unresolved_examples = _unresolved_summary(index)
    reaches = sorted(index.nodes_of_kind("taint-reach"), key=lambda item: item["id"])
    differentials = [{
        "handler_id": verdict["handler_id"], "handler": verdict["handler_label"],
        "location": {"file": verdict["file"], "start_line": verdict["line"]},
        "sinks": verdict["sink_names"], "guarded_siblings": verdict["differential_siblings"],
        "query": {"operation": "handler-security", "node_id": verdict["handler_id"]},
    } for verdict in verdicts
        if verdict["status"] == "UNGUARDED" and verdict.get("differential_siblings")]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "project": {
            "id": project_id, "languages": languages, "frontends": frontends,
            "capabilities": effective_capabilities,
            "frontend_capabilities": frontend_capabilities,
            "capability_semantics": {
                "capabilities": "effective after canonical overlays composed",
                "frontend_capabilities": "declared by the parser frontend(s)",
            },
            "canonical": {"node_count": len(index.nodes), "edge_count": len(graph.get("edges", []))},
        },
        "node_index": {"file": "node_index.json", "count": len(node_index)},
        "tiers": [{
            "tier": tier, "name": TIER_NAMES[tier], "purpose": TIER_PURPOSES[tier],
            "file": f"{tier.lower()}_{TIER_NAMES[tier]}.json",
            "node_count": len(tiers[tier]["nodes"]),
            "edge_count": len(tiers[tier]["edges"]),
            "expands_to_count": len(tiers[tier]["expands_to"]),
            "link_count": len(tiers[tier]["links"]),
            "operations": TIER_OPERATIONS[tier],
        } for tier in TIER_ORDER],
        "entry_points": _entry_points(index, role_of),
        "security": {
            "source_count": sum(node["kind"] == "source" for node in index.nodes.values()),
            "sink_count": sum(node["kind"] == "sink" for node in index.nodes.values()),
            "reachable_path_count": len(reaches),
            "dynamic_boundary_count": sum(
                node["kind"] in {"boundary", "dynamic-behavior"} for node in index.nodes.values()
            ),
            "guard_differential_count": len(differentials),
            "differentials": differentials,
            "path_queries": [
                {"id": reach["id"], "label": reach["label"],
                 "query": {"operation": "security-path", "node_id": reach["id"]}}
                for reach in reaches[:50]
            ],
        },
        "unresolved": {"counts": unresolved_counts, "examples": unresolved_examples},
        "components": _component_summaries(index, role_of, owners),
        "integrity": {
            "untiered_kinds": untiered, "cross_tier_canonical_edges": cross_count,
            "cross_tier_exposed_edges": sum(
                sum(not edge.get("derived", False) for edge in payload["expands_to"])
                + len(payload["links"]) for payload in tiers.values()
            ),
            "derived_path_drills": sum(
                sum(edge.get("relationship") == "PATH_STEP" for edge in payload["expands_to"])
                for payload in tiers.values()
            ),
        },
    }
    return {"manifest": manifest, "node_index": node_index, "tiers": tiers}


def write_layered_graph(layered: dict, out_dir: str) -> list[str]:
    """Write layered-v2 tier, locator, and manifest artifacts."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for tier in TIER_ORDER:
        path = os.path.join(out_dir, f"{tier.lower()}_{TIER_NAMES[tier]}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(layered["tiers"][tier], handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        written.append(path)
    index_path = os.path.join(out_dir, "node_index.json")
    with open(index_path, "w", encoding="utf-8") as handle:
        json.dump(layered["node_index"], handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    written.append(index_path)
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(layered["manifest"], handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    written.append(manifest_path)
    return written
