"""Materialized five-tier read-only projection of the canonical project graph.

The flat graph from ``build_graph`` (~5.8k nodes / ~23k edges on the fixture) is too
large for an LLM to traverse. This projection re-shapes the SAME graph into five
self-contained tiers so a consumer triages at the top (security summary) and drills
down only into a specific finding:

  T0 Perimeter   — components (files), imports rolled up to DEPENDS_ON.
  T1 Reachability— functions/types/wiring/state with roles; CALLS/HANDLES/GUARDED_BY.
  T2 Path        — taint source -> sink slice with guard verdicts (the differential).
  T3 Body        — statements/expressions/operations/calls/cfg; the function body.
  T4 Proof       — raw IR: SSA, heap, contexts, tokens, source lines.

Two uniform mechanics:
  * EXPANDS_TO — drill from a node to its structural children (reuses build_graph's
    containment edges), one structural step at a time.
  * rollup     — a coarse edge aggregates the fine edges beneath it, carrying
    ``witnesses`` (the finer ids/evidence) + ``weight``.

This module is read-only over its input and never invokes compatibility or source
analysis. Every annotated node is a freshly-built dictionary.
"""
import json
import os
from collections import defaultdict

from .security import derive_roles, detect_guards

# --- tier assignment --------------------------------------------------------
TIER_NAMES = {
    "T0": "perimeter", "T1": "reachability", "T2": "path",
    "T3": "body", "T4": "proof",
}
TIER_ORDER = ["T0", "T1", "T2", "T3", "T4"]

# Structural rank for the EXPANDS_TO one-step rule. T2 (Path) is a derived
# cross-cut, not a structural layer, so it shares T1's rank and never appears as a
# structural containment child.
STRUCTURAL_RANK = {"T0": 0, "T1": 1, "T2": 1, "T3": 2, "T4": 3}

NODE_KIND_TIER = {
    # T0 Perimeter
    "file": "T0", "module": "T0", "import-cycle": "T0",
    # T1 Reachability
    "function": "T1", "method": "T1", "constructor": "T1",
    "class": "T1", "interface": "T1", "type": "T1", "enum": "T1",
    "type-reference": "T1", "dispatch-member": "T1", "wiring-boundary": "T1",
    "dynamic-behavior": "T1", "singleton": "T1", "module-state": "T1",
    "module-initializer": "T1", "static-initializer": "T1", "effect-summary": "T1",
    "function-effect": "T1", "runtime-model-application": "T1", "route": "T1",
    "boundary": "T1", "package": "T0", "external-module": "T0",
    # T2 Path
    "source": "T2", "sink": "T2", "taint-reach": "T2",
    # T3 Body
    "statement": "T3", "expression": "T3", "identifier": "T3",
    "operation": "T3", "call": "T3", "construct": "T3",
    "argument": "T3", "return-value": "T3", "call-return": "T3", "cfg-node": "T3",
    "cfg-entry": "T3", "cfg-exit": "T3", "cfg-condition": "T3", "cfg-merge": "T3",
    "phi": "T3", "exception-site": "T3", "catch-handler": "T3",
    "finally-block": "T3", "promise-rejection": "T3", "type-refinement": "T3",
    "dispatch-candidate": "T3", "scope": "T3",
    # T4 Proof
    "definition": "T4", "read": "T4", "parameter": "T4", "property": "T4",
    "heap-object": "T4",
    "heap-location": "T4", "heap-access": "T4", "heap-effect": "T4",
    "context-heap-effect": "T4", "call-context": "T4", "context-return": "T4",
    "context-parameter": "T4", "context-receiver": "T4", "context-dispatch": "T4",
    "applied-effect": "T4", "type-parameter": "T4", "generic-substitution": "T4",
    "overload": "T4", "type-compatibility": "T4", "async-event": "T4",
    "runtime-symbol": "T4", "receiver-type": "T4", "unresolved-symbol": "T4",
    "dynamic-type-reference": "T4", "token": "T4", "source-line": "T4",
    "data-context": "T4", "source-span": "T4", "value": "T4",
    "variable": "T4", "binding": "T4", "write": "T4", "call-value": "T4",
    "property-path": "T4", "allocation": "T4", "diagnostic": "T4",
    # "symbol" is resolved contextually (module-scope -> T1, function-local -> T3).
}

# Containment edge kinds reused as EXPANDS_TO drill links.
EXPANDS_KINDS = {
    "CONTAINS", "CONTAINS_TYPE", "DECLARES_METHOD", "CONTAINS_CALL",
    "CONTAINS_STATEMENT", "HAS_EXPRESSION", "HAS_OPERATION", "HAS_SCOPE",
    "CONTAINS_SCOPE", "HAS_ARGUMENT", "HAS_RETURN_VALUE", "RETURNS_VALUE",
    "CONTAINS_EXCEPTION_SITE", "CONTAINS_CATCH", "CONTAINS_FINALLY",
    "HAS_CFG_ENTRY", "HAS_CFG_EXIT", "HAS_DISPATCH_CANDIDATE",
    "STATEMENT_CONTAINS_TOKEN", "EXPRESSION_CONTAINS_TOKEN", "HAS_CALL_CONTEXT",
    "STATEMENT_DEFINES", "STATEMENT_READS", "STATEMENT_CALLS", "STATEMENT_ARGUMENT",
    "STATEMENT_RETURNS", "EXPRESSION_DEFINES", "EXPRESSION_READS", "EXPRESSION_CALL",
    "EXPRESSION_ARGUMENT", "EXPRESSION_RETURNS", "DECLARES_SYMBOL", "DEFINES",
    "HAS_WIRING_BOUNDARY", "HAS_EFFECT_SUMMARY", "HAS_FUNCTION_EFFECT",
}


class GraphIndex:
    """Adjacency indexes over the flat graph (read-only)."""

    def __init__(self, graph):
        self.nodes = {node["id"]: node for node in graph["nodes"]}
        self.out = defaultdict(list)
        self.inn = defaultdict(list)
        self.by_kind = defaultdict(list)
        for edge in graph["edges"]:
            self.out[edge["source"]].append(edge)
            self.inn[edge["target"]].append(edge)
            self.by_kind[edge["kind"]].append(edge)


def _function_local_scopes(index):
    """Scope ids that live inside a function body (their symbols are T3, not T1)."""
    local = set()
    frontier = []
    for edge in index.by_kind.get("HAS_SCOPE", []):  # function -> scope
        local.add(edge["target"])
        frontier.append(edge["target"])
    while frontier:
        scope_id = frontier.pop()
        for edge in index.out.get(scope_id, []):  # CONTAINS_SCOPE scope -> child
            if edge["kind"] == "CONTAINS_SCOPE" and edge["target"] not in local:
                local.add(edge["target"])
                frontier.append(edge["target"])
    return local


def _assign_tiers(index):
    """node_id -> tier, plus the set of node kinds that fell through to T4."""
    local_scopes = _function_local_scopes(index)
    symbol_scope = {}  # symbol_id -> declaring scope id
    for edge in index.by_kind.get("DECLARES_SYMBOL", []):  # scope -> symbol
        symbol_scope[edge["target"]] = edge["source"]

    tier_of = {}
    untiered = set()
    for node_id, node in index.nodes.items():
        kind = node["kind"]
        if kind == "symbol":
            scope_id = symbol_scope.get(node_id)
            tier_of[node_id] = "T3" if scope_id in local_scopes else "T1"
            continue
        tier = NODE_KIND_TIER.get(kind)
        if tier is None:
            untiered.add(kind)
            tier = "T4"
        tier_of[node_id] = tier
    return tier_of, untiered


def _emit_expands_to(index, tier_of):
    """EXPANDS_TO drill edges from structural containment (one step down)."""
    seen = set()
    edges = []
    for kind in EXPANDS_KINDS:
        for edge in index.by_kind.get(kind, []):
            parent, child = edge["source"], edge["target"]
            if parent not in tier_of or child not in tier_of or parent == child:
                continue
            # EXPANDS_TO is a cross-tier zoom (one structural step to a finer
            # tier). Every real crossing is delta == 1 (T0->T1, T1->T3, T3->T4).
            # Same-tier containment (delta 0, e.g. function->effect-summary
            # annotation, or statement->expression inside T3) is NOT a drill --
            # it is carried verbatim as an intra-tier fine edge instead.
            delta = STRUCTURAL_RANK[tier_of[child]] - STRUCTURAL_RANK[tier_of[parent]]
            if delta != 1:
                continue
            key = (parent, child)
            if key in seen:
                continue
            seen.add(key)
            edges.append({
                "kind": "EXPANDS_TO", "source": parent, "target": child,
                "properties": {"via": kind},
            })
    return edges


def _rollup_key(bucket, src, tgt):
    return bucket.setdefault((src, tgt), [])


def _build_rollups(index, tier_of, verdicts, sinks):
    """Synthesize coarse edges per tier. Each edge has both endpoints in one tier."""
    edges = []  # each: {tier, kind, source, target, properties}

    # T0 DEPENDS_ON: file imports/re-exports rolled to component dependencies.
    depends = {}
    for kind in ("IMPORTS", "RE_EXPORTS"):
        for edge in index.by_kind.get(kind, []):
            if tier_of.get(edge["source"]) != "T0" or tier_of.get(edge["target"]) != "T0":
                continue
            witness_list = _rollup_key(depends, edge["source"], edge["target"])
            symbols = edge["properties"].get("symbols") or []
            witness_list.append(f"{kind}:{','.join(symbols) or edge['properties'].get('import_kind', '')}")
    for (src, tgt), witnesses in depends.items():
        edges.append({
            "tier": "T0", "kind": "DEPENDS_ON", "source": src, "target": tgt,
            "properties": {"witnesses": sorted(w for w in witnesses if w) or [f"{tgt}"],
                           "weight": len(witnesses)},
        })

    # T1 CALLS: function -> function, grouped, witnesses = call sites.
    calls = {}
    for edge in index.by_kind.get("CALLS", []):
        if tier_of.get(edge["source"]) != "T1" or tier_of.get(edge["target"]) != "T1":
            continue
        witness_list = _rollup_key(calls, edge["source"], edge["target"])
        if edge["properties"].get("callsite"):
            witness_list.append(edge["properties"]["callsite"])
    for (src, tgt), witnesses in calls.items():
        edges.append({
            "tier": "T1", "kind": "CALLS", "source": src, "target": tgt,
            "properties": {"witnesses": sorted(set(witnesses)), "weight": len(witnesses)},
        })

    # T1 HANDLES: wiring-boundary -> handler function.
    for kind in ("WIRES_TO", "ROUTE_HANDLED_BY"):
        for edge in index.by_kind.get(kind, []):
            if tier_of.get(edge["source"]) != "T1" or tier_of.get(edge["target"]) != "T1":
                continue
            edges.append({
                "tier": "T1", "kind": "HANDLES", "source": edge["source"],
                "target": edge["target"],
                "properties": {"witnesses": [edge["source"]], "weight": 1,
                               "confidence": edge["properties"].get("confidence")},
            })

    # T1 GUARDED_BY / UNGUARDED: handler function -> sink function.
    function_by_name = defaultdict(list)
    for node_id, node in index.nodes.items():
        if node["kind"] == "function":
            function_by_name[node["label"]].append(node_id)
    for verdict in verdicts:
        handler = verdict["handler_id"]
        for sink_name in verdict["sink_names"]:
            for sink_fn in function_by_name.get(sink_name, []):
                edges.append({
                    "tier": "T1",
                    "kind": "GUARDED_BY" if verdict["status"] == "GUARDED" else "UNGUARDED",
                    "source": handler, "target": sink_fn,
                    "properties": {
                        "status": verdict["status"],
                        "guard_signal": verdict["guard_signal"],
                        "confidence": verdict["confidence"],
                        "witnesses": sorted(set(verdict["witnesses"] + verdict["sink_call_ids"])),
                        "weight": len(verdict["sink_call_ids"]),
                        "differential_siblings": verdict.get("differential_siblings", []),
                    },
                })

    # T2 REACHES: canonical source -> witnessed reach -> canonical sink.
    for reach in (node for node in index.nodes.values() if node["kind"] == "taint-reach"):
        properties = reach.get("properties", {})
        source_id, sink_id = properties.get("source_id"), properties.get("sink_id")
        witnesses = properties.get("witness_ids", [])
        if not source_id or not sink_id:
            continue
        for source, target in ((source_id, reach["id"]), (reach["id"], sink_id)):
            if tier_of.get(source) != "T2" or tier_of.get(target) != "T2":
                continue
            edges.append({
                "tier": "T2", "kind": "REACHES", "source": source,
                "target": target,
                "properties": {"witnesses": witnesses, "weight": len(witnesses)},
            })

    return edges


def build_layered_graph(graph):
    """Project the flat graph into the materialized 5-tier layered graph."""
    index = GraphIndex(graph)
    tier_of, untiered = _assign_tiers(index)

    role_of, sinks = derive_roles(graph)
    verdicts = detect_guards(graph, sinks)

    # Attach the Guard role to the authz-accessor call carried in each GUARDED verdict.
    for verdict in verdicts:
        if verdict["status"] != "GUARDED":
            continue
        for witness in verdict["witnesses"]:
            node = index.nodes.get(witness)
            if node and node["kind"] == "call":
                role_of[witness].append({
                    "role": "Guard", "subtype": "authz", "confidence": "high",
                    "witnesses": [verdict["handler_id"]],
                })

    # Guard verdict lookup by sink call id, for T2 taint-path annotation.
    verdict_by_call = {}
    for verdict in verdicts:
        for call_id in verdict["sink_call_ids"]:
            verdict_by_call[call_id] = verdict

    rollups = _build_rollups(index, tier_of, verdicts, sinks)
    expands = _emit_expands_to(index, tier_of)
    expand_pairs = {(edge["source"], edge["target"]) for edge in expands}

    # Intra-tier edges carried verbatim so a tier is navigable, not just a node
    # bag. Two cases: (a) the fine tiers T3/T4 keep ALL their intra-tier edges
    # (CFG, data-flow, SSA, heap); (b) EVERY tier keeps same-tier *containment*
    # edges (EXPANDS_KINDS -- HAS_EFFECT_SUMMARY, STATEMENT_CONTAINS_TOKEN, ...)
    # so annotation children (e.g. a T1 function's effect-summary) attach to
    # their owner instead of orphaning. EXPANDS_TO stays a strict cross-tier
    # zoom (delta 1); same-tier containment (delta 0) rides here. Containment
    # kinds never include CALLS/DISPATCHES, so coarse-tier rollups aren't
    # duplicated and T0/T1/T2 stay summarized.
    fine_edges = []  # {tier, kind, source, target, properties}
    for edge in graph["edges"]:
        src_tier = tier_of.get(edge["source"])
        tgt_tier = tier_of.get(edge["target"])
        if src_tier is None or src_tier != tgt_tier:
            continue
        if src_tier not in ("T3", "T4") and edge["kind"] not in EXPANDS_KINDS:
            continue
        if edge["kind"] == "EXPANDS_TO" or (edge["source"], edge["target"]) in expand_pairs:
            continue
        fine_edges.append({
            "tier": src_tier, "kind": edge["kind"], "source": edge["source"],
            "target": edge["target"], "properties": edge.get("properties", {}),
        })

    # --- build per-tier node dicts (fresh objects; input graph untouched) ---
    tiers = {tier: {"tier": tier, "name": TIER_NAMES[tier], "nodes": [],
                    "edges": [], "expands_to": []} for tier in TIER_ORDER}
    role_index = defaultdict(list)

    for node_id, node in index.nodes.items():
        tier = tier_of[node_id]
        properties = dict(node["properties"])
        roles = role_of.get(node_id)
        if roles:
            properties["roles"] = roles
            for role in roles:
                role_index[role["role"]].append(node_id)
        # T2 sink carries its owning call's guard verdict inline.
        if node["kind"] == "sink":
            verdict = verdict_by_call.get(node["properties"].get("callsite_id"))
            if verdict:
                properties["guard_status"] = verdict["status"]
                properties["guard_signal"] = verdict["guard_signal"]
                properties["handler"] = verdict["handler_label"]
                properties["differential_siblings"] = verdict.get("differential_siblings", [])
        tiers[tier]["nodes"].append({
            "id": node_id, "kind": node["kind"], "label": node["label"],
            "properties": properties,
        })

    # --- attack-surface summary per component (T0 file nodes) ---
    file_of_node = {}
    for node_id, node in index.nodes.items():
        path = node["properties"].get("file")
        if path:
            file_of_node[node_id] = path
    surface = defaultdict(lambda: defaultdict(int))
    for role_name, ids in role_index.items():
        for node_id in ids:
            path = file_of_node.get(node_id)
            if path:
                surface[path][role_name] += 1
    for node in tiers["T0"]["nodes"]:
        if node["kind"] == "file":
            counts = surface.get(node["label"])
            if counts:
                node["properties"]["attack_surface"] = dict(counts)

    # --- partition edges + expands_to by tier ---
    for edge in rollups + fine_edges:
        tier = edge.pop("tier")
        tiers[tier]["edges"].append(edge)
    for edge in expands:
        tiers[tier_of[edge["source"]]]["expands_to"].append(edge)

    # --- deterministic ordering ---
    for tier in tiers.values():
        tier["nodes"].sort(key=lambda item: item["id"])
        tier["edges"].sort(key=lambda item: (item["kind"], item["source"], item["target"]))
        tier["expands_to"].sort(key=lambda item: (item["source"], item["target"]))

    # --- differentials (the LLM's triage entrypoint) ---
    differentials = [
        {
            "handler": verdict["handler_label"],
            "file_line": f"{(verdict['file'] or '?').split('/')[-1]}:{verdict['line']}",
            "sink": verdict["sink_names"],
            "status": verdict["status"],
            "guarded_siblings": verdict["differential_siblings"],
            "guard_signal": verdict["guard_signal"],
            "tier": "T2",
        }
        for verdict in verdicts
        if verdict["status"] == "UNGUARDED" and verdict.get("differential_siblings")
    ]

    manifest = {
        "version": 1,
        "generated_from": {"nodes": len(index.nodes),
                           "edges": sum(len(v) for v in index.by_kind.values())},
        "tiers": [
            {"tier": tier, "name": TIER_NAMES[tier], "file": f"{tier.lower()}_{TIER_NAMES[tier]}.json",
             "node_count": len(tiers[tier]["nodes"]),
             "edge_count": len(tiers[tier]["edges"]),
             "expands_to_count": len(tiers[tier]["expands_to"])}
            for tier in TIER_ORDER
        ],
        "role_index": {role: sorted(set(ids)) for role, ids in role_index.items()},
        "guard_verdicts": verdicts,
        "differentials": differentials,
        "untiered_kinds": sorted(untiered),
        "unresolved_placeholders": sum(
            1 for node in index.nodes.values() if node["kind"] == "data-context"
        ),
    }

    return {"manifest": manifest, "tiers": tiers}


def write_layered_graph(layered, out_dir):
    """Write one JSON file per tier + manifest.json. Returns the written paths."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for tier in TIER_ORDER:
        payload = layered["tiers"][tier]
        path = os.path.join(out_dir, f"{tier.lower()}_{TIER_NAMES[tier]}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        written.append(path)
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(layered["manifest"], handle, indent=2, ensure_ascii=False)
    written.append(manifest_path)
    return written
