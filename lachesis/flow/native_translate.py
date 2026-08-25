"""Native whole-graph translation adapter.

The Rust preparer already owns the sidecar walk and emits calls, CFGs, and lifetime
operations.  This module only projects that binary result into the legacy F-shaped
boundary used by the remaining semantic matcher.  It is deliberately opt-in while
its recall is compared with :func:`translate.build_F`.
"""
from __future__ import annotations

from collections import defaultdict

from . import atropos
from .coverage import CoverageScheduler
from .normalize import normalizer
from .source_discovery import discover_sources
from .native_lifetime import prepare_graph_pb
from lachesis.nav.dataflow.substrate import cached_substrate, substrate_cache_path
from lachesis.core import lifetime_pb2


def _props(node):
    return node.get("properties") or {}


def _name(sub, node_id):
    return sub.label(node_id) or node_id


def _path_root(sub, path):
    root = (path.root or "").removeprefix("decl:")
    value = _name(sub, root)
    return value + "".join(path.selectors)


def _call_path(sub, root, selectors=()):
    root = (root or "").removeprefix("decl:")
    return _name(sub, root) + "".join(selectors) if root else None


def _native_prepared(index):
    base = (getattr(index, "_pass3_cache_base", None)
            or getattr(index, "_db_dir", None))
    if not base:
        return None
    sidecar = substrate_cache_path(base)
    if not sidecar.is_file():
        return None
    cached = getattr(index, "_native_prepared", None)
    if cached is not None:
        return cached
    prepared = prepare_graph_pb(sidecar)
    index._native_prepared = prepared
    return prepared


def build_native_F(store, lang="c", *, return_graph=False):
    index = store.index
    prepared = _native_prepared(index)
    if prepared is None:
        return None
    sub = cached_substrate(index).load()
    norm = normalizer(lang)
    sinks = atropos.sink_catalog(lang)
    source_names = set(atropos.source_catalog(lang))
    function_nodes = {}
    for node in index.nodes_of_kind("function", "method", "constructor"):
        if _props(node).get("declaration_only"):
            continue
        function_nodes[node["id"]] = node

    recs = {}
    for function_id, item in prepared.items():
        node = function_nodes.get(function_id)
        if node is None:
            continue
        name = node.get("label") or function_id
        if name in recs:
            name = f"{name}@{function_id}"
        calls = []
        callees = []
        assigns = []
        for call in item.calls:
            callee = norm.canon_callee(call.callee) or call.callee
            if not callee:
                continue
            args = [{"pos": arg.position, "node": arg.node,
                     "root": _call_path(sub, arg.root, arg.selectors) or _name(sub, arg.node),
                     "var": _call_path(sub, arg.root, arg.selectors) or _name(sub, arg.node),
                     "value": _call_path(sub, arg.root, arg.selectors) or _name(sub, arg.node)}
                    for arg in call.arguments]
            assigned = (_call_path(sub, call.assigned_root, call.assigned_selectors)
                        or (_name(sub, call.assigned) if call.assigned else None))
            catalog = sinks.get(callee)
            record = {
                "callee": callee, "line": call.line if call.has_line else None,
                "args": args, "guards": [], "guard_status": "not-computed",
                "guard_predicates": (),
                "is_sink": catalog is not None,
                "sink_name": callee if catalog is not None else None,
                "sink_family": catalog.get("family") if catalog else None,
                "assigned": assigned, "receiver": call.receiver or None,
                "node": call.node, "control": (),
            }
            if catalog is not None:
                size_arg = catalog.get("size_arg")
                record["sink"] = {"size_arg": size_arg}
                size = next((arg for arg in args if arg["pos"] == size_arg), None)
                record["size_expr"] = size.get("value") if size else None
                record["dst"] = assigned if call.is_alloc else (args[0].get("value") if args else None)
            calls.append(record)
            callees.append(callee)
            if assigned:
                assigns.append({"var": assigned, "callee": callee,
                                "line": record["line"], "node": call.node})

        events = []
        for operation in item.operations:
            kind = lifetime_pb2.Operation.Kind.Name(operation.kind)
            # Native preparation also records assignment-side writes as USE
            # operations. They are state transitions, not dereference events in
            # the F projection; exposing them here creates spurious UAF leads.
            if (kind not in {"ALLOC", "FREE", "USE"} or
                    operation.target is None or
                    (kind == "USE" and operation.access == "write")):
                continue
            target_root = operation.target.root.removeprefix("decl:")
            if sub.kind(target_root) not in {"VarDecl", "ParmVarDecl", "parameter", "variable"}:
                continue
            event_kind = {"ALLOC": "alloc", "FREE": "free", "USE": "use"}[kind]
            events.append({"kind": event_kind,
                           "family": {"alloc": "memory.alloc", "free": "memory.free",
                                      "use": "memory.deref"}[event_kind],
                           "var": _path_root(sub, operation.target),
                           "line": operation.line if operation.has_line else None,
                           "node": operation.node})
        params = tuple(_name(sub, value) for value in item.parameters)
        recs[name] = {
            "name": name, "file": _props(node).get("file"),
            "line": _props(node).get("start_line"),
            "externally_visible": _props(node).get("storage_class") != "static",
            "params": params, "calls": calls, "events": events,
            "assigns": assigns, "returns": [], "callees": callees,
            "body_node_count": len(item.nodes),
            "cfg": {"nodes": tuple(item.nodes), "entry": item.nodes[0] if item.nodes else None,
                    "succ": {entry.node: tuple(entry.targets) for entry in item.successors}},
        }

    reverse_callers = defaultdict(set)
    reachable = set()
    for name, record in recs.items():
        for call in record["calls"]:
            callee = call["callee"]
            if call.get("is_sink") or norm.is_acquire(callee) or norm.is_release(callee) or norm.is_realloc(callee):
                reachable.add(name)
            elif callee in recs:
                reverse_callers[callee].add(name)
    pending = list(reachable)
    while pending:
        callee = pending.pop()
        for caller in reverse_callers.get(callee, ()):
            if caller not in reachable:
                reachable.add(caller)
                pending.append(caller)

    callers = {name: set() for name in recs}
    for name, record in recs.items():
        for callee in record["callees"]:
            if callee in recs:
                callers[callee].add(name)
    functions = {}
    for name, record in recs.items():
        udf = sorted({callee for callee in record["callees"] if callee in recs})
        ldf = sorted({callee for callee in record["callees"] if callee not in recs})
        sink_ldf = sorted({callee for callee in ldf
                           if callee in sinks or norm.is_acquire(callee)
                           or norm.is_release(callee) or norm.is_realloc(callee)})
        functions[name] = {
            **record, "taxonomy": ("LS-UDF" if not udf and sink_ldf else
                                    "LUDF" if not udf else
                                    "S-UDF" if name in reachable else "UDF"),
            "is_source": not callers[name], "udf_callees": udf,
            "ldf_callees": ldf, "sink_ldf_callees": sink_ldf,
            "callers": sorted(callers[name]),
            "source_calls": [{"callee": call["callee"], "line": call.get("line"),
                              "node": call.get("node"), "assigned": call.get("assigned"),
                              "args": [arg["pos"] for arg in call.get("args", ())]}
                             for call in record["calls"] if call["callee"] in source_names],
            "source_reachable": not callers[name] or any(
                call["callee"] in source_names for call in record["calls"]),
        }
    succ = {name: [callee for callee in record["udf_callees"] if callee in functions]
            for name, record in functions.items()}
    discovery = discover_sources(functions, succ, atropos.source_catalog(lang))
    coverage = CoverageScheduler(functions, succ).plan()
    coverage_by_target = {region.target: region for region in coverage.regions}
    for name, record in functions.items():
        record["source_sites"] = [{"node": site.node, "callee": site.callee,
                                   "line": site.line, "arguments": list(site.arguments),
                                   "influenced_roots": list(site.influenced_roots),
                                   "kind": site.kind} for site in discovery.sites_for(name)]
        record["seam_bindings"] = []
        record["source_reachable"] = name in discovery.reachable_functions
        provenance = discovery.provenance_by_function.get(name, ())
        record["source_provenance"] = (provenance[0] if len(provenance) == 1 else
                                        "mixed" if provenance else "unreachable")
        record["source_influenced_roots"] = discovery.influenced_roots.get(name, ())
        region = coverage_by_target.get(name)
        record["coverage_sources"] = region.sources if region else ()
        record["coverage_functions"] = region.functions if region else ()
        record["coverage_state_keys"] = region.state_keys if region else ()
        record["coverage_unresolved"] = name in coverage.uncovered_functions
    try:
        store._pass3_coverage_cache = (functions, succ, coverage)
    except AttributeError:
        pass
    graph = store.graph if store.graph is not None else index
    return (functions, succ, graph) if return_graph else (functions, succ)
