"""Native whole-graph translation adapter.

The Rust preparer already owns the sidecar walk and emits calls, CFGs, and lifetime
operations.  This module only projects that binary result into the legacy F-shaped
boundary used by the remaining semantic matcher.  It is deliberately opt-in while
its recall is compared with :func:`translate.build_F`.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import os
from pathlib import Path
import tempfile

from . import atropos
from .coverage import CoveragePlan, CoverageRegion, CoverageScheduler
from .normalize import normalizer
from .source_discovery import SourceDiscovery, SourceSite, SeamBinding, discover_sources
from .native_lifetime import (plan_pass2_pb, plan_path, semantic_path, summaries_path,
                               temporal_path, translate_graph_pb)
from .translate import _expression_root, _guard_info, _header_node, _span
from lachesis.planner.unbounded_copy import BranchRegions
from lachesis.nav.dataflow.substrate import (
    cached_substrate, substrate_cache_path, translation_cache_path,
    translation_facts_path, pass2_input_cache_path,
)
from lachesis.core import lifetime_pb2


def _props(node):
    return node.get("properties") or {}


def _name(sub, node_id):
    if sub is None:
        return node_id or ""
    return sub.label(node_id) or node_id


def _path_root(sub, path):
    root = (path.root or "").removeprefix("decl:")
    value = _name(sub, root)
    return value + "".join(path.selectors)


def _call_path(sub, root, selectors=()):
    root = (root or "").removeprefix("decl:")
    return _name(sub, root) + "".join(selectors) if root else None


def _argument_root(sub, argument):
    if getattr(argument, "root_name", ""):
        return argument.root_name + "".join(argument.selectors)
    root = (argument.root or "").removeprefix("decl:")
    if sub is None:
        return _expression_root(argument.expression)
    if root and sub.kind(root) in {"VarDecl", "ParmVarDecl", "parameter", "variable"}:
        return _call_path(sub, argument.root, argument.selectors)
    return _expression_root(argument.expression)


def _native_prepared(index):
    base = (getattr(index, "_pass3_cache_base", None)
            or getattr(index, "_db_dir", None))
    if not base:
        return None
    facts_path = translation_facts_path(base)
    if facts_path.is_file():
        cached = getattr(index, "_native_translation", None)
        if cached is not None:
            return cached
        result = lifetime_pb2.TranslationResult()
        try:
            result.ParseFromString(facts_path.read_bytes())
        except Exception:
            result = None
        if result is not None and result.functions:
            prepared = {function.id: function for function in result.functions}
            index._native_translation = prepared
            return prepared

    sidecar = translation_cache_path(base)
    if not sidecar.is_file():
        sidecar = substrate_cache_path(base)
    if not sidecar.is_file():
        return None
    cached = getattr(index, "_native_translation", None)
    if cached is not None:
        return cached
    prepared = translate_graph_pb(sidecar)
    index._native_translation = prepared
    return prepared


def _compiled_catalog(root, base):
    """Return a versioned protobuf catalog sidecar for the native path planner."""
    models_root = Path(root) / "models"
    model_files = sorted(models_root.rglob("*.json"))
    fingerprint = hashlib.sha256()
    for path in model_files:
        try:
            stat = path.stat()
        except OSError:
            continue
        fingerprint.update(str(path).encode())
        fingerprint.update(str(stat.st_mtime_ns).encode())
        fingerprint.update(str(stat.st_size).encode())
    target = Path(f"{base}.atropos.{fingerprint.hexdigest()[:16]}.catalog.pb")
    if not target.is_file():
        from lachesis.integrations.atropos.native_bind import compile_catalog
        compile_catalog(models_root, target)
    return target


def _native_plan(functions, prepared, source_catalog, *, facts_path=None,
                 catalog_path=None):
    """Adapt the native plan protobuf to the existing Python envelope."""
    def _argument_position(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return value

    if facts_path is not None and catalog_path is not None:
        output = tempfile.NamedTemporaryFile(prefix="lachesis-plan-", suffix=".pb",
                                              delete=False)
        output.close()
        try:
            result = plan_path(facts_path, catalog_path, output.name)
        finally:
            try:
                os.unlink(output.name)
            except OSError:
                pass
    else:
        result = plan_pass2_pb(prepared, source_catalog)
    by_name = {item.name: item for item in result.functions}
    discovery_sites = []
    launch_nodes = {}
    launch_provenance = {}
    provenance = {}
    reachable = set()
    influenced = {}
    for name, record in functions.items():
        item = by_name.get(name)
        if item is None:
            continue
        for site in item.source_sites:
            discovery_sites.append(SourceSite(
                name, site.node or None, site.callee or None,
                site.line if site.has_line else None,
                tuple(_argument_position(value) for value in site.arguments),
                tuple(site.influenced_roots),
                site.kind or "external-input"))
        if item.launch_nodes:
            launch_nodes[name] = tuple(item.launch_nodes)
        if item.launch_provenance:
            launch_provenance[name] = item.launch_provenance
        provenance[name] = tuple(item.provenance)
        influenced[name] = tuple(item.influenced_roots)
        if item.reachable:
            reachable.add(name)
    bindings = tuple(
        SeamBinding(item.caller, item.callee, item.call_node or None,
                    tuple(value.split("\x1f", 1) for value in item.formal_to_actual),
                    item.return_to or None)
        for item in result.bindings)
    discovery = SourceDiscovery(
        tuple(discovery_sites), bindings, launch_nodes, launch_provenance,
        provenance, reachable, influenced)
    regions = []
    for item in result.regions:
        state_keys = tuple(tuple(value.split("\x1f")) for value in item.state_keys)
        context_keys = tuple(tuple(value.split("\x1f")) for value in item.context_keys)
        regions.append(CoverageRegion(item.target, tuple(item.sources),
                                      tuple(item.functions), state_keys,
                                      context_keys))
    coverage = CoveragePlan(tuple(regions), frozenset(result.covered_functions),
                            frozenset(result.uncovered_functions))
    return discovery, coverage


def build_native_F(store, lang="c", *, return_graph=False):
    index = store.index
    base = (getattr(index, "_pass3_cache_base", None)
            or getattr(index, "_db_dir", None))
    prepared = _native_prepared(index)
    if prepared is None:
        return None
    # Rust emits resolved root labels and declaration metadata in the compact
    # translation result.  Keep the million-node Python substrate out of the
    # normal path; only old/incomplete sidecars use it as a compatibility
    # fallback.
    native_complete = all(
        getattr(item, "name", "") and
        all(getattr(arg, "root_name", "") or not arg.root
            for call in item.calls for arg in call.arguments)
        for item in prepared.values()
    )
    sub = None if native_complete else cached_substrate(index)
    norm = normalizer(lang)
    sinks = atropos.sink_catalog(lang)
    source_names = set(atropos.source_catalog(lang))
    graph = store.graph if store.graph is not None else index
    regions = BranchRegions(graph)

    recs = {}
    for function_id, item in prepared.items():
        if not item.name and sub is None:
            continue
        name = item.name or _name(sub, function_id) or function_id
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
                     "root": _argument_root(sub, arg),
                     "var": _argument_root(sub, arg),
                     "value": _argument_root(sub, arg) or arg.expression,
                     "expr": arg.expression or _name(sub, arg.node),
                     "provenance": "const" if not arg.root else "local"}
                    for arg in call.arguments]
            assigned = (getattr(call, "assigned_name", "") + "".join(call.assigned_selectors)
                        if getattr(call, "assigned_name", "") else None)
            assigned = (assigned or _call_path(sub, call.assigned_root, call.assigned_selectors)
                        or (_name(sub, call.assigned) if call.assigned else None))
            call_header = _header_node(index, call.node)
            catalog = sinks.get(callee)
            guard_args = args
            if catalog is not None and catalog.get("size_arg") is not None:
                guard_args = [arg for arg in args
                              if arg.get("pos") == catalog.get("size_arg")]
            guard_roots = {_expression_root(arg["root"])
                           for arg in guard_args if arg.get("root")}
            guard_roots.discard(None)
            guards, guard_status = _guard_info(
                regions, function_id, guard_roots, _span(call_header))
            record = {
                "callee": callee, "line": call.line if call.has_line else None,
                "args": args, "guards": guards, "guard_status": guard_status,
                "guard_predicates": tuple(g.get("canon") for g in guards if g.get("canon")),
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
                record["size_expr"] = size.get("expr") if size else None
                record["dst"] = assigned if call.is_alloc else (args[0].get("value") if args else None)
            calls.append(record)
            callees.append(callee)
            if assigned:
                assigns.append({"var": assigned, "callee": callee,
                                "line": record["line"], "node": call.node})

        events = []
        for operation in getattr(item, "operations", ()):
            kind = lifetime_pb2.Operation.Kind.Name(operation.kind)
            # Native preparation also records assignment-side writes as USE
            # operations. They are state transitions, not dereference events in
            # the F projection; exposing them here creates spurious UAF leads.
            if (kind not in {"ALLOC", "FREE", "USE"} or
                    operation.target is None or
                    (kind == "USE" and operation.access == "write")):
                continue
            target_root = operation.target.root.removeprefix("decl:")
            if sub is None or sub.kind(target_root) not in {"VarDecl", "ParmVarDecl", "parameter", "variable"}:
                continue
            event_kind = {"ALLOC": "alloc", "FREE": "free", "USE": "use"}[kind]
            events.append({"kind": event_kind,
                           "family": {"alloc": "memory.alloc", "free": "memory.free",
                                      "use": "memory.deref"}[event_kind],
                           "var": _path_root(sub, operation.target),
                           "line": operation.line if operation.has_line else None,
                           "node": operation.node})
        # The compact translation ABI intentionally omits the full operation
        # stream. Preserve the lifecycle events that are directly represented
        # on native calls so the semantic F projection remains useful.
        for call in item.calls:
            line = call.line if call.has_line else None
            if call.is_alloc and call.assigned_root:
                events.append({"kind": "alloc", "family": "memory.alloc",
                               "var": _call_path(sub, call.assigned_root,
                                                   call.assigned_selectors),
                               "line": line, "node": call.node})
            if call.is_release and call.arguments:
                argument = call.arguments[0]
                root = _argument_root(sub, argument)
                if root:
                    events.append({"kind": "free", "family": "memory.free",
                                   "var": root, "line": line, "node": call.node,
                                   "callee": call.callee})
        params = tuple(item.parameter_names) or tuple(_name(sub, value) for value in item.parameters)
        returns = []
        for returned in item.returns:
            value = {
                "kind": returned.kind,
                "line": returned.line if returned.has_line else None,
            }
            if returned.kind == "call":
                value["callee"] = returned.callee
            elif returned.root:
                value["var"] = (getattr(returned, "root_name", "") + "".join(returned.selectors)
                                 if getattr(returned, "root_name", "")
                                 else _call_path(sub, returned.root, returned.selectors))
                value["prov"] = "param" if value["var"] in params else "local"
            returns.append(value)
        recs[name] = {
            "function_id": function_id,
            "name": name, "file": item.file or None,
            "line": item.start_line if item.has_start_line else None,
            "externally_visible": item.externally_visible,
            "params": params, "calls": calls, "events": events,
            "assigns": assigns, "returns": returns, "callees": callees,
            "body_node_count": len(getattr(item, "nodes", ())),
            "cfg": None,
            "root_metadata": {
                item.id: (item.label, item.owner, item.type)
                for item in getattr(item, "roots", ())
            },
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
    # The compact facts already contain the complete call graph and source
    # roots.  Keep source discovery and coverage planning in the same Rust
    # process as translation; Python only adapts the typed result for legacy
    # consumers below.
    try:
        # The native planner is now the default: full libxml2 parity covers
        # duplicate symbols, source sites, reachability, and influence roots.
        # Set this escape hatch only when diagnosing an older native library.
        if os.environ.get("LACHESIS_NATIVE_PLAN") == "0":
            raise RuntimeError("native planner explicitly disabled")
        facts_path = translation_facts_path(base)
        from lachesis.integrations.atropos.enrich import locate_atropos
        atropos_root = locate_atropos()
        catalog_path = (_compiled_catalog(atropos_root, base)
                        if facts_path.is_file() and atropos_root is not None else None)
        discovery, coverage = _native_plan(
            functions, prepared, atropos.source_catalog(lang),
            facts_path=facts_path if facts_path.is_file() else None,
            catalog_path=catalog_path)
    except RuntimeError:
        # Older development builds may not expose the planner symbol yet.  The
        # native translation result remains usable while the compatibility path
        # keeps existing callers functional.
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
    return (functions, succ, graph) if return_graph else (functions, succ)


def build_native_summaries(store, lang="c"):
    """Return the compact native reach summaries when binary inputs are available.

    This adapter is deliberately separate from ``build_native_F``: callers can
    compare the native summary domain with Python before enabling it, without
    changing translation selection or silently weakening coverage.
    """
    base = (getattr(store.index, "_pass3_cache_base", None)
            or getattr(store.index, "_db_dir", None))
    if not base:
        return None
    facts = translation_facts_path(base)
    root = __import__("lachesis.integrations.atropos.enrich", fromlist=["locate_atropos"])
    root = root.locate_atropos()
    if not facts.is_file() or root is None:
        return None
    catalog = _compiled_catalog(root, base)
    output = tempfile.NamedTemporaryFile(prefix="lachesis-summary-", suffix=".pb", delete=False)
    output.close()
    try:
        result = summaries_path(facts, catalog, output.name)
    except (OSError, RuntimeError, ValueError):
        return None
    finally:
        try:
            os.unlink(output.name)
        except OSError:
            pass
    summaries = {}
    for item in result.functions:
        sink_params = defaultdict(list)
        for record in item.sink_params:
            sink_params[record.parameter].append({
                "sink": record.sink, "guards": list(record.guards),
                "guarded": record.guarded,
            })
        summaries[item.name] = {
            "name": item.name, "params": tuple(item.parameters),
            "taxonomy": "UDF", "sink_flows": [{
                "sink": record.sink, "value": record.value, "root": record.root,
                "provenance": record.provenance, "guards": list(record.guards),
                "guarded": record.guarded, "site_guarded": record.site_guarded,
                "via": record.via,
            } for record in item.sink_flows],
            "sink_params": dict(sink_params), "typestate": {},
            "param_typestate": {}, "frees_params": {}, "returns": "value",
            "returns_param": None, "returns_dangling": False,
        }
    return summaries


def build_native_temporal(store):
    """Run the compact Rust temporal solver from the Pass-1 path.

    This is an opt-in migration seam.  It intentionally returns the protobuf
    result rather than pretending that findings are equivalent to the richer
    semantic graph used by the compatibility matcher.
    """
    base = (getattr(store.index, "_pass3_cache_base", None)
            or getattr(store.index, "_db_dir", None))
    if not base:
        return None
    input_path = pass2_input_cache_path(base)
    if not input_path.is_file():
        return None
    output_path = Path(f"{base}.pass3.temporal.pb")
    if not output_path.is_file():
        temporal_path(input_path, output_path)
    from .native_lifetime import lifetime_pb2
    result = lifetime_pb2.NativeTemporalResult()
    result.ParseFromString(output_path.read_bytes())
    return result


def build_native_semantic_graph(store, lang="c"):
    """Decode the compact Rust event graph into the query graph only."""
    base = (getattr(store.index, "_pass3_cache_base", None)
            or getattr(store.index, "_db_dir", None))
    if not base:
        return None
    input_path = pass2_input_cache_path(base)
    if not input_path.is_file():
        return None
    output_path = native_semantic_sidecar_path(store)
    result = semantic_path(input_path, output_path) if not output_path.is_file() else None
    if result is None:
        from .native_lifetime import lifetime_pb2
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(output_path.read_bytes())
    return _decode_native_semantic_result(result, lang)


def ensure_native_semantic_sidecar(store):
    """Create the Rust semantic sidecar without decoding it in Python."""
    base = (getattr(store.index, "_pass3_cache_base", None)
            or getattr(store.index, "_db_dir", None))
    if not base:
        return None
    input_path = pass2_input_cache_path(base)
    if not input_path.is_file():
        return None
    output_path = native_semantic_sidecar_path(store)
    if not output_path.is_file():
        semantic_path(input_path, output_path)
    events_path = native_semantic_events_path(output_path)
    if not events_path.is_file():
        # Older full semantic caches predate the event-only publication. Re-run
        # once into a temporary result so Rust can publish the compact sibling;
        # keep the existing full cache intact for advanced queries.
        temporary = Path(f"{output_path}.events-migrate.{os.getpid()}")
        try:
            semantic_path(input_path, temporary)
            generated = native_semantic_events_path(temporary)
            os.replace(generated, events_path)
        finally:
            try:
                temporary.unlink()
            except OSError:
                pass
    return output_path if output_path.is_file() else None


def load_native_semantic_graph_sidecar(path, lang="c"):
    """Decode a native semantic sidecar for a query that needs its nodes."""
    from .native_lifetime import lifetime_pb2
    try:
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(Path(path).read_bytes())
    except (OSError, ValueError):
        return None
    return _decode_native_semantic_result(result, lang)


def native_semantic_events_path(path) -> Path:
    """Return the event-only sidecar emitted beside the full semantic graph."""
    return Path(f"{path}.events.pb")


def load_native_semantic_events_sidecar(path, lang="c"):
    """Load only operation-derived nodes needed by temporal candidate queries."""
    from .semantic_graph import Event, EventKind, ObjRef, SkeletonGraph
    try:
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(native_semantic_events_path(path).read_bytes())
    except (OSError, ValueError):
        return None
    graph = SkeletonGraph(language=lang)
    for function in result.functions:
        for node in function.nodes:
            if not node.event_kind:
                continue
            kind = getattr(EventKind, node.event_kind, node.event_kind)
            obj = (ObjRef(node.object_root, tuple(node.object_selectors),
                          node.generation or "g0") if node.object_root else None)
            event = Event(kind, obj=obj, base=obj, path="*" if obj else None,
                          line=node.line if node.has_line else None)
            graph.add_node(node.id, event, fragment=function.id,
                           owner_function_id=function.id, native_anchor=node.anchor)
    if not result.complete:
        graph.coverage["converged"] = False
    return graph


def _decode_native_semantic_result(result, lang):
    from .semantic_graph import Event, EventKind, ObjRef, SkeletonGraph

    graph = SkeletonGraph(language=lang)
    for function in result.functions:
        if not function.nodes:
            continue
        node_ids = {node.id for node in function.nodes}
        for node in function.nodes:
            event = None
            if node.event_kind:
                kind = getattr(EventKind, node.event_kind, node.event_kind)
                obj = (ObjRef(node.object_root, tuple(node.object_selectors),
                              node.generation or "g0") if node.object_root else None)
                event = Event(kind, obj=obj, base=obj,
                              path="*" if obj is not None else None,
                              line=node.line if node.has_line else None)
            graph.add_node(node.id, event, fragment=function.id,
                           owner_function_id=function.id, native_anchor=node.anchor)
        for edge in function.edges:
            if edge.source in node_ids and edge.target in node_ids:
                graph.add_edge(edge.source, edge.target, kind=edge.kind or "normal")
        exits = [node for node in function.exits if node in node_ids]
        graph.add_fragment(function.id, function.entry if function.entry in node_ids else function.nodes[0].id,
                           exits=exits or [function.nodes[-1].id])
    if not result.complete:
        graph.coverage["converged"] = False
    return graph


def native_semantic_sidecar_path(store) -> Path | None:
    """Return the compact Rust semantic sidecar location for ``store``."""
    base = (getattr(store.index, "_pass3_cache_base", None)
            or getattr(store.index, "_db_dir", None))
    return Path(f"{base}.pass3.semantic.pb") if base else None
