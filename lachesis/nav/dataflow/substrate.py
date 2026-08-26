"""Substrate adapter — synthesize an expression-level CFG-node stream over our CPG.

The reaching-def pass runs over a CFG where every expression/call/identifier is a node with
CFG order. Our kuzu CPG's CFG_NEXT is BASIC-BLOCK granular (statement nodes only; 0 expressions
on the CFG). This adapter reconstructs the per-expression order that pass assumes:

  * basic blocks (statement nodes) are chained by CFG_NEXT;
  * within a block, the contained defs/uses are linearized by `start_offset` (source order),
    with the RHS-before-LHS rule for assignments (a store's operands evaluate before the store).

It also maps our C-frontend node kinds onto dataflow roles (param / call / identifier / fieldAccess /
literal), which the gen/kill transfer function keys on.

Pure reader over a GraphStore index; no mutation, no load_graph.
"""
import os
import tempfile
from collections import defaultdict
from pathlib import Path

from lachesis.core.graph_wire import (
    decode_document, decode_edge, decode_node,
    encode_document, encode_edge, encode_node,
    read_frames, write_frame,
)
from lachesis.core import lifetime_pb2

from lachesis.timeit import timeit

# --- role mapping: C-frontend syntax_kind -> dataflow node role ----------------
# casts/parens are transparent wrappers we peel when resolving a base object.
_CASTS = {"ImplicitCastExpr", "CStyleCastExpr", "ParenExpr", "CXXConstCastExpr",
          "CXXStaticCastExpr", "CXXReinterpretCastExpr"}
# field/index/indirection access — the field-access set (gen/kill transparent).
_FIELD_ACCESS = {"MemberExpr", "ArraySubscriptExpr"}
_LITERALS = {"IntegerLiteral", "FloatingLiteral", "StringLiteral", "CharacterLiteral",
             "CXXBoolLiteralExpr", "ImplicitValueInitExpr", "GNUNullExpr"}
_CALLISH = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr", "BinaryOperator",
            "UnaryOperator", "CompoundAssignOperator", "ConditionalOperator"}

_CACHE_VERSION = 4
_CACHE_SUFFIX = ".pass3.substrate.pb"
_PASS2_INPUT_VERSION = 1
_PASS2_INPUT_SUFFIX = ".pass2.input.pb"
_TRANSLATION_CACHE_SUFFIX = ".pass2.translation.pb"
_TRANSLATION_FACTS_SUFFIX = ".pass2.facts.pb"
_SUBSTRATE_NODE_KINDS = frozenset({
    "ArraySubscriptExpr", "BinaryOperator", "BreakStmt", "CallExpr", "CaseStmt",
    "CompoundAssignOperator", "CompoundStmt", "ConditionalOperator", "ContinueStmt",
    "CXXMemberCallExpr", "CXXNullPtrLiteralExpr", "CXXOperatorCallExpr", "DeclRefExpr",
    "DeclStmt", "DefaultStmt", "DoStmt", "ForStmt", "GNUNullExpr", "GotoStmt",
    "IfStmt", "ImplicitCastExpr", "ImplicitValueInitExpr", "IntegerLiteral", "LabelStmt",
    "MemberExpr", "ParenExpr", "ParmVarDecl", "ReturnStmt", "StringLiteral", "SwitchStmt",
    "UnaryOperator", "UnaryExprOrTypeTraitExpr", "VarDecl", "WhileStmt", "cfg-entry",
    "cfg-exit", "cfg-merge", "cfg-condition", "function", "method", "constructor",
    "FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl",
})
_SUBSTRATE_PROPERTY_KEYS = frozenset({
    "absolute_file", "end_line", "end_offset", "file", "function_id",
    "operator", "owner_function_id", "receiver", "receiver_id",
    "receiver_symbol_id", "receiver_value", "receiver_value_id",
    "start_line", "start_offset", "syntax_kind", "type",
    # Native Pass-2 input.  These are scalar call-site facts already produced
    # during Pass 1; retaining them in the binary substrate lets Rust consume
    # the graph without asking Python to rebuild per-function call records.
    "callee", "form", "method_name", "primary_target_id",
    "receiver_member_id", "resolution", "allocation_kind", "allocated_type",
    "control_kind", "is_alloc", "is_release", "is_realloc", "is_aggregate_copy",
    "declaration_only", "storage_class", "owner_id",
})


def substrate_cache_path(graph_path):
    return Path(str(graph_path).rstrip("/") + _CACHE_SUFFIX)


def pass2_input_cache_path(graph_path):
    """Complete typed Pass-2 input emitted beside a Pass-1 store."""
    return Path(str(graph_path).rstrip("/") + _PASS2_INPUT_SUFFIX)


def translation_cache_path(graph_path):
    return Path(str(graph_path).rstrip("/") + _TRANSLATION_CACHE_SUFFIX)


def translation_facts_path(graph_path):
    return Path(str(graph_path).rstrip("/") + _TRANSLATION_FACTS_SUFFIX)


_PATH_CASTS = {
    "ImplicitCastExpr", "CStyleCastExpr", "ParenExpr", "CXXConstCastExpr",
    "CXXStaticCastExpr", "CXXReinterpretCastExpr", "CXXFunctionalCastExpr",
}


def _translation_facts(nodes, records):
    """Project the Pass-1 records into the compact native translation ABI."""
    by_id = {node["id"]: node for node in nodes}
    children = defaultdict(list)
    parents = {}
    refers = {}
    source_edges = defaultdict(list)
    for edge in records:
        source, target = edge["source"], edge["target"]
        source_edges[source].append(edge)
        if edge["kind"] == "AST_CHILD":
            children[source].append((target, (edge.get("properties") or {}).get("role", "")))
            parents.setdefault(target, source)
        elif edge["kind"] == "REFERS_TO":
            refers[source] = target

    def props(node):
        return node.get("properties") or {}

    def syntax(node_id):
        node = by_id.get(node_id)
        return (props(node).get("syntax_kind") or node.get("kind")) if node else ""

    def peel(node_id):
        for _ in range(12):
            if syntax(node_id) not in _PATH_CASTS:
                break
            items = children.get(node_id, ())
            if not items:
                break
            node_id = items[0][0]
        return node_id

    def path(node_id, depth=0):
        if not node_id or depth > 40:
            return None
        node_id = peel(node_id)
        node = by_id.get(node_id)
        if node is None:
            return None
        kind = syntax(node_id)
        if kind == "DeclRefExpr":
            return path(refers.get(node_id), depth + 1)
        if kind in {"ParmVarDecl", "VarDecl"}:
            return (f"decl:{node_id}", [])
        if kind == "MemberExpr":
            items = children.get(node_id, ())
            base = path(items[0][0], depth + 1) if items else None
            if base is None:
                return None
            label = node.get("label") or ""
            if "->" in label:
                index, width, arrow = label.rfind("->"), 2, True
            elif "." in label:
                index, width, arrow = label.rfind("."), 1, False
            else:
                return base
            field = label[index + width:].split("[", 1)[0].split("(", 1)[0].split(" ", 1)[0]
            if not field:
                return base
            selectors = (["*"] if arrow else []) + [field] + list(base[1])
            return base[0], selectors
        if kind == "ArraySubscriptExpr":
            items = children.get(node_id, ())
            base = path(items[0][0], depth + 1) if items else None
            return None if base is None else (base[0], list(base[1]) + ["<?>", "*"])
        if kind == "UnaryOperator":
            items = children.get(node_id, ())
            base = path(items[0][0], depth + 1) if items else None
            if base is None:
                return None
            operator = props(node).get("operator", "")
            selectors = list(base[1])
            if operator in {"*", "&"}:
                selectors.append(operator)
            return base[0], selectors
        return None

    function_kinds = {"function", "method", "constructor", "FunctionDecl",
                      "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl"}
    function_names = {node["id"]: node.get("label", "") for node in nodes
                      if syntax(node["id"]) in function_kinds}
    function_ids = set(function_names)

    def root_label(root):
        root = (root or "").removeprefix("decl:")
        node = by_id.get(root)
        return (node.get("label") or root) if node else root

    functions = {}
    return_nodes = defaultdict(list)
    for node in nodes:
        owner = props(node).get("owner_function_id") or props(node).get("function_id")
        if not owner:
            continue
        item = functions.setdefault(owner, lifetime_pb2.TranslationFunction(id=owner))
        if owner in by_id:
            function = by_id[owner]
            item.name = function.get("label", "")
            item.file = props(function).get("file", "")
            if "start_line" in props(function):
                item.start_line = int(props(function).get("start_line") or 0)
                item.has_start_line = True
            item.externally_visible = props(function).get("storage_class") != "static"
        if syntax(node["id"]) == "ParmVarDecl":
            item.parameters.append(node["id"])
        if syntax(node["id"]) == "ReturnStmt":
            return_nodes[owner].append(node)
    for item in functions.values():
        item.parameters.sort(key=lambda node_id: int(props(by_id[node_id]).get("start_offset") or 2**63 - 1))
        item.parameter_names.extend(root_label(node_id) for node_id in item.parameters)

    call_kinds = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"}
    for node in nodes:
        node_id = node["id"]
        if syntax(node_id) not in call_kinds:
            continue
        node_props = props(node)
        owner = node_props.get("owner_function_id") or node_props.get("function_id")
        item = functions.get(owner)
        if item is None:
            continue
        target = node_props.get("primary_target_id")
        callee = function_names.get(target) or node_props.get("callee") or node.get("label", "")
        call = lifetime_pb2.FunctionCall(
            node=node_id, callee=callee, receiver=node_props.get("receiver", ""),
            line=int(node_props.get("start_line") or 0), has_line="start_line" in node_props,
            is_alloc=node_props.get("is_alloc") is True,
            is_release=node_props.get("is_release") is True,
            is_realloc=node_props.get("is_realloc") is True,
            is_aggregate_copy=node_props.get("is_aggregate_copy") is True,
        )
        parent_id = parents.get(node_id)
        if parent_id and syntax(parent_id) == "BinaryOperator" and props(by_id[parent_id]).get("operator") == "=":
            call.assigned = next((target for target, role in children.get(parent_id, ())
                                  if role == "LEFT_OPERAND"), "")
        if not call.assigned:
            call.assigned = next((edge["target"] for edge in source_edges[node_id]
                                  if edge["kind"] == "VALUE_FLOWS_TO" and
                                  (edge.get("properties") or {}).get("reason") == "initializer"), "")
        assigned = path(call.assigned)
        if assigned:
            call.assigned_root = assigned[0]
            call.assigned_selectors.extend(assigned[1])
            call.assigned_name = root_label(assigned[0])
        args = [(edge["target"], edge.get("properties", {}).get("position", 0))
                for edge in source_edges[node_id] if edge["kind"] == "AST_CHILD" and
                (edge.get("properties") or {}).get("role") == "ARGUMENT"]
        for arg_id, position in sorted(args, key=lambda pair: pair[1] or 0):
            arg_path = path(arg_id)
            argument = lifetime_pb2.FunctionArgument(
                position=int(position or 0), node=arg_id,
                expression=by_id.get(arg_id, {}).get("label", ""),
            )
            if arg_path:
                argument.root = arg_path[0]
                argument.selectors.extend(arg_path[1])
                argument.root_name = root_label(arg_path[0])
            call.arguments.append(argument)
        item.calls.append(call)

    for item in functions.values():
        for node in return_nodes.get(item.id, ()):
            node_id = node["id"]
            if not children.get(node_id):
                continue
            child = children[node_id][0][0]
            peeled = peel(child)
            line_props = props(node)
            if syntax(peeled) in call_kinds:
                call_node = by_id[peeled]
                call_props = props(call_node)
                target = call_props.get("primary_target_id")
                item.returns.append(lifetime_pb2.FunctionReturn(
                    kind="call", callee=function_names.get(target) or
                    call_props.get("callee") or call_node.get("label", ""),
                    line=int(line_props.get("start_line") or 0), has_line="start_line" in line_props))
            else:
                return_path = path(child)
                if return_path:
                    item.returns.append(lifetime_pb2.FunctionReturn(
                        kind="var", root=return_path[0], selectors=return_path[1],
                        root_name=root_label(return_path[0]),
                        line=int(line_props.get("start_line") or 0), has_line="start_line" in line_props))
    return lifetime_pb2.TranslationResult(functions=[functions[key] for key in sorted(functions)])


def _translation_records(nodes, records):
    """Return the compact call/return projection used by native Pass 2.

    Pass 1 already owns these filtered records while writing the substrate.  Keeping
    this projection here avoids making Pass 2 decode the complete structural sidecar;
    Rust still performs the actual translation and lifetime analysis.
    """
    def syntax(node):
        props = node.get("properties") or {}
        return props.get("syntax_kind") or node.get("kind")

    seed_kinds = {
        "CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr", "ReturnStmt",
        "function", "method", "constructor", "FunctionDecl", "CXXMethodDecl",
        "CXXConstructorDecl", "CXXDestructorDecl", "ParmVarDecl",
    }
    seed_nodes = [node for node in nodes if syntax(node) in seed_kinds]
    call_ids = {node["id"] for node in seed_nodes
                if syntax(node) in {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"}}
    return_ids = {node["id"] for node in seed_nodes if syntax(node) == "ReturnStmt"}
    relevant = call_ids | return_ids
    for _ in range(2):
        for edge in records:
            kind = edge["kind"]
            source, target = edge["source"], edge["target"]
            if kind == "AST_CHILD" and (source in relevant or source in call_ids or
                                         source in return_ids or target in call_ids):
                relevant.add(source)
                relevant.add(target)
            elif kind == "REFERS_TO" and source in relevant:
                relevant.add(target)
            elif kind == "VALUE_FLOWS_TO" and source in call_ids:
                relevant.add(target)
    node_ids = {node["id"] for node in seed_nodes} | relevant
    kept_nodes = [node for node in nodes if node["id"] in node_ids]
    kept_edges = [edge for edge in records if (
        (edge["kind"] == "AST_CHILD" and
         (edge["source"] in relevant or edge["target"] in relevant)) or
        (edge["kind"] == "REFERS_TO" and edge["source"] in relevant) or
        (edge["kind"] == "VALUE_FLOWS_TO" and edge["source"] in call_ids)
    )]
    return kept_nodes, kept_edges


def _write_framed_sidecar(target, prefix, header, nodes, edges):
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=prefix, dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            write_frame(handle, encode_document({"type": "header", **header}))
            for node in nodes:
                write_frame(handle, b"N" + encode_node(node))
            for edge in edges:
                write_frame(handle, b"E" + encode_edge(edge))
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _write_complete_pass2_input(target, nodes, edges, *, manifest=None):
    """Write the lossless typed graph consumed by the native Pass-2 engine.

    The lifetime substrate above is deliberately filtered and remains useful for
    Pass 3.  The native Pass-2 engine needs the complete canonical node/edge
    vocabulary, including nested properties and model roles, so it gets a separate
    framed protobuf stream.  No Python graph reconstruction is required when the
    engine reads it.
    """
    manifest = manifest or {}
    header = {
        "format": "lachesis-pass2-input",
        "version": _PASS2_INPUT_VERSION,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "store_version": manifest.get("version"),
        "core_content_hash": manifest.get("core_content_hash"),
        "source_content_hash": manifest.get("source_content_hash"),
        "build_fingerprint": manifest.get("build_fingerprint"),
    }
    _write_framed_sidecar(target, ".pass2-input-", header, nodes, edges)


def write_streaming_pass1_caches(reader, graph_path, *, manifest=None,
                                 keep_node=None):
    """Publish Pass-1 caches from a replayable shard reader.

    The complete Pass-2 input is copied record-by-record.  Only the narrower
    Pass-3/translation subset is retained briefly, so streaming Kùzu builds keep
    their bounded-memory property while preserving the normal Pass-1 ABI.
    """
    manifest = dict(manifest or {})
    kept_ids = set()
    substrate_nodes = []
    for node in reader.nodes():
        if keep_node is not None and not keep_node(node):
            continue
        kept_ids.add(node.get("id"))
        props = node.get("properties") or {}
        syntax_kind = props.get("syntax_kind") or node.get("kind")
        if syntax_kind in _SUBSTRATE_NODE_KINDS:
            substrate_nodes.append({
                "id": node.get("id"), "kind": node.get("kind"),
                "label": node.get("label"),
                "properties": {
                    key: value for key, value in props.items()
                    if key in _SUBSTRATE_PROPERTY_KEYS
                    and isinstance(value, (str, int, float, bool, type(None)))
                },
            })

    substrate_edges = []
    for edge in reader.edges():
        if edge.get("source") not in kept_ids or edge.get("target") not in kept_ids:
            continue
        props = edge.get("properties") or {}
        kind = (props.get("semantic_kind") or edge.get("semantic_kind")
                or edge.get("kind"))
        if kind == "AST_CHILD":
            props = {key: props[key] for key in ("role", "position") if key in props}
        elif kind in {"REFERS_TO", "CFG_NEXT"}:
            props = {}
        elif kind == "VALUE_FLOWS_TO" and props.get("reason") == "initializer":
            props = {"reason": "initializer"}
        else:
            continue
        substrate_edges.append({"source": edge.get("source"),
                                "target": edge.get("target"), "kind": kind,
                                "properties": props})

    def stored_nodes():
        for node in reader.nodes():
            if keep_node is None or keep_node(node):
                yield node

    def stored_edges():
        for edge in reader.edges():
            if edge.get("source") in kept_ids and edge.get("target") in kept_ids:
                yield edge

    target = Path(graph_path)
    _write_framed_sidecar(
        pass2_input_cache_path(target), ".pass2-input-",
        {"format": "lachesis-pass2-input", "version": _PASS2_INPUT_VERSION,
         "node_count": int(manifest.get("node_count", 0)),
         "edge_count": int(manifest.get("edge_count", 0)),
         "store_version": manifest.get("version"),
         "core_content_hash": manifest.get("core_content_hash"),
         "source_content_hash": manifest.get("source_content_hash"),
         "build_fingerprint": manifest.get("build_fingerprint")},
        stored_nodes(), stored_edges())

    translation_nodes, translation_edges = _translation_records(
        substrate_nodes, substrate_edges)
    common = {"store_version": manifest.get("version"),
              "core_content_hash": manifest.get("core_content_hash"),
              "source_content_hash": manifest.get("source_content_hash"),
              "build_fingerprint": manifest.get("build_fingerprint")}
    _write_framed_sidecar(
        substrate_cache_path(target), ".pass3-substrate-",
        {"format": "lachesis-pass3-substrate", "version": _CACHE_VERSION,
         "edge_count": len(substrate_edges), "node_count": len(substrate_nodes),
         "member_count": sum(1 for node in substrate_nodes
                              if (node.get("properties") or {}).get("syntax_kind") == "MemberExpr"),
         **common}, substrate_nodes, substrate_edges)
    _write_framed_sidecar(
        translation_cache_path(target), ".pass2-translation-",
        {"format": "lachesis-pass2-translation", "version": _CACHE_VERSION,
         "edge_count": len(translation_edges), "node_count": len(translation_nodes),
         **common}, translation_nodes, translation_edges)
    _write_translation_facts(translation_facts_path(target),
                             _translation_facts(translation_nodes, translation_edges))


def _write_translation_facts(target, result):
    fd, temp_name = tempfile.mkstemp(prefix=".pass2-facts-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(result.SerializeToString())
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def write_substrate_cache(graph, graph_path, *, manifest=None):
    """Write the structural Pass-3 substrate produced by Pass 1.

    The file is framed protobuf, not pickle/JSON. It contains only immutable
    relations and scalar expression records consumed by the object substrate;
    Kuzu remains the fallback for anything outside this contract.
    """
    nodes = graph.get("nodes", ())
    # A disk-backed graph can publish this sidecar without materializing its full
    # node table: callers may provide just the required structural edges and the
    # MemberExpr rows.  ``None`` means endpoint validation is intentionally deferred
    # to the graph store's own referential integrity, while an explicit node list
    # retains the stronger validation used by the normal Pass-1 writer.
    node_ids = ({node.get("id") for node in nodes}
                if "nodes" in graph else None)
    records, cached_nodes, member_nodes = [], [], []
    for node in nodes:
        props = node.get("properties") or {}
        syntax_kind = props.get("syntax_kind") or node.get("kind")
        if syntax_kind in _SUBSTRATE_NODE_KINDS:
            cached_properties = {
                key: value for key, value in props.items()
                if key in _SUBSTRATE_PROPERTY_KEYS
                and isinstance(value, (str, int, float, bool, type(None)))
            }
            cached = {
                "id": node.get("id"), "kind": node.get("kind"),
                "label": node.get("label"), "properties": cached_properties,
            }
            cached_nodes.append(cached)
            if syntax_kind == "MemberExpr":
                member_nodes.append(cached)
    for edge in graph.get("edges", ()):
        source, target = edge.get("source"), edge.get("target")
        if node_ids is not None and (source not in node_ids or target not in node_ids):
            continue
        props = edge.get("properties") or {}
        kind = (props.get("semantic_kind") or edge.get("semantic_kind")
                or edge.get("kind"))
        if kind == "AST_CHILD":
            props = {key: props[key] for key in ("role", "position") if key in props}
        elif kind in {"REFERS_TO", "CFG_NEXT"}:
            props = {}
        elif kind == "VALUE_FLOWS_TO" and props.get("reason") == "initializer":
            props = {"reason": "initializer"}
        else:
            continue
        records.append({"source": source, "target": target, "kind": kind,
                        "properties": props})
    manifest = dict(manifest or {})
    header = {
        "format": "lachesis-pass3-substrate",
        "version": _CACHE_VERSION,
        "edge_count": len(records),
        "node_count": len(cached_nodes),
        "member_count": len(member_nodes),
        "store_version": manifest.get("version"),
        "core_content_hash": manifest.get("core_content_hash"),
        "source_content_hash": manifest.get("source_content_hash"),
        "build_fingerprint": manifest.get("build_fingerprint"),
    }
    target = substrate_cache_path(graph_path)
    _write_framed_sidecar(target, ".pass3-substrate-", header, cached_nodes, records)

    # This lossless stream is the future single input to Rust Pass 2.  Keep it
    # separate from the intentionally narrow Pass-3 substrate until the native
    # engine is fully wired; both are generated from the same immutable Pass-1
    # graph and are keyed by the same manifest.
    _write_complete_pass2_input(
        pass2_input_cache_path(graph_path), nodes, graph.get("edges", ()),
        manifest=manifest,
    )

    translation_nodes, translation_edges = _translation_records(cached_nodes, records)
    translation_header = {
        "format": "lachesis-pass2-translation",
        "version": _CACHE_VERSION,
        "edge_count": len(translation_edges),
        "node_count": len(translation_nodes),
        "store_version": manifest.get("version"),
        "core_content_hash": manifest.get("core_content_hash"),
        "source_content_hash": manifest.get("source_content_hash"),
        "build_fingerprint": manifest.get("build_fingerprint"),
    }
    _write_framed_sidecar(translation_cache_path(graph_path), ".pass2-translation-",
                          translation_header, translation_nodes, translation_edges)
    facts = _translation_facts(translation_nodes, translation_edges)
    _write_translation_facts(translation_facts_path(graph_path), facts)
    return str(target)


def read_substrate_cache(index):
    """Load a valid Pass-1 structural sidecar, or return None on a cache miss."""
    graph_path = (getattr(index, "_pass3_cache_base", None)
                  or getattr(index, "_db_dir", None))
    if not graph_path:
        return None
    path = substrate_cache_path(graph_path)
    if not path.is_file():
        return None
    try:
        frames = read_frames(path)
        header = decode_document(next(frames))
        if (header.get("type") != "header" or
                header.get("format") != "lachesis-pass3-substrate" or
                header.get("version") != _CACHE_VERSION):
            return None
        expected = getattr(index, "_store_manifest", {})
        manifest_keys = {
            "store_version": "version",
            "core_content_hash": "core_content_hash",
            "source_content_hash": "source_content_hash",
            "build_fingerprint": "build_fingerprint",
        }
        for header_key, manifest_key in manifest_keys.items():
            if header.get(header_key) != expected.get(manifest_key):
                return None
        result = {"ast": [], "refers": [], "cfg": [],
                  "initializers": [], "members": [], "nodes": []}
        for frame in frames:
            if not frame:
                continue
            is_node = frame[:1] == b"N"
            record = decode_node(frame[1:]) if is_node else decode_edge(frame[1:])
            if is_node:
                result["nodes"].append(record)
                if (record.get("properties") or {}).get("syntax_kind") == "MemberExpr":
                    result["members"].append(record)
            elif record.get("kind") == "AST_CHILD":
                result["ast"].append(record)
            elif record.get("kind") == "REFERS_TO":
                result["refers"].append(record)
            elif record.get("kind") == "CFG_NEXT":
                result["cfg"].append(record)
            elif record.get("kind") == "VALUE_FLOWS_TO":
                result["initializers"].append(record)
        return result
    except (OSError, StopIteration, ValueError, TypeError, KeyError):
        return None


def _is_cfg_synthetic(kind):
    return kind in ("cfg-entry", "cfg-exit", "cfg-merge", "cfg-condition")


class Substrate:
    def __init__(self, index):
        self.idx = index
        self._node = {}
        self.ast_children = defaultdict(list)   # parent -> [child]
        self.ast_by_role = defaultdict(lambda: defaultdict(list))
        self.ast_by_position = defaultdict(lambda: defaultdict(dict))
        self.ast_parent = {}                    # child -> parent
        self.refers = {}                        # DeclRefExpr -> decl
        self.cfg_next = defaultdict(list)       # block -> [block]
        self.cfg_prev = defaultdict(list)
        self.cfg_nodes = set()
        self.initializer_source = {}
        self._warmed_owner_ids = set()
        self._initializers_loaded = False
        self._loaded = False

    # -- lazy bulk load --------------------------------------------------------
    @timeit
    def load(self):
        if self._loaded:
            return self
        cached = read_substrate_cache(self.idx)
        if cached is not None:
            for node in cached.get("nodes", ()):
                self._node[node["id"]] = node
            for e in cached["ast"]:
                self.ast_children[e["source"]].append(e["target"])
                self.ast_parent[e["target"]] = e["source"]
                properties = e.get("properties", {})
                role = properties.get("role") or "AST_CHILD"
                self.ast_by_role[e["source"]][role].append(e["target"])
                position = properties.get("position")
                if isinstance(position, int):
                    self.ast_by_position[e["source"]][role][position] = e["target"]
            for e in cached["refers"]:
                self.refers.setdefault(e["source"], e["target"])
            for e in cached["cfg"]:
                source, target = e["source"], e["target"]
                self.cfg_next[source].append(target)
                self.cfg_prev[target].append(source)
                self.cfg_nodes.update((source, target))
            self._cached_initializers = tuple(cached["initializers"])
            self._loaded = True
            self.idx._pass3_member_expression_cache = tuple(cached["members"])
            return self
        reader = getattr(self.idx, "structural_edges", None)
        ast_edges = (reader("AST_CHILD") if reader is not None
                     else self.idx.edges_of_kind("AST_CHILD"))
        for e in ast_edges:
            self.ast_children[e["source"]].append(e["target"])
            self.ast_parent[e["target"]] = e["source"]
            properties = e.get("properties", {})
            role = properties.get("role") or "AST_CHILD"
            self.ast_by_role[e["source"]][role].append(e["target"])
            position = properties.get("position")
            if isinstance(position, int):
                self.ast_by_position[e["source"]][role][position] = e["target"]
        ref_edges = (reader("REFERS_TO") if reader is not None
                     else self.idx.edges_of_kind("REFERS_TO"))
        for e in ref_edges:
            self.refers.setdefault(e["source"], e["target"])
        cfg_edges = (reader("CFG_NEXT") if reader is not None
                     else self.idx.edges_of_kind("CFG_NEXT"))
        for e in cfg_edges:
            s, t = e["source"], e["target"]
            self.cfg_next[s].append(t)
            self.cfg_prev[t].append(s)
            self.cfg_nodes.add(s)
            self.cfg_nodes.add(t)
        self._loaded = True
        return self

    @timeit
    def load_initializers(self):
        """Bulk-index declaration initializers once instead of one edge query per VarDecl."""
        if self._initializers_loaded:
            return self
        cached = getattr(self, "_cached_initializers", None)
        if cached is not None:
            edges = cached
        else:
            reader = getattr(self.idx, "initializer_edges", None)
            edges = (reader() if reader is not None
                     else self.idx.edges_of_kind("VALUE_FLOWS_TO"))
        for edge in edges:
            if (edge.get("properties", {}).get("reason") == "initializer"):
                self.initializer_source.setdefault(edge["target"], edge["source"])
        self._initializers_loaded = True
        return self

    def warm_nodes(self, node_ids, batch_size=5000):
        """Bulk-warm disk-backed node records; a no-op for the in-memory index."""
        warmer = getattr(self.idx, "_warm_nodes", None)
        if warmer is None:
            return self
        ordered = list(dict.fromkeys(node_ids))
        for start in range(0, len(ordered), batch_size):
            warmer(ordered[start:start + batch_size])
        return self

    @timeit
    def warm_owned(self, function_ids, batch_size=5000):
        """Warm all bodies in bounded batches instead of one query per function."""
        ordered = tuple(dict.fromkeys(function_ids))
        pending = tuple(owner for owner in ordered
                        if owner not in self._warmed_owner_ids)
        if not pending:
            return self
        owner_warmer = getattr(self.idx, "_warm_nodes_by_owner", None)
        if owner_warmer is not None:
            owner_warmer(pending, None)
            self._warmed_owner_ids.update(pending)
            return self
        by_owner = getattr(self.idx, "by_owner", None)
        if by_owner is None:
            return self
        owned = []
        for function_id in pending:
            owned.extend(by_owner.get(function_id, ()))
        result = self.warm_nodes(owned, batch_size=batch_size)
        self._warmed_owner_ids.update(pending)
        return result

    def role_children(self, node, role):
        return self.ast_by_role.get(node, {}).get(role, ())

    def role_child_at(self, node, role, position):
        return self.ast_by_position.get(node, {}).get(role, {}).get(position)

    # -- node accessors --------------------------------------------------------
    def node(self, nid):
        n = self._node.get(nid)
        if n is None:
            nodes = getattr(self.idx, "nodes", None)
            n = (nodes.get(nid) if nodes is not None else self.idx._node(nid)) or {}
            self._node[nid] = n
        return n

    def props(self, nid):
        return self.node(nid).get("properties", {})

    def kind(self, nid):
        p = self.props(nid)
        return p.get("syntax_kind") or self.node(nid).get("kind")

    def offset(self, nid):
        p = self.props(nid)
        v = p.get("start_offset")
        return v if v is not None else (p.get("start_line", 0) or 0) * 100000

    def label(self, nid):
        return self.node(nid).get("label") or ""

    def operator(self, nid):
        return self.props(nid).get("operator")

    # -- role predicates -------------------------------------------------------
    def is_assignment(self, nid):
        return self.kind(nid) in ("BinaryOperator", "CompoundAssignOperator") and \
            self.operator(nid) in ("=", "+=", "-=", "*=", "/=", "%=", "&=", "|=",
                                   "^=", "<<=", ">>=")

    def is_plain_assign(self, nid):   # pure store (kills LHS); compound = read+write
        return self.kind(nid) == "BinaryOperator" and self.operator(nid) == "="

    def is_field_access(self, nid):
        return self.kind(nid) in _FIELD_ACCESS

    def is_identifier(self, nid):
        return self.kind(nid) == "DeclRefExpr"

    def is_literal(self, nid):
        return self.kind(nid) in _LITERALS

    def is_call(self, nid):
        return self.kind(nid) in ("CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr")

    def is_param(self, nid):
        return self.kind(nid) == "ParmVarDecl"

    # -- base-object resolution (for access paths / kills) --------------------
    def resolve_base_decl(self, nid, depth=0):
        """Peel casts; from a DeclRefExpr return its REFERS_TO decl (object identity)."""
        if depth > 10:
            return nid
        k = self.kind(nid)
        if k in _CASTS:
            ch = self.ast_children.get(nid)
            return self.resolve_base_decl(ch[0], depth + 1) if ch else nid
        if k == "DeclRefExpr":
            return self.refers.get(nid, nid)
        return nid

    # -- per-function linearization -------------------------------------------
    def functions(self):
        fns = set()
        for n in self.idx.nodes_of_kind("expression"):
            f = n.get("properties", {}).get("owner_function_id")
            if f:
                fns.add(f)
        return fns

    def _owned(self, fn):
        out = []
        for x in self.idx.nodes_owned_by(fn):
            out.append(x["id"] if isinstance(x, dict) else x)
        return out

    def blocks_in_cfg_order(self, fn):
        """Reverse-post-order over CFG_NEXT restricted to this function's CFG nodes."""
        owned = set(self._owned(fn))
        blocks = [b for b in owned if b in self.cfg_nodes]
        if not blocks:
            return []
        entry = [b for b in blocks if self.kind(b) == "cfg-entry"]
        starts = entry or blocks[:1]
        order, seen, stack = [], set(), list(starts)
        # iterative DFS post-order then reverse
        post = []
        vstack = [(s, False) for s in starts]
        while vstack:
            b, processed = vstack.pop()
            if processed:
                post.append(b)
                continue
            if b in seen:
                continue
            seen.add(b)
            vstack.append((b, True))
            for succ in self.cfg_next.get(b, []):
                if succ in owned and succ not in seen:
                    vstack.append((succ, False))
        rpo = list(reversed(post))
        # append any owned CFG blocks not reached
        for b in blocks:
            if b not in seen:
                rpo.append(b)
        return rpo
    def block_defuse_stream(self, block):
        """Linearized defs/uses inside one basic block, in evaluation order.

        Walk the block's AST subtree, collect the 'operation' nodes (calls, assignments,
        field accesses, identifiers, literals), order by start_offset. For each plain
        assignment, emit RHS-side nodes before the store node (RHS-before-LHS rule).
        Returns a flat list of node ids in evaluation order (the CFG-node stream).
        """
        # collect subtree (exclude nested basic-block children: nested stmts are their
        # own CFG blocks and handled separately)
        stream = []
        stack = list(self.ast_children.get(block, []))
        seen = set()
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            k = self.kind(x)
            if k in self.cfg_nodes and k not in _LITERALS:
                # a nested basic block / statement with its own CFG handling — skip its
                # subtree here (it is linearized when we reach it in block order)
                if x in self.cfg_nodes and x != block:
                    continue
            stream.append(x)
            for c in self.ast_children.get(x, []):
                stack.append(c)
        # order by source offset; assignment store handled by offset naturally (LHS token
        # precedes RHS in source, but we want RHS uses before the store DEF) — we mark the
        # store node with a tiny order bump so its DEF lands after its RHS operands.
        def key(nid):
            base = self.offset(nid)
            return (base, 1 if self.is_assignment(nid) else 0)
        stream.sort(key=key)
        return stream


def cached_substrate(index):
    """Return the read-only substrate shared by Pass3 object/emission phases."""
    cached = getattr(index, "_pass3_substrate", None)
    if cached is None:
        cached = Substrate(index).load().load_initializers()
        try:
            index._pass3_substrate = cached
        except AttributeError:
            # A third-party immutable index can still use an isolated substrate.
            pass
    return cached
