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

_CACHE_VERSION = 1
_CACHE_SUFFIX = ".pass3.substrate.pb"
_PASS2_OWNER_CACHE_VERSION = 1
_PASS2_OWNER_CACHE_SUFFIX = ".pass2.owner.pb"
_PASS2_CFG_CACHE_VERSION = 1
_PASS2_CFG_CACHE_SUFFIX = ".pass2.cfg.pb"


def substrate_cache_path(graph_path):
    return Path(str(graph_path).rstrip("/") + _CACHE_SUFFIX)


def pass2_owner_cache_path(graph_path):
    """The Pass-1 owner stream consumed by Pass-2 object analysis."""
    return Path(str(graph_path).rstrip("/") + _PASS2_OWNER_CACHE_SUFFIX)


def pass2_cfg_cache_path(graph_path):
    return Path(str(graph_path).rstrip("/") + _PASS2_CFG_CACHE_SUFFIX)


def write_pass2_cfg_cache(graph, graph_path, *, manifest=None):
    """Persist the deterministic intraprocedural CFG prepared during Pass 1."""
    from lachesis.core.query import GraphIndex
    from lachesis.nav.dataflow.reaching_def import ReachingDef

    index = GraphIndex(graph)
    substrate = Substrate(index).load().load_initializers()
    functions = [node["id"] for kind in ("function", "method", "constructor")
                 for node in index.nodes_of_kind(kind)]
    manifest = dict(manifest or {})
    header = {
        "type": "lachesis-pass2-cfg-cache",
        "version": _PASS2_CFG_CACHE_VERSION,
        "function_count": len(functions),
        "store_version": manifest.get("version"),
        "core_content_hash": manifest.get("core_content_hash"),
        "source_content_hash": manifest.get("source_content_hash"),
        "build_fingerprint": manifest.get("build_fingerprint"),
    }
    target = pass2_cfg_cache_path(graph_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".pass2-cfg-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            write_frame(handle, encode_document(header))
            analyzer = ReachingDef(substrate)
            for function_id in functions:
                cfg = analyzer.analyze(function_id, reaching_defs=False)
                write_frame(handle, b"C" + encode_document({
                    "function_id": function_id, "cfg": cfg,
                }))
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return str(target)


def read_pass2_cfg_cache(index):
    """Return cached CFGs keyed by owner id, or None on any cache miss."""
    path = pass2_cfg_cache_path(
        getattr(index, "_pass3_cache_base", None) or getattr(index, "_db_dir", ""))
    if not path.is_file():
        return None
    try:
        frames = read_frames(path)
        header = decode_document(next(frames))
        expected = getattr(index, "_store_manifest", {})
        if (header.get("type") != "lachesis-pass2-cfg-cache" or
                header.get("version") != _PASS2_CFG_CACHE_VERSION):
            return None
        for header_key, manifest_key in {
                "store_version": "version",
                "core_content_hash": "core_content_hash",
                "source_content_hash": "source_content_hash",
                "build_fingerprint": "build_fingerprint",
        }.items():
            if header.get(header_key) != expected.get(manifest_key):
                return None
        result = {}
        for frame in frames:
            if not frame or frame[:1] != b"C":
                continue
            record = decode_document(frame[1:])
            result[record["function_id"]] = record.get("cfg")
        return result
    except (OSError, StopIteration, ValueError, TypeError, KeyError):
        return None


def write_pass2_owner_cache(graph, graph_path, *, manifest=None):
    """Persist owned node records so Pass 2 need not rescan Kùzu bodies.

    The records are sorted by owner and id, matching ``stream_nodes_by_owner``'s
    callback contract.  This is deliberately a raw structural sidecar: interprocedural
    summaries still belong to Pass 2 and are never cached here.
    """
    nodes = [node for node in graph.get("nodes", ())
             if (node.get("properties") or {}).get("owner_function_id")]
    nodes.sort(key=lambda node: (
        str((node.get("properties") or {}).get("owner_function_id")),
        str(node.get("id") or ""),
    ))
    manifest = dict(manifest or {})
    header = {
        "type": "lachesis-pass2-owner-cache",
        "version": _PASS2_OWNER_CACHE_VERSION,
        "node_count": len(nodes),
        "store_version": manifest.get("version"),
        "core_content_hash": manifest.get("core_content_hash"),
        "source_content_hash": manifest.get("source_content_hash"),
        "build_fingerprint": manifest.get("build_fingerprint"),
    }
    target = pass2_owner_cache_path(graph_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".pass2-owner-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            write_frame(handle, encode_document(header))
            property_cache = {}
            for node in nodes:
                write_frame(handle, b"N" + encode_node(node, _property_cache=property_cache))
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return str(target)


def stream_pass2_owner_cache(index, owner_ids, callback):
    """Stream valid Pass-1 owner records; return False on a cache miss."""
    path = pass2_owner_cache_path(
        getattr(index, "_pass3_cache_base", None) or getattr(index, "_db_dir", ""))
    if not path.is_file():
        return False
    try:
        frames = read_frames(path)
        header = decode_document(next(frames))
        expected = getattr(index, "_store_manifest", {})
        if (header.get("type") != "lachesis-pass2-owner-cache" or
                header.get("version") != _PASS2_OWNER_CACHE_VERSION):
            return False
        for header_key, manifest_key in {
                "store_version": "version",
                "core_content_hash": "core_content_hash",
                "source_content_hash": "source_content_hash",
                "build_fingerprint": "build_fingerprint",
        }.items():
            if header.get(header_key) != expected.get(manifest_key):
                return False
        wanted = {owner for owner in owner_ids if owner}
        current_owner = None
        batch = []
        for frame in frames:
            if not frame or frame[:1] != b"N":
                continue
            node = decode_node(frame[1:])
            owner = (node.get("properties") or {}).get("owner_function_id")
            if owner not in wanted:
                continue
            if owner != current_owner:
                if current_owner is not None and batch:
                    callback(current_owner, batch)
                current_owner, batch = owner, []
            overlay = getattr(index, "_overlay", None)
            if overlay is not None:
                extra = overlay.node_props.get(node["id"])
                if extra:
                    properties = dict(node.get("properties") or {})
                    properties.update(extra)
                    node = {**node, "properties": properties}
            index._node_cache[node["id"]] = node
            batch.append(node)
        if current_owner is not None and batch:
            callback(current_owner, batch)
        return True
    except (OSError, StopIteration, ValueError, TypeError, KeyError):
        return False


def write_substrate_cache(graph, graph_path, *, manifest=None):
    """Write the structural Pass-3 substrate produced by Pass 1.

    The file is framed protobuf, not pickle/JSON. It contains only immutable
    relations and member-expression records consumed by the object substrate;
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
    records, member_nodes = [], []
    for node in nodes:
        props = node.get("properties") or {}
        if props.get("syntax_kind") == "MemberExpr":
            member_nodes.append({
                "id": node.get("id"), "kind": node.get("kind"),
                "label": node.get("label"), "properties": props,
            })
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
        "node_count": graph.get("node_count", len(node_ids) if node_ids is not None else 0),
        "edge_count": len(records),
        "member_count": len(member_nodes),
        "store_version": manifest.get("version"),
        "core_content_hash": manifest.get("core_content_hash"),
        "source_content_hash": manifest.get("source_content_hash"),
        "build_fingerprint": manifest.get("build_fingerprint"),
    }
    target = substrate_cache_path(graph_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".pass3-substrate-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            write_frame(handle, encode_document({"type": "header", **header}))
            for node in member_nodes:
                write_frame(handle, b"N" + encode_node(node))
            for edge in records:
                write_frame(handle, b"E" + encode_edge(edge))
        os.replace(temp_name, target)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
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
                  "initializers": [], "members": []}
        for frame in frames:
            if not frame:
                continue
            is_node = frame[:1] == b"N"
            record = decode_node(frame[1:]) if is_node else decode_edge(frame[1:])
            if is_node:
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
