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
from collections import defaultdict

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
        self._initializers_loaded = False
        self._loaded = False

    # -- lazy bulk load --------------------------------------------------------
    def load(self):
        if self._loaded:
            return self
        for e in self.idx.edges_of_kind("AST_CHILD"):
            self.ast_children[e["source"]].append(e["target"])
            self.ast_parent[e["target"]] = e["source"]
            properties = e.get("properties", {})
            role = properties.get("role") or "AST_CHILD"
            self.ast_by_role[e["source"]][role].append(e["target"])
            position = properties.get("position")
            if isinstance(position, int):
                self.ast_by_position[e["source"]][role][position] = e["target"]
        for e in self.idx.edges_of_kind("REFERS_TO"):
            self.refers.setdefault(e["source"], e["target"])
        for e in self.idx.edges_of_kind("CFG_NEXT"):
            s, t = e["source"], e["target"]
            self.cfg_next[s].append(t)
            self.cfg_prev[t].append(s)
            self.cfg_nodes.add(s)
            self.cfg_nodes.add(t)
        self._loaded = True
        return self

    def load_initializers(self):
        """Bulk-index declaration initializers once instead of one edge query per VarDecl."""
        if self._initializers_loaded:
            return self
        for edge in self.idx.edges_of_kind("VALUE_FLOWS_TO"):
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

    def warm_owned(self, function_ids, batch_size=5000):
        """Warm all bodies in bounded batches instead of one query per function."""
        by_owner = getattr(self.idx, "by_owner", None)
        if by_owner is None:
            return self
        owned = []
        for function_id in function_ids:
            owned.extend(by_owner.get(function_id, ()))
        return self.warm_nodes(owned, batch_size=batch_size)

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
