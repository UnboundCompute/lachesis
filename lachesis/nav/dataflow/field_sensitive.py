"""Increment 1 — intraprocedural field-sensitive def-use.

Implemented clean-room from the described algorithm (no code vendored): access-path build +
EXACT match, usage analysis (isUsing/isAlias), and gen/kill with field-access transparent.

What field sensitivity requires (three ingredients):
  1. reaching-defs on the BASE variable, classic gen/kill over the CFG;
  2. an access-path EXACT-match filter deciding which def reaches which field use;
  3. (increment 2) an interprocedural context-sensitive param<->arg solver.

This module implements the core of (1)+(2) as an *added* field def-use relation on
top of our existing (field-INsensitive) VALUE_FLOWS_TO substrate: for each function,
group MemberExpr sites by (owner_fn, base-object-identity, access-path) and connect
every field WRITE to every matching field READ. Base-object identity is the resolved
declaration node (DeclRefExpr --REFERS_TO--> decl), so "same object" is real graph
identity within a function, not a name-string match.

PRECISION CAVEAT (honest): this increment is flow-INsensitive within a group — it
does not yet model kills (base reassignment) or CFG order, so it is an upper bound on
full precision. Increment 2 adds gen/kill over CFG_NEXT + interprocedural binding.
It is field-SENSITIVE, which is the property VALUE_FLOWS_TO lacks and the whole point.

"""
from collections import defaultdict

# nodes we transparently skip when descending from a MemberExpr to its base object
_CASTS = {"ImplicitCastExpr", "CStyleCastExpr", "ParenExpr", "CXXConstCastExpr"}

# Field-access node kinds per frontend. Value = extraction strategy:
#   "structural" — clang decomposes member access into an AST_CHILD base chain, so we
#                  resolve the base to its *declaration node* (real identity via REFERS_TO).
#   "lexical"    — the frontend flattens member access; the whole path is in the label,
#                  so base identity is the label-prefix string, scoped by function.
_FIELD_KINDS = {
    "MemberExpr": "structural",             # C / C++ (clang)
    "Attribute": "lexical",                 # Python
    "MemberExpression": "lexical",          # JavaScript (TS compiler / babel)
    "PropertyAccessExpression": "lexical",  # TypeScript
}


class FieldSensitiveDefUse:
    """Builds intraprocedural field def-use edges over an existing GraphStore index.

    Usage:
        fs = FieldSensitiveDefUse(store.index)
        fs.build()
        adj = fs.augmented_value_flow()   # VALUE_FLOWS_TO ∪ field def-use, for reachability
        fs.groups                         # {(fn, root, path): {"w":[...], "r":[...]}}
        fs.edges                          # [(write_id, read_id), ...] added
    """

    def __init__(self, index):
        self.idx = index
        self._meta = {}
        self._ast_children = defaultdict(list)
        self._refers = {}
        self._vft = defaultdict(list)
        self._vft_in = set()
        self._vft_out = set()
        self.groups = {}
        self.edges = []

    # ---- structural helpers -------------------------------------------------
    def _load_edges(self):
        for e in self.idx.edges_of_kind("AST_CHILD"):
            self._ast_children[e["source"]].append(e["target"])
        for e in self.idx.edges_of_kind("REFERS_TO"):
            self._refers.setdefault(e["source"], e["target"])
        for e in self.idx.edges_of_kind("VALUE_FLOWS_TO"):
            self._vft[e["source"]].append(e["target"])
            self._vft_out.add(e["source"])
            self._vft_in.add(e["target"])

    def _m(self, nid):
        m = self._meta.get(nid)
        if m is None:
            n = self.idx._node(nid)
            p = (n or {}).get("properties", {})
            m = (p.get("syntax_kind"), (n or {}).get("label"))
            self._meta[nid] = m
        return m

    @staticmethod
    def _field_seg(label):
        """Field name of a MemberExpr from its label ('p->payload' -> 'payload')."""
        if not label:
            return None
        for sep in ("->", "."):
            if sep in label:
                tail = label.rsplit(sep, 1)[1].strip()
                if tail.isidentifier():
                    return tail
        return None

    def _resolve_child(self, nid, depth=0):
        """Skip casts/parens to the underlying base expression node."""
        if depth > 8:
            return nid
        sk, _ = self._m(nid)
        if sk in _CASTS:
            ch = self._ast_children.get(nid)
            if ch:
                return self._resolve_child(ch[0], depth + 1)
        return nid

    @staticmethod
    def _lexical_path(label):
        """Frontends that flatten member access: split the label on the last '.'.

        'self.app_import_path' -> (root='self', ('app_import_path',))
        'a.b.c'               -> (root='a.b', ('c',))   base kept as a string prefix
        Returns (root_string, (field,)) or None. Root is a string; the group key also
        carries owner_function_id, so 'self' is scoped per function (not global).
        """
        if not label or "." not in label:
            return None
        base, field = label.rsplit(".", 1)
        base, field = base.strip(), field.strip()
        if not field.isidentifier() or not base:
            return None
        return (base, (field,))

    def access_path(self, me_id, depth=0):
        """(root, (field, ... leaf-last)) or None. Dispatches by frontend strategy.

        structural (clang): root = the base *declaration* node — real object identity
          within a function, resolved via AST_CHILD -> cast-skip -> DeclRefExpr -> REFERS_TO.
        lexical (Python/JS/TS): root = the label-prefix string (function-scoped identity),
          because the frontend does not decompose member access into a base child.
        """
        if depth > 12:
            return None
        sk, lab = self._m(me_id)
        strategy = _FIELD_KINDS.get(sk)
        if strategy == "lexical":
            return self._lexical_path(lab)
        # structural (clang MemberExpr)
        field = self._field_seg(lab)
        if field is None:
            return None
        ch = self._ast_children.get(me_id)
        if not ch:
            return None
        base = self._resolve_child(ch[0])
        bsk, _ = self._m(base)
        if bsk == "MemberExpr":
            sub = self.access_path(base, depth + 1)
            if sub is None:
                return None
            root, fields = sub
            return (root, fields + (field,))
        if bsk == "DeclRefExpr":
            # REFERS_TO canonicalises the use to its declaration = object identity
            return (self._refers.get(base, base), (field,))
        # opaque base (call result, index expr): use the base node id as the root
        return (base, (field,))

    # ---- main build ---------------------------------------------------------
    def build(self):
        self._load_edges()
        groups = defaultdict(lambda: {"w": [], "r": []})
        for n in self.idx.nodes_of_kind("expression"):
            p = n.get("properties", {})
            if p.get("syntax_kind") not in _FIELD_KINDS:   # any frontend's field access
                continue
            nid = n["id"]
            self._meta[nid] = (p.get("syntax_kind"), n.get("label"))
            ap = self.access_path(nid)
            fn = p.get("owner_function_id")
            if ap is None or not fn:
                continue
            key = (fn, ap[0], ap[1])
            g = groups[key]
            # write == value flows INTO the member (assignment LHS / out-param);
            # read  == value flows OUT of the member.  A site can be both.
            if nid in self._vft_in:
                g["w"].append(nid)
            if nid in self._vft_out:
                g["r"].append(nid)
        self.groups = dict(groups)

        # add field def-use: every matching write -> read within the same object+path
        for key, g in self.groups.items():
            if g["w"] and g["r"]:
                for w in g["w"]:
                    for r in g["r"]:
                        if w != r:
                            self.edges.append((w, r))
        return self

    def augmented_value_flow(self):
        """VALUE_FLOWS_TO forward adjacency ∪ the added field def-use edges."""
        adj = defaultdict(list)
        for s, ts in self._vft.items():
            adj[s] = list(ts)
        for w, r in self.edges:
            adj[w].append(r)
        return adj
