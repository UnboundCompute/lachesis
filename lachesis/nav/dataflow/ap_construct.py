"""Ingredient 1 (construction) — clang CPG expression -> (tracked base, access-path Elements).

Our clang frontend emits structured AST: MemberExpr (arrow/dot), ArraySubscriptExpr,
UnaryOperator (* / &), wrapped in casts. This module walks that AST and produces the
(base, normalized Elements) pair the algebra in access_path.py consumes, following the
operator->token table in the access-path spec.

The tracked base is represented as a hashable identity key:
  ("named", decl_id)  a variable/param, canonicalised to its declaration node (REFERS_TO) — real
                      object identity within a function.
  ("ret", call_id)    the return value of a non-member-access call.
  ("lit", nid)        a literal.  ("unk", nid) opaque base.

Build order: recurse the base sub-expression, PREPEND this operator's tokens onto the
(reversed) accumulator, reverse once at the end, normalize once.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from .access_path import (Elem, Const, Var, VPS, Ind, Addr, Shift, normalize)

_CASTS = {"ImplicitCastExpr", "CStyleCastExpr", "ParenExpr", "CXXConstCastExpr",
          "CXXStaticCastExpr", "CXXReinterpretCastExpr", "CXXFunctionalCastExpr"}
_LITERALS = {"IntegerLiteral", "FloatingLiteral", "StringLiteral", "CharacterLiteral",
             "CXXBoolLiteralExpr", "ImplicitValueInitExpr", "GNUNullExpr"}
_CALLISH = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"}


class APBuilder:
    """Constructs (base, Elements) for expression nodes over a Substrate adapter."""

    def __init__(self, sub):
        self.sub = sub                      # Substrate (substrate.py) — provides kind/label/ast/refers

    # -- helpers --------------------------------------------------------------
    def _children(self, nid) -> List:
        return self.sub.ast_children.get(nid, [])

    def _peel(self, nid, depth=0):
        """Skip cast/paren wrappers to the underlying expression node."""
        if depth > 12:
            return nid
        if self.sub.kind(nid) in _CASTS:
            ch = self._children(nid)
            if ch:
                return self._peel(ch[0], depth + 1)
        return nid

    @staticmethod
    def _member_field_and_arrow(label: str) -> Optional[Tuple[str, bool]]:
        """(field, is_arrow) from a MemberExpr label. Rightmost '->' vs '.' wins."""
        if not label:
            return None
        ia = label.rfind("->")
        id_ = label.rfind(".")
        if ia < 0 and id_ < 0:
            return None
        if ia > id_:
            field = label[ia + 2:].strip()
            arrow = True
        else:
            field = label[id_ + 1:].strip()
            arrow = False
        # strip any trailing subscript/paren noise
        for stop in ("[", "(", " "):
            if stop in field:
                field = field.split(stop, 1)[0]
        return (field, arrow) if field.isidentifier() else None

    # -- leaf bases -----------------------------------------------------------
    def _leaf(self, nid):
        k = self.sub.kind(nid)
        if k == "DeclRefExpr":
            decl = self.sub.refers.get(nid, nid)
            return ("named", decl)
        if k in ("ParmVarDecl", "VarDecl"):
            return ("named", nid)
        if k in _LITERALS:
            return ("lit", nid)
        return None

    # -- recursion ------------------------------------------------------------
    def build(self, nid, depth=0) -> Optional[Tuple[Tuple, List[Elem]]]:
        """Returns (base_key, normalized Elements) or None. Elements in FINAL order."""
        base, rev = self._build_rev(nid, depth)
        if base is None:
            return None
        rev.reverse()
        return (base, normalize(rev))

    def _build_rev(self, nid, depth) -> Tuple[Optional[Tuple], List[Elem]]:
        """Returns (base_key, path in REVERSED build order). Prepending == list.append here."""
        if depth > 40:
            return (("unk", nid), [])
        nid = self._peel(nid)
        k = self.sub.kind(nid)

        leaf = self._leaf(nid)
        if leaf is not None:
            return (leaf, [])

        if k == "MemberExpr":
            fa = self._member_field_and_arrow(self.sub.label(nid))
            if fa is None:
                return (("unk", nid), [])
            field, arrow = fa
            ch = self._children(nid)
            if not ch:
                return (("unk", nid), [])
            base, tail = self._build_rev(ch[0], depth + 1)
            # indirectFieldAccess p->f : prepend FIELD then Indirection ; fieldAccess x.f : prepend FIELD
            tail.append(Const(field))
            if arrow:
                tail.append(Ind())
            return (base, tail)

        if k == "ArraySubscriptExpr":
            ch = self._children(nid)
            if not ch:
                return (("unk", nid), [])
            # child[0] = the array/pointer base, child[1] = index
            base, tail = self._build_rev(ch[0], depth + 1)
            idx_tok = self._index_token(ch[1]) if len(ch) > 1 else VPS()
            # indirectIndexAccess p[i] : prepend Indirection then SHIFT (build), final <i> *
            tail.append(idx_tok)
            tail.append(Ind())
            return (base, tail)

        if k == "UnaryOperator":
            op = self.sub.operator(nid)
            ch = self._children(nid)
            if not ch:
                return (("unk", nid), [])
            if op == "*":
                base, tail = self._build_rev(ch[0], depth + 1)
                tail.append(Ind())
                return (base, tail)
            if op == "&":
                base, tail = self._build_rev(ch[0], depth + 1)
                tail.append(Addr())
                return (base, tail)
            # ++/--/! etc: not an access-path op; treat operand as the value
            return self._build_rev(ch[0], depth + 1)

        if k in _CALLISH:
            return (("ret", nid), [])          # real call = fresh base (its return value)

        return (("unk", nid), [])

    def _index_token(self, idx_nid) -> Elem:
        idx_nid = self._peel(idx_nid)
        if self.sub.kind(idx_nid) in _LITERALS:
            lab = (self.sub.label(idx_nid) or "").strip()
            try:
                return Shift(int(lab, 0))
            except ValueError:
                return VPS()
        return VPS()
