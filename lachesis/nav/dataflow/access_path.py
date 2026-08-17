"""Ingredient 1 — the access-path algebra (exact-match), implemented clean-room.

Implemented from the ALGORITHM described in the access-path spec (no code vendored). This is the exact-match algebra that decides whether a def of one access path reaches a
use of another: the token alphabet, canonical normalization, tail inversion, seam concatenation,
and the 7-way match-and-diff state machine.

Everything here is pure/immutable and graph-agnostic. Construction of an access path FROM our clang
CPG lives in `ap_construct.py` (kept separate so the algebra can be unit-tested standalone).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


# --- 0. Alphabet -------------------------------------------------------------
# kind is the primary compare key; str form is the secondary key.
K_CONST = 0x01010101
K_VAR = 0x02020202     # ? wildcard, non-invertible head
K_VPS = 0x03030303     # <?> wildcard, invertible tail
K_IND = 0x04040404     # *  non-invertible head
K_ADDR = 0x05050505    # &  invertible tail
K_SHIFT = 0x06060606   # <i> invertible tail


@dataclass(frozen=True)
class Elem:
    kind: int
    # payload: field text for CONST, logical offset for SHIFT, else None
    field: Optional[str] = None
    offset: Optional[int] = None

    def s(self) -> str:
        if self.kind == K_CONST:
            return self.field or ""
        if self.kind == K_VAR:
            return "?"
        if self.kind == K_VPS:
            return "<?>"
        if self.kind == K_IND:
            return "*"
        if self.kind == K_ADDR:
            return "&"
        if self.kind == K_SHIFT:
            return "<%d>" % self.offset
        return "?"

    # sort: kind asc, then string name (shifts compare LEXICOGRAPHICALLY, per spec §0)
    def sort_key(self) -> Tuple[int, str]:
        return (self.kind, self.s())

    @property
    def invertible(self) -> bool:
        return self.kind in (K_ADDR, K_VPS, K_SHIFT)

    @property
    def wildcard(self) -> bool:
        return self.kind in (K_VAR, K_VPS)


# token constructors
def Const(field: str) -> Elem: return Elem(K_CONST, field=field)
def Var() -> Elem: return Elem(K_VAR)
def VPS() -> Elem: return Elem(K_VPS)
def Ind() -> Elem: return Elem(K_IND)
def Addr() -> Elem: return Elem(K_ADDR)
def Shift(i: int) -> Elem: return Elem(K_SHIFT, offset=i)


# --- 1. Normalization --------------------------------------------------------
def normalize(seq: List[Elem]) -> List[Elem]:
    """Left-to-right stack pass; cancellations chain (new top re-tested vs next input)."""
    out: List[Elem] = []
    for e in seq:
        if e.kind == K_SHIFT and e.offset == 0:
            continue                                    # drop <0>
        if not out:
            out.append(e)
            continue
        last = out[-1]
        if last.kind == K_SHIFT and e.kind == K_SHIFT:
            s = last.offset + e.offset
            if s != 0:
                out[-1] = Shift(s)                      # <i><j> -> <i+j>
            else:
                out.pop()                               # <i><-i> -> cancel
        elif last.kind == K_VPS and e.kind in (K_SHIFT, K_VPS):
            pass                                        # <?><j> -> <?> ; <?><?> -> <?>
        elif last.kind == K_SHIFT and e.kind == K_VPS:
            out[-1] = VPS()                             # <i><?> -> <?>
        elif last.kind == K_ADDR and e.kind == K_IND:
            out.pop()                                   # & * -> cancel
        elif last.kind == K_IND and e.kind == K_ADDR:
            out.pop()                                   # * & -> cancel (intentional)
        else:
            out.append(e)
    return out


def inverted(seq: List[Elem]) -> List[Elem]:
    """Invert an all-invertible slice: reverse + map. THROWS on Const/Variable (contract)."""
    res: List[Elem] = []
    for e in reversed(seq):
        if e.kind == K_ADDR:
            res.append(Ind())
        elif e.kind == K_IND:
            res.append(Addr())
        elif e.kind == K_SHIFT:
            res.append(Shift(-e.offset))
        elif e.kind == K_VPS:
            res.append(VPS())
        else:
            raise ValueError("cannot invert non-invertible element: %s" % e.s())
    return res


def concat(a: List[Elem], b: List[Elem]) -> List[Elem]:
    """a ++ b: reconcile ONLY the seam (tail of a meets head of b), walking inward symmetrically."""
    if not a:
        return list(b)
    if not b:
        return list(a)
    idx = 0
    buf: Optional[Elem] = None
    done = False
    while idx < min(len(a), len(b)) and not done:
        la = a[len(a) - 1 - idx]
        rb = b[idx]
        if la.kind == K_ADDR and rb.kind == K_IND:
            idx += 1                                    # & * cancel, keep walking
        elif la.kind == K_IND and rb.kind == K_ADDR:
            idx += 1                                    # * & cancel
        elif (la.kind == K_VPS and rb.kind == K_VPS) or \
             (la.kind == K_SHIFT and rb.kind == K_VPS) or \
             (la.kind == K_VPS and rb.kind == K_SHIFT):
            done = True
            buf = VPS()
            idx += 1
        elif la.kind == K_SHIFT and rb.kind == K_SHIFT:
            s = la.offset + rb.offset
            if s != 0:
                done = True
                buf = Shift(s)
            idx += 1                                    # s==0 -> keep walking deeper
        else:
            done = True
    head = a[:len(a) - idx]
    mid = [buf] if buf is not None else []
    tail = b[idx:]
    return head + mid + tail


# --- MatchResult -------------------------------------------------------------
NO_MATCH = "NO_MATCH"
EXACT = "EXACT_MATCH"
VAR_EXACT = "VARIABLE_EXACT_MATCH"
PREFIX = "PREFIX_MATCH"
VAR_PREFIX = "VARIABLE_PREFIX_MATCH"
EXTENDED = "EXTENDED_MATCH"
VAR_EXTENDED = "VARIABLE_EXTENDED_MATCH"


def _invertible_tail_len(e: List[Elem]) -> int:
    n = 0
    for x in reversed(e):
        if x.invertible:
            n += 1
        else:
            break
    return n


def _no_overtaint_ap(e: List[Elem], frm: int) -> bool:
    """AccessPath-private noOvertaint: False if any of e[frm:] is VariableAccess OR VarPtrShift."""
    for x in e[frm:]:
        if x.kind in (K_VAR, K_VPS):
            return False
    return True


def _elems_eq(a: List[Elem], b: List[Elem]) -> bool:
    return a == b   # frozen dataclass -> structural equality


def _starts_with(seq: List[Elem], prefix: List[Elem]) -> bool:
    if len(prefix) > len(seq):
        return False
    return seq[:len(prefix)] == prefix


def match_and_diff(this: List[Elem], other: List[Elem],
                   exclusions: Optional[List[List[Elem]]] = None) -> Tuple[str, List[Elem]]:
    """CP=this, AP=other. Returns (MatchResult, diff). exclusions only used for EXTENDED case."""
    exclusions = exclusions or []
    this_tail = _invertible_tail_len(this)
    other_tail = _invertible_tail_len(other)
    this_head = len(this) - this_tail
    other_head = len(other) - other_tail
    cmp_until = min(this_head, other_head)
    idx = 0
    over = False

    # Phase 1: compare heads
    _OVERTAINT_P1 = {
        (K_VAR, K_VAR), (K_CONST, K_VAR), (K_VAR, K_CONST),
        (K_VPS, K_VPS), (K_SHIFT, K_VPS), (K_VPS, K_SHIFT),
    }
    while idx < cmp_until:
        a, b = this[idx], other[idx]
        if (a.kind, b.kind) in _OVERTAINT_P1:
            over = True
        elif a != b:
            return (NO_MATCH, [])
        idx += 1

    # Phase 2: greedy tail extension
    minlen = min(len(this), len(other))
    done = False
    _OVERTAINT_P2 = {(K_SHIFT, K_VPS), (K_VPS, K_SHIFT), (K_VPS, K_VPS)}
    while not done and idx < minlen:
        a, b = this[idx], other[idx]
        if (a.kind, b.kind) in _OVERTAINT_P2:
            over = True
            idx += 1
        elif a == b:
            idx += 1
        else:
            done = True

    # Classify
    if this_head >= other_head:
        diff = concat(inverted(other[idx:]), this[idx:])
        if not _no_overtaint_ap(other, other_head):
            over = True
        if this_head == other_head:
            return (VAR_EXACT if over else EXACT, diff)
        return (VAR_PREFIX if over else PREFIX, diff)
    else:
        diff = concat(inverted(this[idx:]), other[idx:])
        if (not _no_overtaint_ap(this, this_head)) or (not _no_overtaint_ap(other, other_head)):
            over = True
        if over:
            return (VAR_EXTENDED, diff)
        for ex in exclusions:
            if _starts_with(diff, ex):
                return (NO_MATCH, [])
        return (EXTENDED, diff)


# --- self-test (worked examples from the spec) -------------------------------
if __name__ == "__main__":
    c, d = Const("c"), Const("d")

    def check(cp, ap, want_res, want_diff, excl=None):
        res, diff = match_and_diff(normalize(cp), normalize(ap), excl)
        ok = (res == want_res) and _elems_eq(diff, normalize(want_diff))
        print(("ok " if ok else "FAIL"),
              "".join(x.s() for x in cp) or "ε", "|",
              "".join(x.s() for x in ap) or "ε", "->", res,
              "diff=", "".join(x.s() for x in diff) or "ε",
              ("" if ok else f"  (wanted {want_res} diff={''.join(x.s() for x in want_diff) or 'ε'})"))
        return ok

    allok = True
    allok &= check([Ind(), c], [Ind(), c], EXACT, [])
    allok &= check([c], [d], NO_MATCH, [])
    allok &= check([c, d], [c], PREFIX, [d])
    allok &= check([c], [c, d], EXTENDED, [d])
    allok &= check([Ind()], [Ind(), Shift(2)], EXACT, [Shift(-2)])
    allok &= check([Ind(), Shift(5), Ind()], [Ind(), Shift(2)], PREFIX, [Shift(3), Ind()])
    allok &= check([Var()], [c], VAR_EXACT, [])
    allok &= check([VPS(), Ind()], [Shift(3), Ind()], VAR_EXACT, [])
    allok &= check([c], [c, d], NO_MATCH, [], excl=[[d]])
    allok &= check([c, d], [c, Var()], VAR_EXACT, [])
    # normalization spot-checks
    def neq(seq, want, tag):
        got = normalize(seq)
        ok = _elems_eq(got, want)
        print(("ok " if ok else "FAIL"), "norm", tag, "->", "".join(x.s() for x in got) or "ε")
        return ok
    allok &= neq([Addr(), Ind()], [], "&*")
    allok &= neq([Ind(), Addr()], [], "*&")
    allok &= neq([Shift(2), Shift(-2)], [], "<2><-2>")
    allok &= neq([Shift(2), Shift(3)], [Shift(5)], "<2><3>")
    allok &= neq([Shift(0)], [], "<0>")
    allok &= neq([VPS(), Shift(3)], [VPS()], "<?><3>")
    allok &= neq([Addr(), Shift(2), Shift(-2), Ind()], [], "&<2><-2>*")
    print("\nALL PASS" if allok else "\nSOME FAILED")
