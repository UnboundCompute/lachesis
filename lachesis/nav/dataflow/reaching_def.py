"""Ingredient 2 — reaching-def gen/kill dataflow over our clang CPG.

Implemented clean-room from the described algorithm (no code vendored). See the access-path
layer for the usage-analysis/access-path half.

Substrate mismatch: the reference algorithm runs gen/kill over an EXPRESSION-level CFG. Ours is
statement-level AND does not even chain straight-line assignments (measured: BinaryOps sit under a
CompoundStmt with no CFG position). So this module SYNTHESIZES a structured CFG from the AST
(sequence / if-else-merge / loop back-edge / return->exit) whose nodes are per-expression
micro-nodes in evaluation order (post-order: operands before operator; RHS-before-LHS for stores),
then runs the faithful forward gen/kill fixpoint over it. That is Horizon-A intraprocedural parity.

The model: EVERYTHING is a call.
  gen(op)  = {}                              if op is a member-access (fieldAccess/index/indirection/*)
           = {op} ∪ {id/call args}           otherwise
  kill(op) = {}                              if op is a generic-member-access (adds &, pointerShift)
           = ∪ over gen(op) of same-variable defs   otherwise
              (reassigning identifier x also kills fieldAccesses x.f; a call kills same-code calls)
  transfer(n,x) = gen(n) ∪ (x \ kill(n));  meet = union;  IN(entry)=∅, OUT init = gen.
A REACHING_DEF edge d->use is emitted when a reaching def d of node n is actually USED by an
argument `use` of n (isUsing = sameVariable | isContainer | isPart | isAlias),
isAlias being the field-sensitive access-path EXACT_MATCH test.
"""
from __future__ import annotations

import os
import sys
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

from .access_path import match_and_diff, EXACT
from .ap_construct import APBuilder
from lachesis.timeit import timeit

_DEBUG = os.environ.get("RD_DEBUG") == "1"


def _dbg(msg):
    if _DEBUG:
        sys.stderr.write(f"[rd {time.time():.1f}] {msg}\n")
        sys.stderr.flush()

# clang syntax_kind -> role sets ----------------------------------------------
_CASTS = {"ImplicitCastExpr", "CStyleCastExpr", "ParenExpr", "CXXConstCastExpr",
          "CXXStaticCastExpr", "CXXReinterpretCastExpr", "CXXFunctionalCastExpr"}
_LITERALS = {"IntegerLiteral", "FloatingLiteral", "StringLiteral", "CharacterLiteral",
             "CXXBoolLiteralExpr", "ImplicitValueInitExpr", "GNUNullExpr"}
_CALL = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"}
_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}
# operations that produce a value (a value-producing op)
_OP_KINDS = {"BinaryOperator", "CompoundAssignOperator", "UnaryOperator", "ConditionalOperator",
             "CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr", "MemberExpr",
             "ArraySubscriptExpr"}
_CONTAINER = {"MemberExpr", "ArraySubscriptExpr"}   # container set (fieldAccess/index)

_MAX_MICRO = 6000   # per-function bail-out


class ReachingDef:
    def __init__(self, sub):
        self.sub = sub
        self.apb = APBuilder(sub)
        self._ap_cache: Dict = {}

    # -- role predicates ------------------------------------------------------
    def _k(self, nid):
        return self.sub.kind(nid)

    def is_member_access(self, nid):
        """≈ isFieldAccess: transparent gen (fieldAccess/index/indirection *)."""
        k = self._k(nid)
        if k in _CONTAINER:
            return True
        if k == "UnaryOperator" and self.sub.operator(nid) == "*":
            return True
        return False

    def is_generic_member_access(self, nid):
        """≈ isGenericMemberAccessName: transparent kill (adds & / pointer shift)."""
        if self.is_member_access(nid):
            return True
        if self._k(nid) == "UnaryOperator" and self.sub.operator(nid) == "&":
            return True
        return False

    def is_op(self, nid):
        return self._k(nid) in _OP_KINDS

    def is_identifier(self, nid):
        return self._k(nid) == "DeclRefExpr"

    def is_param(self, nid):
        return self._k(nid) == "ParmVarDecl"

    def _peel(self, nid, d=0):
        if d > 12:
            return nid
        if self._k(nid) in _CASTS:
            ch = self.sub.ast_children.get(nid, [])
            if ch:
                return self._peel(ch[0], d + 1)
        return nid

    def _op_args(self, nid):
        """Direct argument sub-expressions of an operation (peeled; callee skipped for calls).

        Restricted to the function's owned set so macro-expansion argument nodes (emitted at line 1)
        don't leak in as spurious defs/uses. Falls back to unfiltered when no owned set is active."""
        ch = list(self.sub.ast_children.get(nid, []))
        if self._k(nid) in _CALL and ch:
            ch = ch[1:]                       # skip callee DeclRefExpr (index-0 receiver)
        os = getattr(self, "_owned_set", None)
        peeled = [self._peel(c) for c in ch]
        if os is None:
            return peeled
        return [c for c in peeled if c in os]

    def _name(self, nid):
        """nodeToString: identifier->name, expr->code, param->name (our label serves all)."""
        return self.sub.label(nid) or ""

    # -- expression micro-stream (post-order eval: operands before operator) --
    def _kids(self, nid):
        """AST children restricted to this function's owned set (drops macro-expansion nodes at
        line 1 and cross-function leakage that pollute the synthesized CFG)."""
        os = self._owned_set
        return [c for c in self.sub.ast_children.get(nid, []) if c in os]

    def expr_stream(self, nid, out: List, seen: Set, depth=0):
        if depth > 60 or nid in seen:
            return
        seen.add(nid)
        nid_p = self._peel(nid)
        if nid_p != nid:
            # Macro wrappers can belong to this function while the shared expansion
            # child is attributed to a synthetic macro function. Keep the local wrapper
            # as the micro-node instead of peeling into a foreign, unreachable node.
            if nid in self._owned_set and nid_p not in self._owned_set:
                out.append(nid)
                return
            self.expr_stream(nid_p, out, seen, depth + 1)
            return
        if nid not in self._owned_set:
            return
        k = self._k(nid)
        ch = list(self._kids(nid))
        # order children: RHS before LHS for plain assignment; else source order
        if k == "BinaryOperator" and self.sub.operator(nid) == "=" and len(ch) >= 2:
            ch = sorted(ch, key=lambda c: self.sub.offset(c))
            ch = [ch[1], ch[0]] + ch[2:]     # rhs, lhs, (rest)
        else:
            ch = sorted(ch, key=lambda c: self.sub.offset(c))
        for c in ch:
            self.expr_stream(c, out, seen, depth + 1)
        out.append(nid)                       # operator after operands

    # -- structured CFG synthesis from AST ------------------------------------
    def _is_stmt(self, nid):
        k = self._k(nid)
        return k.endswith("Stmt") or k in ("cfg-entry", "cfg-exit", "cfg-merge", "cfg-condition")

    def _label_name(self, nid) -> Optional[str]:
        """Identifier of a `LabelStmt`. The frontend renders it as ``name: <stmt>``;
        the name is the token before the first colon."""
        lbl = self.sub.label(nid) or ""
        name = lbl.split(":", 1)[0].strip()
        return name or None

    def _goto_target(self, nid) -> Optional[str]:
        """Target label of a `GotoStmt`. Rendered as ``goto name``; the name is the
        remainder after the leading ``goto`` keyword."""
        lbl = (self.sub.label(nid) or "").strip()
        if lbl.startswith("goto"):
            lbl = lbl[len("goto"):]
        return lbl.strip().rstrip(";").strip() or None

    def emit_stmt(self, nid, succ, depth=0) -> Tuple[Optional[str], List[str]]:
        """Return (entry_micro, [exit_micros]) for a statement subtree, wiring `succ` in between.

        Memoized per node id (reset each run_function): the clang AST reaching us is not a strict
        tree — nodes can be shared across paths (DAG) or form back-edges (cycle) — so without a
        visited guard emit_stmt re-traverses exponentially. A node is emitted at most once; a node
        re-entered while still in progress is a cycle and returns (None, []) to break it.
        """
        if depth > 200:
            return (None, [])
        memo = self._emit_memo
        if nid in memo:
            self._emit_memo_hits += 1
            return memo[nid]
        if nid in self._emit_inprogress:
            self._emit_cycle_breaks += 1
            _dbg(f"CYCLE at nid={nid} kind={self._k(nid)} label={self._name(nid)[:40]!r} "
                 f"line={self.sub.props(nid).get('start_line')}")
            return (None, [])
        self._emit_inprogress.add(nid)
        res = self._emit_stmt_body(nid, succ, depth)
        self._emit_inprogress.discard(nid)
        memo[nid] = res
        return res

    def _emit_stmt_body(self, nid, succ, depth) -> Tuple[Optional[str], List[str]]:
        k = self._k(nid)

        def role_children():
            out = defaultdict(list)
            role_index = getattr(self.sub, "ast_by_role", None)
            if role_index is not None:
                for role, children in role_index.get(nid, {}).items():
                    out[role].extend(child for child in children if child in self._owned_set)
                return out
            for edge in self.sub.idx.outgoing_of_kind(nid, "AST_CHILD"):
                if edge["target"] in self._owned_set:
                    out[edge.get("properties", {}).get("role") or "AST_CHILD"].append(
                        edge["target"])
            return out

        def chain(micros) -> Tuple[Optional[str], List[str]]:
            micros = [m for m in micros if m is not None]
            for a, b in zip(micros, micros[1:]):
                succ[a].append(b)
            if not micros:
                return (None, [])
            return (micros[0], [micros[-1]])

        if k in ("CompoundStmt",):
            kids = sorted(self._kids(nid), key=lambda c: self.sub.offset(c))
            first = None
            prev_exits: List[str] = []
            for c in kids:
                e, x = self.emit_stmt(c, succ, depth + 1)
                if e is None:
                    continue
                if first is None:
                    first = e
                for pe in prev_exits:
                    succ[pe].append(e)
                prev_exits = x
            return (first, prev_exits)

        if k == "IfStmt":
            kids = list(self._kids(nid))
            roles = role_children()
            conds = roles.get("CONDITION", [])
            cond = conds[0] if conds else (min(kids, key=self.sub.offset) if kids else None)
            branches = roles.get("TRUE_BRANCH", []) + roles.get("FALSE_BRANCH", [])
            if not branches:
                branches = [child for child in kids if child != cond][:2]
            cstream: List[str] = []
            if cond is not None:
                self.expr_stream(cond, cstream, set())
            centry, cexit = chain(cstream)
            exits: List[str] = []
            connected = False
            for br in branches:
                be, bx = self.emit_stmt(br, succ, depth + 1)
                if be is not None:
                    for ce in (cexit or []):
                        succ[ce].append(be)
                    connected = True
                    exits.extend(bx)
            # fall-through when a branch is absent
            if cexit and (len(branches) < 2 or not connected):
                exits.extend(cexit)
            return (centry or (exits[0] if exits else None), exits or cexit)

        if k == "ForStmt":
            kids = list(self._kids(nid))
            roles = role_children()
            body = next(iter(roles.get("LOOP_BODY", [])), None)
            cond = next(iter(roles.get("CONDITION", [])), None)
            # The init and increment arrive as unroled AST children distinguished only
            # by source position: init precedes the condition, increment follows it.
            # init may be a DeclStmt (`for (int i = 0; ...)`) OR a plain expression
            # (`for (p = head; ...)`); keying on DeclStmt alone drops the expression
            # form entirely, orphaning every value it defines. emit_stmt handles both
            # (a DeclStmt as a statement, an expression via the bare-expr path).
            other = sorted((child for child in kids if child not in {body, cond}),
                           key=lambda c: self.sub.offset(c))
            if cond is not None:
                cond_off = self.sub.offset(cond)
                init = next((c for c in other if self.sub.offset(c) < cond_off), None)
                increment = next((c for c in reversed(other)
                                  if self.sub.offset(c) > cond_off), None)
            else:
                init = other[0] if other else None
                increment = other[-1] if len(other) >= 2 else None
            ie, ix = self.emit_stmt(init, succ, depth + 1) if init else (None, [])
            cstream: List[str] = []
            if cond is not None:
                self.expr_stream(cond, cstream, set())
            centry, cexit = chain(cstream)
            be, bx = self.emit_stmt(body, succ, depth + 1) if body else (None, [])
            nstream: List[str] = []
            if increment is not None:
                self.expr_stream(increment, nstream, set())
            nentry, nexit = chain(nstream)
            if centry is not None:
                for x in ix:
                    succ[x].append(centry)
            if be is not None and cexit:
                for ce in cexit:
                    succ[ce].append(be)
            back = nentry or centry
            for x in bx:
                if back is not None:
                    succ[x].append(back)
            if nentry is not None and centry is not None:
                for x in nexit:
                    succ[x].append(centry)
            entry = ie or centry or be
            return (entry, cexit or bx)

        if k in ("WhileStmt", "DoStmt"):
            kids = list(self._kids(nid))
            roles = role_children()
            body = next(iter(roles.get("LOOP_BODY", [])), None)
            cond = next(iter(roles.get("CONDITION", [])), None)
            if (body is None or cond is None) and len(kids) >= 2:
                body, cond = ((kids[0], kids[-1]) if k == "DoStmt"
                              else (kids[-1], kids[0]))
            cstream: List[str] = []
            if cond is not None:
                self.expr_stream(cond, cstream, set())
            centry, cexit = chain(cstream)
            be, bx = self.emit_stmt(body, succ, depth + 1) if body else (None, [])
            if k == "DoStmt":
                for x in bx:
                    if centry is not None:
                        succ[x].append(centry)
                for x in cexit:
                    if be is not None:
                        succ[x].append(be)
                return (be or centry, cexit)
            for x in cexit:
                if be is not None:
                    succ[x].append(be)
            for x in bx:
                if centry is not None:
                    succ[x].append(centry)
            return (centry, cexit or bx)

        if k == "LabelStmt":
            # Linearize like the generic statement group below, but record the entry
            # micro under the label's name so deferred `goto`s can splice an edge to it.
            micros: List[str] = []
            for c in sorted(self._kids(nid), key=lambda c: self.sub.offset(c)):
                if self._is_stmt(c):
                    e, x = self.emit_stmt(c, succ, depth + 1)
                    if e is not None:
                        micros.append((e, x))
                else:
                    s = []
                    self.expr_stream(c, s, set())
                    micros.extend((m, [m]) for m in s)
            entry = micros[0][0] if micros else nid
            prev_exits: List[str] = []
            for e, x in micros:
                for pe in prev_exits:
                    succ[pe].append(e)
                prev_exits = x
            name = self._label_name(nid)
            if name:
                self._label_entries[name] = entry
            if not micros:
                # a bare `label:;` still needs a reachable placement node
                succ.setdefault(nid, [])
                return (nid, [nid])
            return (entry, prev_exits)

        if k == "GotoStmt":
            # An unconditional jump: a reachable micro-node with no fall-through exit,
            # wired to its target label after the whole body is emitted.
            target = self._goto_target(nid)
            if target:
                self._pending_gotos.append((nid, target))
            succ.setdefault(nid, [])
            return (nid, [])

        if k == "SwitchStmt":
            # A switch dispatches: control flows from the condition to EVERY case/
            # default label, not only into the first one. Sequential fall-through
            # between consecutive cases is real too, but it is NOT the only entry --
            # a case whose predecessor ends without fall-through (returns/breaks with
            # no exit) is still reachable via the dispatch. Modelling only fall-through
            # orphans every such case (and everything nested inside it). So: emit the
            # body compound (which chains the cases in source order, preserving
            # fall-through), then add an edge from the condition to each case/default
            # label entry. Precise `break`->after-switch edges remain a refinement;
            # the absence of a default keeps the condition itself as a fall-out exit.
            kids = list(self._kids(nid))
            roles = role_children()
            cond = next(iter(roles.get("CONDITION", [])), None)
            body = next(iter(roles.get("LOOP_BODY", [])), None)
            if body is None:
                comps = [c for c in kids if self._k(c) == "CompoundStmt"]
                body = comps[0] if comps else None
            if cond is None:
                non_body = [c for c in kids if c is not body]
                cond = min(non_body, key=self.sub.offset) if non_body else None
            cstream: List[str] = []
            if cond is not None:
                self.expr_stream(cond, cstream, set())
            centry, cexit = chain(cstream)
            bentry, bexits = (self.emit_stmt(body, succ, depth + 1)
                              if body is not None else (None, []))
            label_kids = []
            if body is not None:
                if self._k(body) in ("CaseStmt", "DefaultStmt"):
                    label_kids = [body]
                else:
                    label_kids = [c for c in sorted(self._kids(body),
                                                    key=lambda c: self.sub.offset(c))
                                  if self._k(c) in ("CaseStmt", "DefaultStmt")]
            case_entries: List[str] = []
            for c in label_kids:
                ce, _cx = self.emit_stmt(c, succ, depth + 1)   # memoized: same entry
                if ce is not None:
                    case_entries.append(ce)
            dispatch_srcs = cexit if cexit else ([centry] if centry else [])
            for src in dispatch_srcs:
                for ce in case_entries:
                    succ[src].append(ce)
            entry = centry or bentry or (case_entries[0] if case_entries else None)
            exits = list(bexits)
            has_default = any(self._k(c) == "DefaultStmt" for c in label_kids)
            if not has_default and cexit:
                exits.extend(cexit)        # no default => the condition can fall out
            return (entry, exits or cexit)

        if k in ("CaseStmt", "DefaultStmt"):
            # A case/default label carries nested STATEMENTS (the case body), not only
            # expressions. Chain the case-value expression and the guarded statement
            # subtrees in source order so the bodies stay reachable; the plain-expr
            # path below would keep only string micros and orphan every statement.
            units: List[Tuple[str, List[str]]] = []
            for c in sorted(self._kids(nid), key=lambda c: self.sub.offset(c)):
                if self._is_stmt(c):
                    e, x = self.emit_stmt(c, succ, depth + 1)
                    if e is not None:
                        units.append((e, x))
                else:
                    s = []
                    self.expr_stream(c, s, set())
                    units.extend((m, [m]) for m in s)
            if not units:
                return (None, [])
            first = units[0][0]
            prev_exits: List[str] = []
            for e, x in units:
                for pe in prev_exits:
                    succ[pe].append(e)
                prev_exits = x
            return (first, prev_exits)

        if k in ("ReturnStmt", "DeclStmt"):
            # linearize any contained expressions in source order
            micros: List[str] = []
            for c in sorted(self._kids(nid), key=lambda c: self.sub.offset(c)):
                if self._is_stmt(c):
                    e, x = self.emit_stmt(c, succ, depth + 1)
                    if e is not None:
                        micros.append(("_grp", e, x))
                else:
                    s: List[str] = []
                    self.expr_stream(c, s, set())
                    micros.extend(s)
            # flatten (only plain expr micros here for the common case)
            flat = [m for m in micros if isinstance(m, str)]
            entry, exits = chain(flat)
            if k == "ReturnStmt":
                # Keep a terminal node even for bare `return;`; callers can distinguish
                # it from normal fallthrough because it has no exits.
                if entry is None:
                    succ.setdefault(nid, [])
                    return (nid, [])
                for x in exits:
                    succ[x].append(nid)
                succ.setdefault(nid, [])
                return (entry, [])
            if k == "DeclStmt" and entry is None:
                # Macro-only initializers may have no owned expansion child. The
                # declaration statement is still a valid placement node.
                succ.setdefault(nid, [])
                return (nid, [nid])
            return (entry, exits)

        if k == "NullStmt":
            return (None, [])

        if k in ("BreakStmt", "ContinueStmt"):
            # A jump: reachable (so it is placed), but with NO fall-through exit -- the
            # statement that textually follows is not wired from here. In a switch this
            # is what stops one case from bleeding into the next; the following case is
            # still reachable through the switch's dispatch edges. Without this a `break`
            # was invisible and every case fell through into the next, both spuriously
            # (a case->case edge C never takes) and expensively (the extra fan-in blows
            # the object-state transfer budget). Precise break->after-switch /
            # continue->loop-header edges remain a refinement.
            succ.setdefault(nid, [])
            return (nid, [])

        if self._is_stmt(nid):
            return (None, [])

        # bare expression used as a statement
        s: List[str] = []
        self.expr_stream(nid, s, set())
        return chain(s)

    # -- per-function reaching-def --------------------------------------------
    def run_function(self, fn) -> Dict:
        st = self.analyze(fn)
        if st is None:
            return {"edges": [], "field_edges": [], "micro": 0}
        if st.get("bailed"):
            return {"edges": [], "field_edges": [], "micro": st["micro"], "bailed": True}
        return self._emit_edges(st["nodes"], st["IN"], st["gen"])

    @timeit
    def analyze(self, fn, *, reaching_defs=True) -> Optional[Dict]:
        """Intraprocedural CFG state for `fn`, the shared substrate the def->use edge
        emitter (and any def-site-keyed client such as a typestate pass) runs over:

          nodes  ordered micro-node list (BFS from entry)
          succ   node -> [node]     control-flow successors (branch/loop/merge)
          pred   node -> [node]     predecessors
          gen    node -> {def}      reaching-defs generated here (def-site == node id)
          kill   node -> {def}      reaching-defs killed here (a redefinition kills the
                                    prior def -- this is what makes reassignment reset
                                    a pointer's tracked state, generally, for free)
          IN/OUT node -> {def}      reaching-def sets at the fixpoint

        ``reaching_defs=False`` returns after CFG synthesis with only
        ``nodes/succ/params/root/micro``. Def-site clients use the full default;
        object-state clients need control flow but not a second, unused dataflow
        fixpoint.

        Returns None when the function has no analysable body; a dict with
        ``bailed=True`` (and ``micro``) when the body exceeds the micro-node cap."""
        owned = set(self.sub._owned(fn))
        # function body root = the top CompoundStmt owned by fn
        roots = [b for b in owned if self._k(b) == "CompoundStmt"
                 and self.sub.ast_parent.get(b) not in owned]
        if not roots:
            roots = [b for b in owned if self._k(b) == "CompoundStmt"]
        if not roots:
            return None
        # pick outermost (smallest offset / largest span)
        root = min(roots, key=lambda b: self.sub.offset(b))

        _dbg(f"analyze fn={fn} owned={len(owned)} root={root}")
        succ: Dict[str, List[str]] = defaultdict(list)
        params = [p for p in owned if self._k(p) == "ParmVarDecl"]
        params.sort(key=lambda p: self.sub.offset(p))
        self._owned_set = owned
        self._emit_memo = {}
        self._emit_inprogress = set()
        self._emit_memo_hits = 0
        self._emit_cycle_breaks = 0
        # goto/label wiring: a labeled block reachable only via `goto` (the dominant C
        # cleanup idiom) is otherwise dropped from the CFG. Collect label entry-micros
        # and deferred goto edges during emission, then splice them after the walk when
        # every label has been emitted.
        self._label_entries: Dict[str, str] = {}
        self._pending_gotos: List[Tuple[str, str]] = []
        entry, exits = self.emit_stmt(root, succ, 0)
        for goto_nid, target in self._pending_gotos:
            label_entry = self._label_entries.get(target)
            if label_entry is not None:
                succ[goto_nid].append(label_entry)
        _dbg(f"emit_stmt done: succ-keys={len(succ)} entry={entry} "
             f"emit-calls={len(self._emit_memo)} memo-hits={self._emit_memo_hits} "
             f"cycle-breaks={self._emit_cycle_breaks}")
        if entry is None:
            return None

        # Make normal fallthrough explicit. This preserves the false edge of a final
        # if/loop condition, which otherwise has only its taken successor.
        cfg_entries = [n for n in owned if self._k(n) == "cfg-entry"]
        cfg_exits = [n for n in owned if self._k(n) == "cfg-exit"]
        cfg_entry = cfg_entries[0] if cfg_entries else None
        cfg_exit = cfg_exits[0] if cfg_exits else None
        if cfg_exit is not None:
            succ.setdefault(cfg_exit, [])
            for x in exits:
                succ[x].append(cfg_exit)

        # prepend CFG entry + formal parameter chain -> body entry
        chain_nodes = ([cfg_entry] if cfg_entry else []) + params + [entry]
        for a, b in zip(chain_nodes, chain_nodes[1:]):
            succ[a].append(b)
        start = chain_nodes[0]

        # collect all micro-nodes reachable
        nodes: List[str] = []
        seen: Set[str] = set()
        dq = deque([start])
        while dq:
            n = dq.popleft()
            if n in seen:
                continue
            seen.add(n)
            nodes.append(n)
            for s in succ.get(n, []):
                if s not in seen:
                    dq.append(s)
        _dbg(f"micro-nodes collected={len(nodes)}")
        if _DEBUG:
            seq = [(self.sub.props(n).get("start_line"), self._k(n), self._name(n)[:22]) for n in nodes]
            _dbg("CFG micro order (BFS): " + " | ".join(
                f"L{ln}:{k}:{lab}" for ln, k, lab in seq))
        if len(nodes) > _MAX_MICRO:
            return {"bailed": True, "micro": len(nodes)}

        if not reaching_defs:
            return {"nodes": nodes, "succ": dict(succ), "params": params,
                    "root": root, "micro": len(nodes)}

        pred: Dict[str, List[str]] = defaultdict(list)
        for a, ss in succ.items():
            for b in ss:
                if a in seen and b in seen:
                    pred[b].append(a)

        gen, kill = self._gen_kill(nodes, params)
        _dbg(f"gen/kill done: gen-keys={len(gen)} kill-keys={len(kill)} "
             f"gen-total={sum(len(v) for v in gen.values())}")

        # forward fixpoint (worklist)
        IN: Dict[str, Set[str]] = {n: set() for n in nodes}
        OUT: Dict[str, Set[str]] = {n: set(gen.get(n, ())) for n in nodes}
        wl = deque(nodes)
        inwl = set(nodes)
        _iter = 0
        _cap = 200 * len(nodes) + 100000     # generous upper bound; monotone => converges far sooner
        while wl:
            _iter += 1
            if _DEBUG and _iter % 100000 == 0:
                _dbg(f"fixpoint iter={_iter} wl={len(wl)}")
            if _iter > _cap:
                _dbg(f"FIXPOINT CAP HIT at iter={_iter} (nodes={len(nodes)}) — non-convergence bug")
                break
            n = wl.popleft()
            inwl.discard(n)
            newin: Set[str] = set()
            for p in pred.get(n, ()):
                newin |= OUT[p]
            IN[n] = newin
            newout = set(gen.get(n, ())) | (newin - kill.get(n, set()))
            if newout != OUT[n]:
                OUT[n] = newout
                for s in succ.get(n, ()):
                    if s in seen and s not in inwl:
                        wl.append(s)
                        inwl.add(s)
        _dbg(f"fixpoint done iter={_iter}")

        return {"nodes": nodes, "succ": dict(succ), "pred": dict(pred),
                "gen": gen, "kill": kill, "IN": IN, "OUT": OUT,
                "params": params, "root": root, "micro": len(nodes)}

    def _gen_kill(self, nodes, params):
        gen: Dict[str, Set[str]] = {}
        # precompute name -> identifier/param nodes, and code -> op nodes, and
        # fieldAccess nodes containing identifier name
        name_nodes: Dict[str, List[str]] = defaultdict(list)
        code_ops: Dict[str, List[str]] = defaultdict(list)
        field_by_name: Dict[str, List[str]] = defaultdict(list)
        for n in nodes:
            if self.is_identifier(n) or self.is_param(n):
                name_nodes[self._name(n)].append(n)
            if self.is_op(n) and not self.is_member_access(n):
                code_ops[self._name(n)].append(n)
            if self._k(n) in _CONTAINER:
                for idn in self._contained_ident_names(n):
                    field_by_name[idn].append(n)

        for p in params:
            gen[p] = {p}
        for n in nodes:
            if not self.is_op(n):
                continue
            if self.is_member_access(n):
                gen[n] = set()               # transparent
                continue
            g = {n}
            for a in self._op_args(n):
                if self.is_identifier(a) or self.is_op(a):
                    g.add(a)
            gen[n] = g

        kill: Dict[str, Set[str]] = {}
        for n in nodes:
            if not self.is_op(n) or self.is_generic_member_access(n):
                continue
            ks: Set[str] = set()
            for d in gen.get(n, ()):
                if self.is_identifier(d) or self.is_param(d):
                    nm = self._name(d)
                    for x in name_nodes.get(nm, ()):
                        if x != d:
                            ks.add(x)
                    for x in field_by_name.get(nm, ()):
                        ks.add(x)
                elif self.is_op(d):
                    for x in code_ops.get(self._name(d), ()):
                        if x != d:
                            ks.add(x)
            if ks:
                kill[n] = ks
        return gen, kill

    def _contained_ident_names(self, nid) -> Set[str]:
        names: Set[str] = set()
        stack = list(self.sub.ast_children.get(nid, []))
        d = 0
        while stack and d < 5000:
            d += 1
            x = stack.pop()
            if self.is_identifier(x):
                names.add(self._name(x))
            for c in self.sub.ast_children.get(x, []):
                stack.append(c)
        return names

    # -- usage analysis + edge emission ---------------------------------------
    def _track(self, nid):
        if nid not in self._ap_cache:
            self._ap_cache[nid] = self.apb.build(nid)
        return self._ap_cache[nid]

    def is_using(self, use, inn) -> bool:
        return (self._same_variable(use, inn) or self._is_container(use, inn)
                or self._is_part(use, inn) or self._is_alias(use, inn))

    def _same_variable(self, use, inn) -> bool:
        us = self._name(use)
        if self.is_param(inn):
            return self._name(inn) in us
        if self._k(inn) == "UnaryOperator" and self.sub.operator(inn) in ("&", "*"):
            ch = self._op_args(inn)
            return bool(ch) and self._name(ch[0]) in us
        if self.is_op(inn):
            return self._name(inn) in us
        if self.is_identifier(inn):
            return self._name(inn) in us
        return False

    def _is_container(self, use, inn) -> bool:
        if self._k(inn) in _CONTAINER:
            args = self._op_args(inn)
            if args:
                return self._name(use) == self._name(args[0])
        return False

    def _is_part(self, use, inn) -> bool:
        if self._k(use) in _CONTAINER:
            args = self._op_args(use)
            if not args:
                return False
            base = self._name(args[0])
            if self.is_param(inn) or self.is_identifier(inn):
                return self._name(inn) in base
        return False

    def _is_alias(self, use, inn) -> bool:
        if not (self.is_op(use) and self.is_op(inn)):
            return False
        tu = self._track(use)
        ti = self._track(inn)
        if tu is None or ti is None:
            return False
        if tu[0] != ti[0]:
            return False
        res, _ = match_and_diff(tu[1], ti[1])
        return res == EXACT

    def _uses(self, nid) -> List[str]:
        k = self._k(nid)
        if k in _OP_KINDS:
            return self._op_args(nid)
        if k == "ReturnStmt":
            return [self._peel(c) for c in self.sub.ast_children.get(nid, [])
                    if not self._is_stmt(c)]
        return []

    def _emit_edges(self, nodes, IN, gen) -> Dict:
        edges: List[Tuple[str, str]] = []
        field_edges: List[Tuple[str, str]] = []
        _pairs = 0
        for n in nodes:
            if not self.is_op(n):
                continue
            reaching = IN.get(n, set())
            if not reaching:
                continue
            for use in self._uses(n):
                for d in reaching:
                    _pairs += 1
                    if _DEBUG and _pairs % 500000 == 0:
                        _dbg(f"emit_edges pairs={_pairs} edges={len(edges)}")
                    if d == use:
                        continue
                    if self.is_using(use, d):
                        edges.append((d, use))
                        if self._k(d) in _CONTAINER and self._k(use) in _CONTAINER:
                            field_edges.append((d, use))
        return {"edges": edges, "field_edges": field_edges, "micro": len(nodes)}
