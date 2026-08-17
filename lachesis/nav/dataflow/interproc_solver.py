"""Ingredient 3 — interprocedural backward context-sensitive solver, implemented clean-room.

Implemented clean-room from the described algorithm (no code vendored). The dataflow answer is:
walk REACHING_DEF edges BACKWARD from a sink; the walk is context-sensitive via a callSiteStack (push on descending into a
callee / crossing to a caller, pop on return) bounded by call depth (k = 4); a
FlowSemantic table decides how taint crosses a call (arg index -> param/return index; default
external-leaky, internal-without-semantic descends).

This runs OVER the materialized REACHING_DEF edges produced by reaching_def.py, plus our
ARGUMENT_BINDS_PARAMETER edges (arg-expr <-> callee ParmVarDecl) which realise the param<->arg
binding. It is the context-sensitive replacement for a context-insensitive forward closure.

Representation:
  * A "task" fingerprint = (node, call_site_stack, call_depth).
  * State on the walk = a PathElement (node, call_site_stack).
  * Sources = the taint sources we want to reach (attacker-controlled params / capture fields).

The FlowSemantic table below is a minimal default covering a few well-known library calls; a
caller may supply a richer semantics catalog without changing the solver.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

MAX_CALL_DEPTH = 4          # max call depth (k-limit)

# transparent-cast wrappers to peel so a bind's arg node lands on the same node the
# REACHING_DEF edges use (our clang frontend splits arg-expr vs ImplicitCastExpr into two
# nodes for one logical argument). MUST match reaching_def._CASTS.
_CASTS = {"ImplicitCastExpr", "CStyleCastExpr", "ParenExpr", "CXXConstCastExpr",
          "CXXStaticCastExpr", "CXXReinterpretCastExpr", "CXXFunctionalCastExpr"}


class FlowSemantic:
    """Minimal src-arg -> dst-(arg|return) mappings for well-known external calls.

    This is a small default; richer semantics can be supplied by the caller (e.g. a
    catalog keyed by call name) and consulted through `for_call`.

    index convention: 0 = receiver, 1..n = positional args, -1 = return value.
    A call NOT in this table and internal -> descend into it (create sub-task).
    A call NOT in this table and external -> leaky passthrough (every arg taints return + args).
    """
    # name -> list of (src_index, dst_index)
    TABLE: Dict[str, List[Tuple[int, int]]] = {
        "memcpy": [(2, 1), (2, -1)],          # src(2) -> dst(1), return
        "memmove": [(2, 1), (2, -1)],
        "strcpy": [(2, 1), (2, -1)],
        "strncpy": [(2, 1), (2, -1)],
        "memset": [(1, -1)],
    }

    @classmethod
    def for_call(cls, name: str) -> Optional[List[Tuple[int, int]]]:
        return cls.TABLE.get(name)


class InterprocSolver:
    """Backward context-sensitive reachability over materialized REACHING_DEF + arg/param binds."""

    def __init__(self, sub, reaching_def_edges: List[Tuple[str, str]]):
        self.sub = sub
        # backward adjacency over REACHING_DEF: use -> [defs] (walk dst -> src)
        self.rd_back: Dict[str, List[str]] = defaultdict(list)
        for d, u in reaching_def_edges:
            self.rd_back[u].append(d)
        # param <-> arg binding (ARGUMENT_BINDS_PARAMETER: arg -> param)
        self.arg_of_param: Dict[str, List[str]] = defaultdict(list)   # param -> [arg exprs]
        self.param_of_arg: Dict[str, List[str]] = defaultdict(list)   # arg -> [params]
        for e in sub.idx.edges_of_kind("ARGUMENT_BINDS_PARAMETER"):
            arg = self._peel(e["source"])          # land on the RD-participating node
            self.arg_of_param[e["target"]].append(arg)
            self.param_of_arg[arg].append(e["target"])

    def _peel(self, nid, d=0):
        """Strip transparent cast/paren wrappers (mirrors reaching_def._peel)."""
        if d > 12:
            return nid
        if self.sub.kind(nid) in _CASTS:
            ch = self.sub.ast_children.get(nid, [])
            if ch:
                return self._peel(ch[0], d + 1)
        return nid

    def _is_param(self, nid):
        return self.sub.kind(nid) in ("ParmVarDecl", "VarDecl")

    def reaches(self, sink: str, sources: Set[str], budget: int = 200000) -> Optional[List[str]]:
        """Backward context-sensitive search: does taint from any `source` reach `sink`?

        Returns a witness node path (source..sink) or None. call_site_stack gives context
        sensitivity: when we cross from a param up to a caller's argument we PUSH the call site,
        and we only cross back down through the matching call (pop), bounded by MAX_CALL_DEPTH.
        """
        sources = set(sources)
        # state = (node, call_stack_tuple, depth); visited on (node, call_stack)
        start = (sink, (), 0)
        # seed `seen` with the start key: otherwise the sink can be rediscovered as a
        # neighbour (e.g. an arg descending back to its own param with an emptied stack)
        # and re-parented, which OVERWRITES its None sentinel and forms a parent cycle
        # that makes _witness loop forever (budget only guards the search loop, not _witness).
        seen: Set[Tuple[str, tuple]] = {(sink, ())}
        # store parent for witness reconstruction
        parent: Dict[Tuple[str, tuple], Optional[Tuple[str, tuple]]] = {(sink, ()): None}
        dq = deque([start])
        while dq and budget > 0:
            budget -= 1
            node, stack, depth = dq.popleft()
            if node in sources:
                return self._witness(parent, (node, stack))

            nxts: List[Tuple[str, tuple, int]] = []
            # (a) intra-procedural: backward REACHING_DEF edges
            for d in self.rd_back.get(node, ()):
                nxts.append((d, stack, depth))
            # (b) reached a parameter -> cross to callers (bind param -> arg), PUSH call site
            if self._is_param(node) and depth < MAX_CALL_DEPTH:
                for arg in self.arg_of_param.get(node, ()):
                    call = self._call_of_arg(arg)
                    nstack = stack + ((call,) if call else ())
                    nxts.append((arg, nstack, depth + 1))
            # (c) reached a call argument that binds a callee param -> descend into callee,
            #     but only if it is context-consistent (matching call on stack top) OR no context
            #     (call-site match). We descend param<-arg backward here.
            for param in self.param_of_arg.get(node, ()):
                # descending: if stack top is this call, POP (return to caller context)
                call = self._call_of_arg(node)
                if stack and call is not None and stack[-1] == call:
                    nstack = stack[:-1]
                    nxts.append((param, nstack, depth))
                elif not stack and depth < MAX_CALL_DEPTH:
                    nxts.append((param, stack, depth + 1))

            for nn, nstk, ndep in nxts:
                key = (nn, nstk)
                if key in seen:
                    continue
                seen.add(key)
                parent[key] = (node, stack)
                dq.append((nn, nstk, ndep))
        return None

    def _call_of_arg(self, arg) -> Optional[str]:
        """The call expression that `arg` is an argument of (nearest CallExpr ancestor)."""
        cur = self.sub.ast_parent.get(arg)
        d = 0
        while cur is not None and d < 20:
            if self.sub.kind(cur) in ("CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"):
                return cur
            cur = self.sub.ast_parent.get(cur)
            d += 1
        return None

    @staticmethod
    def _witness(parent, end_key):
        path = []
        k = end_key
        guard = set()          # defensive: never traverse a parent cycle
        while k is not None and k not in guard:
            guard.add(k)
            path.append(k[0])
            k = parent.get(k)
        path.reverse()
        return path
