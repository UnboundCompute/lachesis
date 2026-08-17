"""Field-sensitive dataflow — a clean-room field-sensitive tainter algorithm.

Three ingredients, each graph-agnostic over a `Substrate` adapter:

  1. access-path algebra (`access_path`, `ap_construct`) — the exact-match `matchAndDiff`
     state machine that decides whether a def of one access path reaches a use of another.
  2. intraprocedural reaching-def (`reaching_def`) — gen/kill over a CFG synthesized from the
     AST, producing field-sensitive def->use edges.
  3. interprocedural context-sensitive solver (`interproc_solver`) — backward reachability over
     the reaching-def edges + argument/parameter binds, with a call-site stack (k-bounded) and a
     minimal flow-semantics table for well-known library calls.

The algorithms are implemented from their described behaviour (no code vendored). This
package is the *reader*: it turns source into field-precise dataflow. The tuned
flow-semantics catalog and any adjudication/triage tuning live outside it.
"""
from __future__ import annotations

from .access_path import (
    Elem, Const, Var, VPS, Ind, Addr, Shift,
    normalize, inverted, concat, match_and_diff,
    NO_MATCH, EXACT, VAR_EXACT, PREFIX, VAR_PREFIX, EXTENDED, VAR_EXTENDED,
)
from .ap_construct import APBuilder

__all__ = [
    "Elem", "Const", "Var", "VPS", "Ind", "Addr", "Shift",
    "normalize", "inverted", "concat", "match_and_diff",
    "NO_MATCH", "EXACT", "VAR_EXACT", "PREFIX", "VAR_PREFIX", "EXTENDED", "VAR_EXTENDED",
    "APBuilder",
]
