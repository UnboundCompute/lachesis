#!/usr/bin/env python3
"""Named edges — a generic display-verb map for the navigation layer.

Every edge an agent walks in the nav graph should read like a sentence:
"file *imports* file", "function *calls* function", "folder *contains* file".
This module is the single place that turns a canonical edge kind (plus role /
`via` refinement) into a human verb. It is pure lookup over **schema kind
strings only** — no target/package/vendor literal ever appears here, so the map
works for any graph the frontends emit.

`display_name(edge)` is what the L0/L1 builders and `render_graph.py` call to
label an edge; `verb(kind, ...)` is the lower-level lookup.
"""
from __future__ import annotations

# canonical edge kind -> human display verb.
_VERBS: dict[str, str] = {
    # containment / structure (L0)
    "CONTAINS": "contains",
    "DECLARES": "declares",
    "DECLARES_MEMBER": "declares",
    "DECLARES_SYMBOL": "declares",
    "SYMBOL_DECLARES": "declares",
    "PACKAGE_CONTAINS": "contains",
    # imports / module graph (L1)
    "DEPENDS_ON": "imports",
    "RUNTIME_DEPENDS_ON": "imports (runtime)",
    "RE_EXPORTS": "re-exports",
    "EXPORTS": "exports",
    "IMPORTS": "imports",
    # calls (L1)
    "CALLS": "calls",
    "INVOKES": "invokes",
    "MAY_INVOKE": "may invoke",
    "CONTEXT_CALLS": "calls",
    # control flow (L2 / body)
    "CFG_NEXT": "then",
    "TRUE_BRANCH": "if true",
    "FALSE_BRANCH": "if false",
    "CONDITION": "on",
    "LOOP_BACK": "loops back",
    "LOOP_TRUE": "loop while",
    "BREAKS_TO": "breaks to",
    "CONTINUES_TO": "continues to",
    "EXCEPTION_BRANCH": "on throw",
    "TRY_BODY": "tries",
    "ITERATES": "iterates",
    "PHI_AT": "merges at",
    "NARROWS_TYPE": "narrows",
    "REFINES_SYMBOL": "refines",
    # data flow (L3 / proof)
    "VALUE_FLOWS_TO": "flows to",
    "READS_FROM": "reads",
    "WRITES_TO": "writes",
    "DEFINES": "defines",
    "BRANCH_READS_FROM": "branch reads",
    "PREVIOUS_VERSION": "prior value",
    "PROPERTY_READ": "reads property",
    "NEXT_TOKEN": "next",
    # nav-layer synthetic edges (folder/file builders + jump-refs)
    "JUMP_REF": "jumps to",
    "AST_CHILD": "has",
}

# AST_CHILD role -> verb refinement (operands, arguments, etc.).
_ROLE_VERBS: dict[str, str] = {
    "LEFT_OPERAND": "left of",
    "RIGHT_OPERAND": "right of",
    "ARGUMENT": "arg",
    "CALLEE": "callee",
    "BODY": "body",
    "CONDITION": "condition",
}


def verb(kind: str | None, via: str | None = None, role: str | None = None) -> str:
    """Display verb for an edge kind, refined by `via` (EXPANDS_TO) or a role.

    EXPANDS_TO reifies a cross-tier structural edge, preserving the original kind
    in `properties.via` — so resolve through `via` when present. Unknown kinds
    fall back to a lowercased, de-underscored form so nothing renders blank.
    """
    if kind == "EXPANDS_TO" and via:
        return _VERBS.get(via, _humanize(via))
    if kind == "AST_CHILD" and role and role in _ROLE_VERBS:
        return _ROLE_VERBS[role]
    if kind in _VERBS:
        return _VERBS[kind]
    return _humanize(kind)


def display_name(edge: dict) -> str:
    """Human verb for a canonical edge dict (reads its kind + properties)."""
    props = edge.get("properties") or {}
    return verb(edge.get("kind"), via=props.get("via"), role=props.get("role"))


def _humanize(kind: str | None) -> str:
    return (kind or "").lower().replace("_", " ") or "->"
