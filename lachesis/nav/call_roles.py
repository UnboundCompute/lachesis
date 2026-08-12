#!/usr/bin/env python3
"""Fix 4 — derive a security *role* for each CALLS edge (the base graph has none).

`CALLS` carries `callsite`/`relationship_class` only — no security role — so
"this function is missing a verify/authz call" can today only be answered by
name-spotting. This module *types* each call from the callee's shape so the
question becomes a graph query:

    role ∈ { verify | sanitize | authz | validate | none }

Derivation is two-signal and generic:
  * **name** — the callee label, categorized through the same security lexicon the
    detectors already use (`graphlib.security_weight`), split into role buckets by
    generic security verbs (verif/hmac/sign → verify; sanit/escape → sanitize;
    authoriz/permission/scope/tenant → authz; valid/assert/check/guard → validate).
  * **shape** — the callee's own `guard_signal` (Fix 2): a call into a function that
    is itself a `guard`/`validate` gets at least a `validate` role even when its
    name is neutral, so a renamed/obfuscated guard is still typed.

The stronger of the two wins; `fact_origin` records which signal fired so the role
is auditable. No vendor/interface literal appears — only generic security verbs and
derived guard-shape.

Materialization (`--build-overlay`): writes guard_signal (Fix 2) to node_props,
role onto each CALLS edge (edge_props), and a first-class **GUARDED** edge from a
function to every guard-family call it makes — so "what guards this function" is a
one-hop query and the previously-empty GUARDED relation is populated.

  python3 nav/call_roles.py graph.kuzu --fn <function-id|name>
  python3 nav/call_roles.py graph.kuzu --build-overlay
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.nav.graph_store import GraphStore
from lachesis.nav.guards import GuardProfiles
from lachesis.nav.overlay import Overlay, sidecar_path

# Ordered by specificity; first match wins. Generic security verbs only — the same
# vocabulary as graphlib's lexicon, bucketed into roles. Not a target allowlist.
ROLE_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("verify", re.compile(r"verif|hmac|\bsign|signature|digest|\bhash\b", re.I)),
    ("sanitize", re.compile(r"sanit|escap|encod|\bstrip|\bclean|\bquote", re.I)),
    ("authz", re.compile(r"authoriz|permission|permit|forbid|\bdeny|\ballow"
                         r"|\bscope|tenant|\bowner\b|\brole|entitl|\bacl\b", re.I)),
    ("validate", re.compile(r"valid|assert|\bcheck|guard|\btoken|trust|origin"
                            r"|\bcred|secret|\bauth", re.I)),
)
GUARD_FAMILY_ROLES = frozenset({"verify", "sanitize", "authz", "validate"})


def role_from_name(name: str) -> str | None:
    for role, pat in ROLE_PATTERNS:
        if pat.search(name or ""):
            return role
    return None


class CallRoles:
    """Types the outgoing CALLS of a function, name + callee guard-shape."""

    def __init__(self, store: GraphStore, guards: GuardProfiles | None = None) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index
        self.guards = guards or GuardProfiles(store)

    def _role(self, callee: dict) -> tuple[str, str]:
        """(role, fact_origin) for a callee node."""
        name_role = role_from_name(self.gl.label(callee))
        if name_role:
            return name_role, "call-role/name"
        # shape fallback: a call into a function that is itself a guard/validate
        prof = self.guards.profile(callee["id"])
        if prof["class"] in ("guard", "validate"):
            return "validate", "call-role/callee-shape"
        return "none", "call-role/none"

    def roles_for(self, fn_id: str) -> list[dict]:
        """Each outgoing CALLS of `fn_id`, typed. Uses the raw CALLS edges so the
        edge identity is available for overlay `edge_props` materialization."""
        out: list[dict] = []
        for edge in self.index.outgoing_of_kind(fn_id, "CALLS"):
            callee = self.gl.nodes.get(edge.get("target"))
            if not callee:
                continue
            role, origin = self._role(callee)
            f, l, _ = self.gl.loc(callee)
            out.append({
                "edge": edge, "callee_id": callee["id"],
                "callee": self.gl.label(callee), "role": role,
                "fact_origin": origin, "file": f, "line": l,
            })
        return out

    def build_overlay(self, overlay: Overlay) -> dict:
        """Write guard_signal + call roles + GUARDED edges into the sidecar."""
        # Fix 2 signals first (so a callee's guard_signal is also queryable).
        signals = self.guards.write_signals(overlay)
        typed = guarded = 0
        callers = {e.get("source") for e in self.index.edges_of_kind("CALLS")}
        for fn_id in callers:
            if fn_id is None:
                continue
            for rec in self.roles_for(fn_id):
                overlay.set_edge_prop(rec["edge"], "role", rec["role"])
                typed += 1
                if rec["role"] in GUARD_FAMILY_ROLES:
                    overlay.add_derived_edge(
                        fn_id, rec["callee_id"], "GUARDED",
                        {"role": rec["role"], "reason": "guard-family call",
                         "fact_origin": rec["fact_origin"],
                         "confidence": "medium"})
                    guarded += 1
        return {"guard_signals": signals, "calls_typed": typed,
                "guarded_edges": guarded}


def _resolve_fn(store: GraphStore, token: str) -> str | None:
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fix 4 — CALLS security roles")
    p.add_argument("graph")
    p.add_argument("--overlay", help="override sidecar overlay path")
    p.add_argument("--fn", metavar="ID|NAME", help="type the outgoing calls of a function")
    p.add_argument("--build-overlay", action="store_true",
                   help="write guard_signal + CALLS roles + GUARDED edges to the sidecar")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph, overlay_path=args.overlay)
    store.ensure_dataflow_tier()  # a core-only store grows its overlay tier here
    cr = CallRoles(store)
    if args.build_overlay:
        overlay = store.overlay
        overlay.source = Path(args.graph).name
        stats = cr.build_overlay(overlay)
        path = Path(args.overlay) if args.overlay else sidecar_path(args.graph)
        overlay.write(path)
        print(json.dumps({"wrote": str(path), **stats, **overlay.summary()},
                         indent=2, ensure_ascii=False), file=sys.stderr)
        return 0
    if args.fn:
        fn = _resolve_fn(store, args.fn)
        if not fn:
            print(f"no function for {args.fn!r}", file=sys.stderr); return 2
        recs = cr.roles_for(fn)
        out = [{"callee": r["callee"], "role": r["role"],
                "fact_origin": r["fact_origin"],
                "at": f"{r['file']}:{r['line']}"} for r in recs]
        print(json.dumps({"function": store.gl.label(store.node(fn)),
                          "calls": out}, indent=2, ensure_ascii=False))
        return 0
    print("need --fn or --build-overlay", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
