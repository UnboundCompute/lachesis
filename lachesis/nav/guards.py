#!/usr/bin/env python3
"""Fix 2 — derive a per-function guard profile (`guard_signal` = 0 in the base graph).

`guard_signal` is genuinely unpopulated (probed: 0 nodes, 0 edges). But the shapes
that *make* a function a guard are all present and attributable: a function owns
`CONDITION` edges (branch/validation density), `SHORT_CIRCUIT_LEFT/RIGHT` (fail-open
`x && y` / `x || throw` defensiveness), `THROWS_VALUE` (validate-and-throw),
`EXCEPTION_BRANCH`/`TRY_BODY`/`HANDLED_BY` (swallow vs handle). Guard edges anchor to
a function through their endpoints' `owner_function_id`, so one pass over the guard
edges buckets the whole codebase by owning function.

The output is an **explainable** signal — every raw component is exposed next to the
score and the class — not a magic number:

    guard_signal = {
      "score": 0.0..1.0,        # ranking aid (structural density × security weight)
      "class": "guard"|"validate"|"passthrough",
      "conditions","short_circuits","throws","exception_branches","handles": int,
      "security_weight": 0.0|0.6|1.0,   # generic lexicon, callee names only
      "owned": int,             # function size, so density isn't fooled by big fns
    }

Nothing here is target-specific: counts come from graph structure and the score's
security term reuses `graphlib.security_weight` (the blessed generic lexicon).

  python3 nav/guards.py graph.kuzu --fn <function-id|name>
  python3 nav/guards.py graph.kuzu --top 20        # most guard-shaped functions
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.nav.graphlib import security_weight
from lachesis.nav.graph_store import GraphStore

# guard-shaped edge kinds, grouped by the signal they carry.
CONDITION_KINDS = ("CONDITION",)
SHORT_CIRCUIT_KINDS = ("SHORT_CIRCUIT_LEFT", "SHORT_CIRCUIT_RIGHT")
THROW_KINDS = ("THROWS_VALUE",)
EXCEPTION_KINDS = ("EXCEPTION_BRANCH",)
HANDLE_KINDS = ("TRY_BODY", "HANDLED_BY")
ALL_GUARD_KINDS = (CONDITION_KINDS + SHORT_CIRCUIT_KINDS + THROW_KINDS
                   + EXCEPTION_KINDS + HANDLE_KINDS)


class GuardProfiles:
    """Per-function guard profiles, computed in one edge pass over the graph."""

    def __init__(self, store: GraphStore) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index
        self._owner_cache: dict[str, str | None] = {}
        self._counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int))
        self._built = False

    # -- attribution ---------------------------------------------------------

    def _owner_id(self, node_id: str) -> str | None:
        """The function that owns a node (owner_function_id, climbing if needed)."""
        if node_id in self._owner_cache:
            return self._owner_cache[node_id]
        node = self.gl.nodes.get(node_id)
        owner_id = None
        if node is not None:
            owner = self.gl.owner_function(node)
            owner_id = owner["id"] if owner else None
        self._owner_cache[node_id] = owner_id
        return owner_id

    def _build(self) -> None:
        if self._built:
            return
        for kind in ALL_GUARD_KINDS:
            for edge in self.index.edges_of_kind(kind):
                # attribute to the owner of the source (the statement/expression);
                # fall back to the target so an edge is never dropped.
                owner = self._owner_id(edge.get("source")) or self._owner_id(edge.get("target"))
                if owner:
                    self._counts[owner][kind] += 1
        self._built = True

    # -- profile -------------------------------------------------------------

    def _security_weight(self, fn_id: str) -> float:
        best = 0.0
        for callee in self.gl.calls_from(fn_id):
            best = max(best, security_weight(self.gl.label(callee)))
            if best >= 1.0:
                break
        return best

    def profile(self, fn_id: str) -> dict:
        self._build()
        c = self._counts.get(fn_id, {})
        conditions = c.get("CONDITION", 0)
        short_circuits = sum(c.get(k, 0) for k in SHORT_CIRCUIT_KINDS)
        throws = c.get("THROWS_VALUE", 0)
        exceptions = c.get("EXCEPTION_BRANCH", 0)
        handles = sum(c.get(k, 0) for k in HANDLE_KINDS)
        owned = len(self.index.nodes_owned_by(fn_id))
        sec = self._security_weight(fn_id)

        # structural guard events, weighted by how strongly each shape guards.
        events = (0.15 * conditions + 0.2 * short_circuits + 0.3 * throws
                  + 0.1 * exceptions)
        # amplify (never gate) by how security-relevant the function's callees look.
        score = min(1.0, events) * (0.5 + 0.5 * sec)

        if throws and (conditions or short_circuits):
            cls = "guard"          # validate-and-throw: the strongest guard shape
        elif conditions or short_circuits:
            cls = "validate"       # branches on something, but doesn't hard-stop
        else:
            cls = "passthrough"    # no guard structure of its own

        return {
            "score": round(score, 3),
            "class": cls,
            "conditions": conditions,
            "short_circuits": short_circuits,
            "throws": throws,
            "exception_branches": exceptions,
            "handles": handles,
            "security_weight": sec,
            "owned": owned,
        }

    def functions(self) -> list[str]:
        """Function ids that own at least one guard edge."""
        self._build()
        return list(self._counts)

    def top(self, n: int = 20) -> list[dict]:
        """The N most guard-shaped functions, each with an addressable handle.

        This is the cold-start entry point: a ranked list needs no prior name
        knowledge, and every row carries `node_id` + `handle` (file:line) so even
        an anonymous high-signal function (`<anonymous@N>`) can be navigated to."""
        self._build()
        rows = []
        for fn_id in self.functions():
            node = self.gl.nodes.get(fn_id)
            if node is None:
                continue
            f, l, _ = self.gl.loc(node)
            rows.append({
                "node_id": fn_id,
                "name": self.gl.label(node),
                "handle": f"{f}:{l}" if f and l else None,
                "guard_signal": self.profile(fn_id),
            })
        rows.sort(key=lambda r: r["guard_signal"]["score"], reverse=True)
        return rows[:n]

    def write_signals(self, overlay) -> int:
        """Materialize guard_signal onto every guard-bearing function (node_props)."""
        n = 0
        for fn_id in self.functions():
            overlay.set_node_prop(fn_id, "guard_signal", self.profile(fn_id))
            n += 1
        return n


def _resolve_fn(store: GraphStore, token: str) -> str | None:
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fix 2 — per-function guard profile")
    p.add_argument("graph")
    p.add_argument("--overlay", help="override sidecar overlay path")
    p.add_argument("--fn", metavar="ID|NAME", help="guard profile for one function")
    p.add_argument("--top", type=int, metavar="N", help="N most guard-shaped functions")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph, overlay_path=args.overlay)
    store.ensure_dataflow_tier()  # a core-only store grows its overlay tier here
    gp = GuardProfiles(store)
    if args.fn:
        fn = _resolve_fn(store, args.fn)
        if not fn:
            print(f"no function for {args.fn!r}", file=sys.stderr); return 2
        prof = gp.profile(fn)
        print(json.dumps({"function": fn, "name": store.gl.label(store.node(fn)),
                          "guard_signal": prof}, indent=2, ensure_ascii=False))
        return 0
    for row in gp.top(args.top or 20):
        prof = row["guard_signal"]
        print(f"{prof['score']:.3f} {prof['class']:11} {row['name']:32} "
              f"c={prof['conditions']} sc={prof['short_circuits']} thr={prof['throws']} "
              f"sec={prof['security_weight']}  {row['handle'] or '?'}  {row['node_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
