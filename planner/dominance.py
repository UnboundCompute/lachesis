#!/usr/bin/env python3
"""A1 — call-path dominance: can a guard be proven present between entry and effect?

This is the primitive that converts a wandering lead into a closed verdict. Given an
entrypoint and the function that performs a sensitive effect, it walks the call
closure from the entrypoint, finds the witness path to the effect, and asks the
guard-recognition layer whether any function *on that path* guards.

Three honesty rules are encoded here, not just documented:

**1. Only two static outcomes exist.** ``PROVEN_PRESERVED`` (a guard is on the path,
so the candidate is suppressed and the guard is named) and ``UNPROVEN`` (it is not,
so the candidate is queued with its evidence). ``PROVEN_VIOLATED`` is never produced
by static analysis and this module cannot emit it.

**2. Call-path presence is an over-approximation of dominance.** A guard that appears
on the call chain can still be skipped by a branch that routes around it. True
dominance needs the intra-procedural CFG and a dominator tree per function (A2, the
next step); until then a verdict whose guard sits in a branching function is labelled
``PARTIAL``, and only a guard reached through straight-line code is
``DETERMINISTIC``. On real code ``PARTIAL`` is the common answer, which is the
accurate state of the evidence rather than a defect in the label.

**3. Exhaustion never suppresses.** If the closure hits its depth or node budget, the
verdict is ``UNPROVEN`` with completeness ``OPAQUE``. A search that ran out of room
has not proven anything, and turning "I stopped looking" into "it is guarded" is the
one failure this layer must never have.

  python3 planner/dominance.py graph.kuzu --entry <handler> --effect <function>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nav.graph_store import GraphStore
from nav import symbol_index as si
from planner.entrypoints import EntryPoints
from planner.guard_recognition import GuardSet

# How deep a call closure goes before it stops. Six hops is what the POC needed to
# reach an effect from a registered handler through the usual wrapper/service/model
# layering; beyond that the closure stops describing "this entrypoint" and starts
# describing the whole application.
CALL_DEPTH = 6
# How many declarations one closure may visit. A hub function fans out to thousands
# of callees, and an unbounded closure from a single entrypoint would walk most of a
# large tree. Hitting this is reported as OPAQUE, never as an answer.
CLOSURE_BUDGET = 4000

STATE_PRESERVED = "PROVEN_PRESERVED"
STATE_UNPROVEN = "UNPROVEN"

COMPLETENESS_DETERMINISTIC = "DETERMINISTIC"
COMPLETENESS_PARTIAL = "PARTIAL"
COMPLETENESS_OPAQUE = "OPAQUE"


class Closure:
    """The call closure of one entrypoint, with the parent links to rebuild paths."""

    __slots__ = ("entry_id", "depth_of", "parent", "exhausted", "max_depth")

    def __init__(self, entry_id: str) -> None:
        self.entry_id = entry_id
        self.depth_of: dict[str, int] = {entry_id: 0}
        self.parent: dict[str, tuple[str, dict]] = {}
        self.exhausted = False
        self.max_depth = 0

    def __contains__(self, node_id: str) -> bool:
        return node_id in self.depth_of

    def path_to(self, node_id: str) -> list[str]:
        """The witness call chain entry -> ... -> node_id (empty if unreached)."""
        if node_id not in self.depth_of:
            return []
        chain = [node_id]
        current = node_id
        while current != self.entry_id:
            parent = self.parent.get(current)
            if parent is None:
                break
            current = parent[0]
            chain.append(current)
        chain.reverse()
        return chain

    def summary(self) -> dict:
        return {"visited": len(self.depth_of), "max_depth": self.max_depth,
                "exhausted": self.exhausted}


class Dominance:
    """Call-path dominance over the resolved call graph, guards included."""

    def __init__(self, store: GraphStore, guard_set: GuardSet | None = None,
                 entry_points: EntryPoints | None = None) -> None:
        self.store = store
        self.gl = store.gl
        self.entry_points = entry_points or EntryPoints(store)
        self.guard_set = guard_set or GuardSet(store, entry_points=self.entry_points)
        self._closures: dict[tuple[str, int], Closure] = {}
        self._guards: dict[str, list[dict]] = {}
        self._callees: dict[str, tuple[dict, ...]] = {}

    # -- the call graph ------------------------------------------------------

    def callees_of(self, fn_id: str) -> tuple[dict, ...]:
        """``symbol_index.callees``, memoized for the life of this object.

        Closures from thousands of entrypoints converge on the same utility and
        service functions, so without the memo the same expansion is paid once per
        entrypoint that reaches it. This is a per-run cache only: nothing is written
        to disk, and a rebuilt store starts cold."""
        cached = self._callees.get(fn_id)
        if cached is None:
            cached = tuple(si.callees(self.gl, fn_id))
            self._callees[fn_id] = cached
        return cached

    # -- the closure ---------------------------------------------------------

    def call_closure(self, entry_id: str, depth: int = CALL_DEPTH,
                     budget: int = CLOSURE_BUDGET) -> Closure:
        """Breadth-first over ``symbol_index.callees``, cycle-safe and budgeted.

        Callees rather than raw ``CALLS`` edges, so a callee reached only through
        dispatch is in the closure. Recursion is handled by the visited set, and the
        budget is a *stop*, not a filter: when it trips, ``exhausted`` is set and
        every verdict built on this closure degrades to OPAQUE."""
        cached = self._closures.get((entry_id, depth))
        if cached is not None:
            return cached
        closure = Closure(entry_id)
        frontier = [entry_id]
        for level in range(depth):
            nxt: list[str] = []
            for current in frontier:
                for callee in self.callees_of(current):
                    callee_id = callee["node_id"]
                    if callee_id in closure.depth_of:
                        continue
                    if len(closure.depth_of) >= budget:
                        closure.exhausted = True
                        self._closures[(entry_id, depth)] = closure
                        return closure
                    closure.depth_of[callee_id] = level + 1
                    closure.parent[callee_id] = (current, callee)
                    closure.max_depth = max(closure.max_depth, level + 1)
                    nxt.append(callee_id)
            frontier = nxt
            if not frontier:
                break
        self._closures[(entry_id, depth)] = closure
        return closure

    # -- guards on a path ----------------------------------------------------

    def _recognitions_on(self, fn_id: str) -> list[dict]:
        """Every guard recognition hosted by one function (memoized).

        Declarative recognitions are absent by construction: they are recognized on
        a registration, not on a function."""
        cached = self._guards.get(fn_id)
        if cached is None:
            cached = [{**g, "host_id": fn_id,
                       "host_name": self.gl.label(self.gl.nodes.get(fn_id) or {})}
                      for g in self.guard_set.for_function(fn_id)]
            self._guards[fn_id] = cached
        return cached

    def _guards_on(self, fn_id: str) -> list[dict]:
        """Only the recognitions allowed to answer an authorization question."""
        return [g for g in self._recognitions_on(fn_id) if g.get("can_suppress")]

    def _branches(self, fn_id: str) -> bool:
        profile = self.guard_set.guards.profile(fn_id)
        return bool(profile["conditions"] or profile["short_circuits"])

    # -- the verdict ---------------------------------------------------------

    def verdict(self, entry_id: str, effect_fn_id: str, depth: int = CALL_DEPTH,
                budget: int = CLOSURE_BUDGET) -> dict:
        """Is a guard provably present between ``entry_id`` and ``effect_fn_id``?

        Returns the state, the completeness label that qualifies it, the guards that
        justified a suppression (named, with the function that hosts each), and the
        witness call path in the shared ``path_shape`` envelope."""
        closure = self.call_closure(entry_id, depth=depth, budget=budget)
        chain = closure.path_to(effect_fn_id)
        if not chain:
            reason = ("the call closure hit its budget before reaching the effect"
                      if closure.exhausted else
                      "the effect is not on the call closure of this entrypoint")
            return self._result(STATE_UNPROVEN, COMPLETENESS_OPAQUE, [], reason,
                                closure, [])

        found: list[dict] = []
        others: list[dict] = []
        for fn_id in chain:
            for recognition in self._recognitions_on(fn_id):
                (found if recognition.get("can_suppress") else others).append(
                    recognition)

        if not found:
            # Absence is the sound direction: if no function on the path guards, then
            # certainly none dominates. So a complete closure with no guard is
            # DETERMINISTIC even though the presence direction is only an
            # over-approximation. A truncated closure proves nothing either way.
            completeness = (COMPLETENESS_OPAQUE if closure.exhausted
                            else COMPLETENESS_DETERMINISTIC)
            reason = ("no authorization guard was recognized on any function of the "
                      "call path" if not closure.exhausted else
                      "no authorization guard was recognized, and the closure was "
                      "truncated")
            if others:
                reason += (f"; {len(others)} non-authorization guard(s) are present "
                           f"and do not answer the question")
            return self._result(STATE_UNPROVEN, completeness, [], reason,
                                closure, chain, others)

        # A guard reached through a branching function can be branched around, so the
        # strongest label its host allows is PARTIAL until CFG dominance (A2) lands.
        deterministic = any(not self._branches(g["host_id"]) for g in found)
        completeness = (COMPLETENESS_DETERMINISTIC if deterministic
                        else COMPLETENESS_PARTIAL)
        names = ", ".join(sorted({g["guard_name"] for g in found}))
        reason = (f"authorization guard(s) on the call path from the entrypoint to "
                  f"the effect: {names}")
        return self._result(STATE_PRESERVED, completeness, found, reason,
                            closure, chain, others)

    def _result(self, state: str, completeness: str, guards: list[dict],
                reason: str, closure: Closure, chain: list[str],
                others: list[dict] | None = None) -> dict:
        return {
            "state": state,
            "completeness": completeness,
            "provenance": "STATIC_PROVEN",
            "guards": guards,
            "other_guards": others or [],
            "reason": reason,
            "closure": closure.summary(),
            "witness": self._witness(closure, chain),
        }

    def _witness(self, closure: Closure, chain: list[str]) -> dict:
        edges = []
        for source, target in zip(chain, chain[1:]):
            call = closure.parent.get(target)
            row = call[1] if call else {}
            edges.append({
                "source": source, "target": target, "kind": "CALLS",
                "properties": {"via": row.get("via"),
                               "reason": "call-path dominance witness",
                               "confidence": "exact" if row.get("resolved")
                                             else "conservative",
                               "fact_origin": "call-graph"},
            })
        return self.store.path_shape(chain, edges)


def _resolve_fn(store: GraphStore, token: str) -> str | None:
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="A1 — call-path dominance")
    p.add_argument("graph")
    p.add_argument("--entry", metavar="ID|NAME", required=True)
    p.add_argument("--effect", metavar="ID|NAME", required=True,
                   help="the function that performs the sensitive effect")
    p.add_argument("--depth", type=int, default=CALL_DEPTH)
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph)
    store.ensure_dataflow_tier()
    entry = _resolve_fn(store, args.entry)
    effect = _resolve_fn(store, args.effect)
    if not entry or not effect:
        print("could not resolve --entry / --effect", file=sys.stderr)
        return 2
    result = Dominance(store).verdict(entry, effect)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
