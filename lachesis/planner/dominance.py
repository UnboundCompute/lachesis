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

**2. Call-path presence is an over-approximation of dominance, so it is checked
inside the host.** A guard that appears on the call chain can still be skipped by a
branch that routes around it. Structured JavaScript makes that decidable without a
dominator tree: the frontend already marks every conditionally executed region
(``TRUE_BRANCH``, ``FALSE_BRANCH``, ``LOOP_TRUE``, ``SWITCH_CASE``,
``EXCEPTION_BRANCH``, ``SHORT_CIRCUIT_RIGHT``), so a guard call dominates the step
that carries execution onward iff every such region containing the guard also
contains that step, and the guard comes first. Three answers, never two:

  * *dominates* — the suppression stands and the verdict is ``DETERMINISTIC``.
  * *skippable* — a region holds the guard and not the effect, so a caller can take
    the other branch. The suppression is **withdrawn**: the capsule goes back on the
    queue as ``UNPROVEN`` with the region named. Proving a guard skippable is as
    much a result as proving it dominant, and keeping such a capsule suppressed is
    exactly the missed bug this layer exists to avoid.
  * *undecided* — a guard one call hop away from the step it should dominate, a node
    with no offsets, a region kind not recognized. The suppression stands and the
    verdict stays ``PARTIAL``, which is the accurate state of the evidence.

The comparison is intra-procedural by construction: it relates a guard to the next
step *inside the same function*, either the call that continues toward the effect or
the effect's own call site. A guard whose host is not the one performing the step is
undecided, never assumed.

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

from lachesis.nav.graph_store import GraphStore
from lachesis.nav import symbol_index as si
from lachesis.planner.entrypoints import EntryPoints
from lachesis.planner.guard_recognition import GuardSet

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

# Edge kinds whose *target* is a region that only executes under a condition. A try
# body is deliberately absent: it always runs, so a guard inside one is not skippable
# by taking another branch. `SHORT_CIRCUIT_RIGHT` is here because the right operand of
# `a && guard(x)` runs only when the left one allows it.
CONDITIONAL_REGION_EDGES = ("TRUE_BRANCH", "FALSE_BRANCH", "LOOP_TRUE",
                            "SWITCH_CASE", "EXCEPTION_BRANCH", "SHORT_CIRCUIT_RIGHT")

DOMINATES = "dominates"
SKIPPABLE = "skippable"
UNDECIDED = "undecided"


def _span(node: dict | None) -> tuple[str, int, int] | None:
    """(file, start_offset, end_offset), or None when the node carries no span."""
    props = (node or {}).get("properties") or {}
    path = props.get("absolute_file")
    start, end = props.get("start_offset"), props.get("end_offset")
    if not path or start is None or end is None:
        return None
    return path, start, end


class ConditionalRegions:
    """Which conditionally executed regions of a function contain a given node.

    Containment is decided from source spans rather than by walking the AST: the
    regions are whole statements or expressions with byte offsets, and a call is in a
    region exactly when its offsets are inside the region's. Regions are narrowed to
    the host function first, so the comparison stays proportional to one function's
    size and not to the file's."""

    def __init__(self, store: GraphStore) -> None:
        self.gl = store.gl
        self.index = store.index
        self._by_file: dict[str, list[tuple[int, int, str]]] | None = None
        self._in_host: dict[str, tuple[tuple[int, int, str], ...]] = {}

    def _regions(self) -> dict[str, list[tuple[int, int, str]]]:
        if self._by_file is None:
            found: dict[str, dict[str, tuple[int, int, str]]] = {}
            for edge in self.index.edges_of_kind(*CONDITIONAL_REGION_EDGES):
                region = self.gl.nodes.get(edge.get("target"))
                span = _span(region)
                if span is None:
                    continue
                path, start, end = span
                found.setdefault(path, {})[region["id"]] = (start, end, region["id"])
            self._by_file = {path: sorted(rows.values())
                             for path, rows in found.items()}
        return self._by_file

    def in_host(self, host_id: str) -> tuple[tuple[int, int, str], ...]:
        """The conditional regions that lie inside one function's own span."""
        cached = self._in_host.get(host_id)
        if cached is None:
            span = _span(self.gl.nodes.get(host_id))
            if span is None:
                cached = ()
            else:
                path, start, end = span
                cached = tuple((s, e, rid) for s, e, rid
                               in self._regions().get(path, ())
                               if s >= start and e <= end)
            self._in_host[host_id] = cached
        return cached

    def enclosing(self, host_id: str, span: tuple[str, int, int]) -> frozenset[str]:
        _, start, end = span
        return frozenset(rid for s, e, rid in self.in_host(host_id)
                         if s <= start and end <= e)

    def relation(self, host_id: str, guard: tuple | None,
                 step: tuple | None) -> tuple[str, str | None]:
        """How a guard call relates to the step that carries execution onward.

        The second element is the phrase that explains a withdrawal, so the capsule
        can say which region or which ordering makes the guard skippable."""
        if guard is None or step is None or guard[0] != step[0]:
            return UNDECIDED, None
        around = self.enclosing(host_id, guard) - self.enclosing(host_id, step)
        if around:
            region = self.gl.nodes.get(sorted(around)[0])
            label = self.gl.label(region).splitlines()[0][:60] if region else "a branch"
            return SKIPPABLE, f"only inside a conditional region ({label}) that the " \
                              f"effect is not in"
        if guard[1] < step[1]:
            return DOMINATES, None
        # Order is the other half of dominance. A guard that runs after the effect
        # protects nothing on this pass, so the suppression is withdrawn rather
        # than left standing.
        return SKIPPABLE, "after the effect it would have to protect"


def _skippable_note(guard: dict, why: str | None) -> str:
    where = why or "where it cannot protect the effect"
    return (f"{guard['guard_name']} is called {where} in {guard.get('host_name')}, "
            f"so execution can reach the effect without it")


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
        self.regions = ConditionalRegions(store)
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

    # -- A2: dominance inside the host ---------------------------------------

    def _next_step_sites(self, host_id: str, chain: list[str], effect_fn_id: str,
                         effect_site_id: str | None) -> list[str]:
        """The call sites in ``host_id`` that carry execution on toward the effect.

        Either the effect's own call site, when the host is the function performing
        it, or every call in the host to the next function on the witness chain. All
        of them, because a guard that dominates one of two calls to the same callee
        does not dominate the effect."""
        if host_id == effect_fn_id:
            return [effect_site_id] if effect_site_id else []
        try:
            following = chain[chain.index(host_id) + 1]
        except (ValueError, IndexError):
            return []
        return list(self.guard_set.branch_use.call_sites(host_id).get(following, ()))

    def _dominance_in_host(self, guard: dict, chain: list[str], effect_fn_id: str,
                           effect_site_id: str | None) -> tuple[str, str | None]:
        """Does this guard dominate the step onward, inside the host that calls it?"""
        host_id = guard["host_id"]
        steps = self._next_step_sites(host_id, chain, effect_fn_id, effect_site_id)
        sites = self.guard_set.branch_use.call_sites(host_id).get(
            guard["guard_id"], ())
        if not steps or not sites:
            return UNDECIDED, None
        node = self.gl.nodes.get
        answers: list[tuple[str, str | None]] = []
        for step in steps:
            step_span = _span(node(step))
            best: tuple[str, str | None] = (UNDECIDED, None)
            for site in sites:
                answer = self.regions.relation(host_id, _span(node(site)), step_span)
                if answer[0] == DOMINATES:
                    best = answer
                    break
                if answer[0] == SKIPPABLE and best[0] == UNDECIDED:
                    best = answer
            answers.append(best)
        if all(a[0] == DOMINATES for a in answers):
            return DOMINATES, None
        skipped = [a for a in answers if a[0] == SKIPPABLE]
        if skipped and len(skipped) + sum(a[0] == DOMINATES for a in answers) \
                == len(answers):
            return SKIPPABLE, skipped[0][1]
        return UNDECIDED, None

    # -- the verdict ---------------------------------------------------------

    def verdict(self, entry_id: str, effect_fn_id: str, depth: int = CALL_DEPTH,
                budget: int = CLOSURE_BUDGET,
                effect_site_id: str | None = None) -> dict:
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

        # A guard on the call path can still be branched around inside the function
        # that calls it, so each one is asked whether it dominates the step onward.
        decided = [(g, *self._dominance_in_host(g, chain, effect_fn_id,
                                                effect_site_id))
                   for g in found]
        dominating = [g for g, answer, _ in decided if answer == DOMINATES]
        if dominating:
            names = ", ".join(sorted({g["guard_name"] for g in dominating}))
            return self._result(
                STATE_PRESERVED, COMPLETENESS_DETERMINISTIC, dominating,
                f"authorization guard(s) that dominate the effect inside the "
                f"function calling them: {names}",
                closure, chain,
                others + [g for g, answer, _ in decided if answer != DOMINATES])

        skippable = [(g, region) for g, answer, region in decided
                     if answer == SKIPPABLE]
        if len(skippable) == len(decided):
            # Every recognized guard on the path can be branched around. That is a
            # proof, and it points the other way: the suppression is withdrawn and
            # the capsule goes back on the queue naming the region that skips it.
            withdrawn = [{**g, "note": _skippable_note(g, region)}
                         for g, region in skippable]
            names = ", ".join(sorted({g["guard_name"] for g, _ in skippable}))
            completeness = (COMPLETENESS_OPAQUE if closure.exhausted
                            else COMPLETENESS_DETERMINISTIC)
            return self._result(
                STATE_UNPROVEN, completeness, [],
                f"the only authorization guard(s) on the path can be branched "
                f"around inside the function calling them: {names}",
                closure, chain, others + withdrawn)

        names = ", ".join(sorted({g["guard_name"] for g in found}))
        return self._result(
            STATE_PRESERVED, COMPLETENESS_PARTIAL, found,
            f"authorization guard(s) on the call path from the entrypoint to the "
            f"effect: {names}; whether they dominate every branch inside their host "
            f"is not decided",
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
