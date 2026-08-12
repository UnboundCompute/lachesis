#!/usr/bin/env python3
"""B1 / C1 — GUARD_DIFFERENTIAL: manufacture candidates and suppress what is proven.

A constructor is a graph query pattern that states a **null hypothesis** and then
looks for its counterexample. This one is C1 from the catalog:

    Null hypothesis: every path from an entrypoint to a sensitive effect passes a
    guard, of some recognized kind, before the effect happens.

    Counterexample search: an (anchor, effect) pair for which no function on the
    call path carries a guard the recognition layer can name.

That is the whole constructor. What makes it usable rather than a noise generator is
what happens *after* a candidate is built: dominance runs, and a candidate whose
guard is proven present becomes a ``PROVEN_PRESERVED`` capsule with the guard named
and the host recorded, so a suppression is auditable and countable rather than a
silent drop. Only what survives that is queued.

The differential is what turns an absence into evidence. An unguarded function on
its own says little; an unguarded function whose *own siblings* all guard the same
effect says a great deal, and that peer rides along as ``cross_reference`` so the
consumer can read the two side by side. Family formation is delegated to
``nav.siblings``, unchanged and unmodified.

Three things this constructor deliberately does not do: it does not declare a
violation (see ``planner.capsule``), it does not let a declarative guard suppress
(its value is unreadable — see ``planner.guard_recognition``), and it does not treat
a truncated search as a clean one (an ``OPAQUE`` verdict stays on the queue).

  python3 planner/constructors.py graph.kuzu --limit 50
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nav.graph_store import GraphStore
from nav.siblings import SiblingDiff
from planner import capsule as cap
from planner.dominance import (CALL_DEPTH, COMPLETENESS_OPAQUE, Dominance,
                               STATE_PRESERVED)
from planner.entrypoints import EntryPoints
from planner.guard_recognition import GuardSet
from planner.rank import ranked

CONSTRUCTOR_ID = "GUARD_DIFFERENTIAL"

# Sink kinds this constructor treats as a sensitive effect. `response` is excluded:
# writing a response is what every handler does, so a guard differential over it
# would flag the whole application and say nothing. It stays in the graph and other
# constructors may want it; it is simply not a privileged effect.
SENSITIVE_SINK_KINDS = frozenset({
    "dynamic-code", "process", "deserialize", "database", "filesystem-write",
    "network", "filesystem-read",
})

# Who the claim is about, by how the entrypoint was anchored. Only a route is
# evidence that something outside the tree can call this; a callback handed to some
# call, or an export nothing in the tree calls, says a caller exists somewhere and
# does not say it is reachable by an attacker. Writing "external_caller" over all
# three would smuggle an unproven reachability claim into the subject line.
_SUBJECT = {
    "route": "external_caller",
    "callback-registration": "caller_of_this_registration",
    "exported-entry": "caller_outside_this_tree",
    "unanchored": "caller",
}
# The matching sentence a capsule carries so the consumer sees the same limit.
_REACHABILITY_GAP = {
    "callback-registration": (
        "this entrypoint is a callback handed to a registration call, not a route; "
        "that it can be driven from outside the system is not established here"),
    "exported-entry": (
        "this entrypoint is an export with no in-repo caller, so it is an entry by "
        "elimination; an unresolved dynamic call looks the same as no caller"),
    "unanchored": (
        "no registration anchor was found for this entrypoint, so who reaches it is "
        "unknown"),
}

# The verb a claim uses for each effect, so the claim reads as a sentence rather
# than as a category name.
_EFFECT_VERB = {
    "dynamic-code": "execute code through",
    "process": "run a process through",
    "deserialize": "deserialize untrusted data through",
    "database": "read or write data through",
    "filesystem-write": "write to the filesystem through",
    "filesystem-read": "read from the filesystem through",
    "network": "make an outbound request through",
}


class GuardDifferential:
    """The C1 constructor: candidates in, suppressed-or-queued capsules out."""

    def __init__(self, store: GraphStore, depth: int = CALL_DEPTH) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index
        self.depth = depth
        self.entry_points = EntryPoints(store)
        self.guard_set = GuardSet(store, entry_points=self.entry_points)
        self.dominance = Dominance(store, guard_set=self.guard_set,
                                   entry_points=self.entry_points)
        self.siblings = SiblingDiff(store)
        self._effects: dict[str, list[dict]] | None = None
        self._inputs: dict[str, list[dict]] | None = None
        self._entry_by_id: dict[str, dict] | None = None
        self._peer: dict[str, dict | None] = {}

    # -- the two catalogs ----------------------------------------------------

    def effects(self) -> dict[str, list[dict]]:
        """function id -> the sensitive effects that function performs.

        Built from the ``sink`` nodes the security-role model already materialized,
        attributed to the function that owns the call site. Nothing is invented
        here: the sink catalog and its graded confidence come from the graph."""
        if self._effects is None:
            index: dict[str, list[dict]] = {}
            for sink in self.index.nodes_of_kind("sink"):
                props = sink.get("properties") or {}
                kind = props.get("sink_kind")
                if kind not in SENSITIVE_SINK_KINDS:
                    continue
                callsite = self.gl.nodes.get(props.get("callsite_id"))
                if callsite is None:
                    continue
                owner = self.gl.owner_function(callsite)
                if owner is None:
                    continue
                file, line, _ = self.gl.loc(callsite)
                index.setdefault(owner["id"], []).append({
                    "node_id": sink["id"], "symbol": self.gl.label(callsite),
                    "kind": kind, "file": file, "line": line,
                    "confidence": props.get("confidence") or "conservative",
                })
            self._effects = index
        return self._effects

    def attacker_inputs(self, fn_id: str) -> list[dict]:
        """The externally controlled parameters of a function, from `source` nodes."""
        if self._inputs is None:
            index: dict[str, list[dict]] = {}
            for source in self.index.nodes_of_kind("source"):
                props = source.get("properties") or {}
                owner = props.get("function_id")
                if not owner:
                    continue
                value = self.gl.nodes.get(props.get("value_id"))
                index.setdefault(owner, []).append({
                    "param": self.gl.label(value) if value else
                             str(props.get("value_id")),
                    "origin": props.get("source_kind") or "unknown",
                    "node_id": source["id"],
                    "confidence": props.get("confidence") or "conservative",
                })
            self._inputs = index
        return self._inputs.get(fn_id, [])

    # -- the differential ----------------------------------------------------

    def _entry_for(self, node_id: str) -> dict | None:
        if self._entry_by_id is None:
            self._entry_by_id = {e["node_id"]: e for e in self.store.entries}
        return self._entry_by_id.get(node_id)

    def guarded_peer(self, fn_id: str) -> dict | None:
        """A sibling of this function that does carry a guard, or None.

        Family formation is ``nav.siblings`` untouched — same verb anchor, shared
        noun. Guardedness is asked of the recognition layer rather than of
        ``SiblingDiff.guardedness`` so that "guarded" means the same thing here as it
        does in the dominance verdict; two definitions of guarded in one pipeline is
        how a differential starts lying."""
        if fn_id in self._peer:
            return self._peer[fn_id]
        entry = self._entry_for(fn_id)
        peer = None
        if entry is not None:
            _key, members = self.siblings.family_of(entry)
            for member in members:
                if member["node_id"] == fn_id:
                    continue
                guards = self.dominance._guards_on(member["node_id"])
                if guards:
                    peer = {
                        "sibling_id": member["node_id"], "symbol": member["name"],
                        "at": f"{member['file']}:{member['line']}",
                        "why": (f"a peer of this function guards the same kind of "
                                f"effect (via {guards[0]['guard_name']}); this one "
                                f"has no recognized guard"),
                        "guard_name": guards[0]["guard_name"],
                    }
                    break
        self._peer[fn_id] = peer
        return peer

    # -- candidate -> capsule ------------------------------------------------

    def _capsule(self, anchor: dict, handler: dict, effect_fn_id: str,
                 effect: dict, verdict: dict,
                 declarative: list[dict]) -> dict:
        handler_id = handler["id"]
        handler_file, handler_line, _ = self.gl.loc(handler)
        suppressed = verdict["state"] == STATE_PRESERVED

        guards_present = [{
            "predicate": guard["guard_name"], "dominates": True,
            "how": guard["how"], "node_id": guard["guard_id"],
            "host": guard.get("host_name"), "file": guard.get("file"),
            "line": guard.get("line"), "confidence": guard.get("confidence"),
        } for guard in verdict["guards"]]
        guards_present += [{
            "predicate": guard["guard_name"], "dominates": False,
            "how": guard["how"], "node_id": guard["guard_id"],
            "host": None, "file": guard.get("file"), "line": guard.get("line"),
            "confidence": guard.get("confidence"), "note": guard.get("note", ""),
        } for guard in declarative]

        peer = None if suppressed else self.guarded_peer(effect_fn_id)
        witness = verdict["witness"]
        flow = [f"{n['name']} ({n['file']}:{n['line']})" for n in witness["nodes"]]

        how = anchor.get("how") if anchor else "unanchored"
        uncertainty = list(self.guard_set.unknowns_for(effect_fn_id))
        if how in _REACHABILITY_GAP:
            uncertainty.append(_REACHABILITY_GAP[how])
        if verdict["completeness"] == COMPLETENESS_OPAQUE:
            uncertainty.append(
                "the call search was truncated before it could answer; this capsule "
                "is queued because an unexamined path is not a cleared one")
        if declarative:
            uncertainty.append(
                "a declarative requirement is present on the registration "
                f"({', '.join(g['guard_name'] for g in declarative)}) but its value "
                "is not readable from the graph, so it did not suppress")
        if suppressed:
            uncertainty.append(
                "the guard is present on the call path; whether it dominates every "
                "branch inside its host is not decided until CFG dominance lands")

        verb = _EFFECT_VERB.get(effect["kind"], "reach")
        claim = {
            "subject": _SUBJECT.get(how, "caller"),
            "action": verb,
            "object": effect["symbol"],
            "constraint": "without passing a recognized authorization guard",
        }
        actors = ["judge"]
        if how == "route":
            actors.append("runtime-probe")

        return cap.new_capsule(
            constructor=CONSTRUCTOR_ID,
            claim=claim,
            entrypoint={
                "node_id": handler_id, "symbol": self.gl.label(handler),
                "file": handler_file, "line": handler_line,
                "how": how,
                "anchor": anchor.get("anchor_label") if anchor else None,
            },
            attacker_inputs=self.attacker_inputs(handler_id),
            sensitive_effect=effect,
            dataflow=flow,
            witness=witness,
            guards_present=guards_present,
            missing_guard=None if suppressed or not peer else {
                "predicate": peer["guard_name"], "expected_from": "family",
                "why": peer["why"],
            },
            cross_reference=None if not peer else
                            {k: v for k, v in peer.items() if k != "guard_name"},
            uncertainty=uncertainty,
            objective=(
                f"prove or kill: a caller that passes no recognized guard can "
                f"{verb} {effect['symbol']} ({effect['kind']}) starting from "
                f"{self.gl.label(handler)}"
                f"{' at ' + handler_file + ':' + str(handler_line) if handler_file else ''}"),
            suggested_actors=actors,
            state=verdict["state"],
            provenance=verdict["provenance"],
            completeness=verdict["completeness"],
        )

    # -- the run -------------------------------------------------------------

    def run(self, limit_entrypoints: int = 0) -> dict:
        """Every (anchor, sensitive effect) pair, adjudicated.

        ``limit_entrypoints`` bounds the scan for a quick look; the census reports
        how many entrypoints were skipped, because a truncated run that reads as a
        complete one is the same lie as a truncated search that reads as a clean
        verdict."""
        effects = self.effects()
        handlers = sorted(self.entry_points.by_handler())
        scanned = handlers[:limit_entrypoints] if limit_entrypoints else handlers
        capsules: list[dict] = []
        suppressed = 0
        inert = 0
        exhausted = 0

        for handler_id in scanned:
            handler = self.gl.nodes.get(handler_id)
            if handler is None:
                continue
            anchors = self.entry_points.by_handler().get(handler_id, [])
            anchor = anchors[0] if anchors else None
            declarative = [g for g in self.guard_set.for_function(handler_id, anchors)
                           if g["how"] == "declarative"]
            closure = self.dominance.call_closure(handler_id, depth=self.depth)
            if closure.exhausted:
                exhausted += 1
            reached = [fn for fn in effects if fn in closure]
            if not reached:
                inert += 1
                continue
            for effect_fn_id in reached:
                verdict = self.dominance.verdict(handler_id, effect_fn_id,
                                                 depth=self.depth)
                for effect in effects[effect_fn_id]:
                    capsule = self._capsule(anchor, handler, effect_fn_id, effect,
                                            verdict, declarative)
                    if capsule["state"] == STATE_PRESERVED:
                        suppressed += 1
                    capsules.append(capsule)

        queue = ranked([c for c in capsules if c["state"] != STATE_PRESERVED])
        suppressions = [c for c in capsules if c["state"] == STATE_PRESERVED]
        return {
            "constructor": CONSTRUCTOR_ID,
            "census": {
                "entrypoints_total": len(handlers),
                "entrypoints_scanned": len(scanned),
                "entrypoints_skipped": len(handlers) - len(scanned),
                "entrypoints_inert": inert,
                "closures_truncated": exhausted,
                "candidates": len(capsules),
                "suppressed": suppressed,
                "queued": len(queue),
                "effect_functions": len(effects),
            },
            "queue": queue,
            "suppressions": suppressions,
        }


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="B1/C1 — the guard-differential constructor")
    p.add_argument("graph")
    p.add_argument("--limit", type=int, default=0,
                   help="scan only the first N entrypoints (0 = all)")
    p.add_argument("--depth", type=int, default=CALL_DEPTH)
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph)
    store.ensure_dataflow_tier()
    result = GuardDifferential(store, depth=args.depth).run(
        limit_entrypoints=args.limit)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
