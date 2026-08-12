#!/usr/bin/env python3
"""A4 — guard recognition: the union of the ways a guard actually shows up.

A name regex over callees finds one kind of guard and quietly misses two others,
and the two it misses are exactly the ones that produce false positives. So this
module returns, per function, every guard it can recognize **together with how it
was recognized** — never a bare boolean:

  * ``named`` — the function calls something whose name lands in a guard-family
    role (``verify`` / ``sanitize`` / ``authz`` / ``validate``), via the shared
    generic lexicon in ``nav.call_roles``. No target literals; the same vocabulary
    the rest of the nav layer already scores with.
  * ``structural`` — the function is *itself* guard-shaped: it branches and throws
    (``nav.guards.GuardProfiles`` class ``guard``). This catches a renamed or
    obfuscated guard whose name says nothing.
  * ``declarative`` — permission metadata on the registration itself. An api-style
    route declares its requirement as an object property on the registration
    argument, which is **not a call**, so no call-graph method can ever see it.
    Recognized from graph structure (the registration call's argument expression
    and its identifier children), not from source text.

**Recognizing a guard and clearing a candidate are different questions.** Every
recognition above is reported; only the ones in an authorization family
(``authz``, ``verify``) may *suppress*. A validator, a sanitizer and a bare
guard shape all prove that something was checked, and none of them proves that the
caller was allowed, so they lower a rank and stay in the evidence rather than
answering the question. ``can_suppress`` carries that distinction on every row.

**Three honest limits, all reported rather than hidden.**

*Relational and ownership guards* — ``if (doc.owner !== userId) throw`` — are real
guards that none of these three recognitions names. Some are caught incidentally by
the structural rule (they branch and throw); the ones that are not are a genuine gap
and belong to a semantic resolver, not here. ``unknowns_for`` states that gap so a
capsule carries it as uncertainty instead of treating the function as unguarded.

*Declarative values are not observable on a pruned store.* Literal value nodes are
dropped at build time, so we can see the key ``authRequired`` but not whether it was
set to ``true`` or ``false``. A declarative recognition therefore carries
``can_suppress: False``: it may lower a candidate's rank and appear in its evidence,
and it may never flip one to ``PROVEN_PRESERVED``. Suppressing on an unread value
would trade a false positive for a missed bug, which is the wrong direction.

  python3 planner/guard_recognition.py graph.kuzu --fn executeArchiveRoom
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nav.call_roles import CallRoles, GUARD_FAMILY_ROLES, role_from_name
from nav.graph_store import GraphStore
from nav.graphlib import camel_tokens
from nav.guards import GuardProfiles
from planner.entrypoints import EntryPoints

# Recognitions, strongest first. Order is the tie-break when a function is guarded
# several ways, and it is also the order a reader should read the evidence in.
RECOGNITIONS = ("named", "structural", "declarative")

# Which recognized roles are allowed to *suppress* an authorization question. A
# permission check and a signature check answer "is this caller allowed"; a
# validator and a sanitizer answer "is this input well formed", and a function that
# merely branches and throws answers "something was checked". The last two are real
# guards and belong in the evidence, but treating them as authorization is how a
# missing-authorization bug gets suppressed by a null check. Everything else lowers
# a rank and stays on the queue.
SUPPRESSING_ROLES = frozenset({"authz", "verify"})
_NOT_AUTHZ = ("this is a guard, but not an authorization one, so it is evidence "
              "against the candidate without answering it")

# Whole tokens that mean "this names an authorization requirement". Deliberately
# narrower than the general security lexicon: this list is read against the
# identifiers inside a registration's options object, where a schema or an error
# handler named `validate...` sits right next to the real permission key. A loose
# family would recognize the schema as a guard.
PERMISSION_TOKENS = frozenset({
    "permission", "permissions", "authz", "authorization", "acl",
    "role", "roles", "scope", "scopes",
    "entitlement", "entitlements", "privilege", "privileges",
})
# The authentication-required flag shape (`authRequired: true`), which is a pair of
# tokens rather than one distinctive word.
_AUTH_FLAG = frozenset({"auth", "required"})


def declarative_tokens(name: str) -> frozenset[str]:
    """The permission-ish tokens an identifier contributes, or an empty set."""
    tokens = set(camel_tokens(name))
    hits = tokens & PERMISSION_TOKENS
    if _AUTH_FLAG <= tokens:
        hits |= _AUTH_FLAG
    return frozenset(hits)


class GuardSet:
    """Every guard recognizable on a function, with its recognition attached."""

    def __init__(self, store: GraphStore, guards: GuardProfiles | None = None,
                 entry_points: EntryPoints | None = None) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index
        self.guards = guards or GuardProfiles(store)
        self.roles = CallRoles(store, guards=self.guards)
        self.entry_points = entry_points or EntryPoints(store)
        self._args_by_call: dict[str, list[dict]] | None = None

    # -- the three recognitions ---------------------------------------------

    def _named(self, fn_id: str) -> list[dict]:
        out: list[dict] = []
        for rec in self.roles.roles_for(fn_id):
            if rec["role"] not in GUARD_FAMILY_ROLES:
                continue
            # `roles_for` types a call by name *or* by the callee's guard shape; only
            # the name signal is the `named` recognition, and the shape signal is
            # already reported by the transitive structural chase. Keeping them
            # separate is what makes "how was this recognized" answerable.
            if not role_from_name(rec["callee"]):
                continue
            suppresses = rec["role"] in SUPPRESSING_ROLES
            row = {
                "how": "named", "role": rec["role"],
                "guard_id": rec["callee_id"], "guard_name": rec["callee"],
                "file": rec["file"], "line": rec["line"],
                "confidence": "medium", "can_suppress": suppresses,
                "fact_origin": rec["fact_origin"],
                "evidence_ids": [fn_id, rec["callee_id"]],
            }
            if not suppresses:
                row["note"] = _NOT_AUTHZ
            out.append(row)
        return out

    def _structural(self, fn_id: str) -> list[dict]:
        profile = self.guards.profile(fn_id)
        if profile["class"] != "guard":
            return []
        node = self.gl.nodes.get(fn_id)
        file, line, _ = self.gl.loc(node) if node else (None, None, None)
        return [{
            "how": "structural", "role": "validate",
            "guard_id": fn_id, "guard_name": self.gl.label(node) if node else fn_id,
            "file": file, "line": line,
            "confidence": "medium", "can_suppress": False,
            "fact_origin": "guard-profile",
            "evidence_ids": [fn_id],
            "counts": {k: profile[k] for k in
                       ("conditions", "short_circuits", "throws")},
            "note": "guard-shaped: it branches and throws. What it checks is not "
                    "recoverable from the shape, so it may lower a rank and never "
                    "suppress an authorization question",
        }]

    def _arguments_of(self, callsite_id: str) -> list[dict]:
        """The argument nodes of a call site, in position order (indexed once)."""
        if self._args_by_call is None:
            index: dict[str, list[dict]] = {}
            for argument in self.index.nodes_of_kind("argument"):
                owner = (argument.get("properties") or {}).get("callsite_id")
                if owner:
                    index.setdefault(owner, []).append(argument)
            for arguments in index.values():
                arguments.sort(
                    key=lambda a: (a.get("properties") or {}).get("position", -1))
            self._args_by_call = index
        return self._args_by_call.get(callsite_id, [])

    def _declarative(self, anchor: dict) -> list[dict]:
        """Permission metadata declared on a registration, not called by it.

        The registration's non-callback arguments expand to an options expression
        whose identifier children are the keys (and the identifier values) written
        there. A permission-ish key is a declared requirement; its *value* is not
        readable on a pruned store, which is why these never suppress."""
        callsite_id = anchor.get("anchor_id")
        node = self.gl.nodes.get(callsite_id)
        if node is None:
            return []
        if self.gl.kind(callsite_id) == "route":
            # a route is a derived fact; the arguments live on the call it was
            # derived from
            callsite_id = (node.get("properties") or {}).get("callsite_id")
            node = self.gl.nodes.get(callsite_id) if callsite_id else None
        if node is None or self.gl.kind(callsite_id) not in ("call", "construct"):
            return []
        out: list[dict] = []
        seen: set[str] = set()
        for argument in self._arguments_of(callsite_id):
            if (argument.get("properties") or {}).get("literal"):
                continue
            for expression in self.index.targets(argument["id"], "EXPANDS_TO"):
                for child in self.index.targets(expression["id"], "AST_CHILD"):
                    if self.gl.kind(child["id"]) != "identifier":
                        continue
                    name = self.gl.label(child)
                    tokens = declarative_tokens(name)
                    if not tokens or name in seen:
                        continue
                    seen.add(name)
                    file, line, _ = self.gl.loc(child)
                    out.append({
                        "how": "declarative", "role": "authz",
                        "guard_id": child["id"], "guard_name": name,
                        "file": file, "line": line,
                        "confidence": "conservative", "can_suppress": False,
                        "fact_origin": "registration-metadata",
                        "evidence_ids": [callsite_id, argument["id"], child["id"]],
                        "tokens": sorted(tokens),
                        "value_observed": None,
                        "note": "declared requirement; its value is not observable "
                                "on a pruned store, so it may lower rank but never "
                                "suppress",
                    })
        return out

    # -- the union -----------------------------------------------------------

    def for_function(self, fn_id: str, anchors: list[dict] | None = None) -> list[dict]:
        """Every guard recognized on this function, strongest recognition first.

        ``anchors`` are the registrations this function sits under (see
        ``planner.entrypoints``); pass them and the declarative recognition is run
        against each, so a route that declares its permission is seen even though
        the handler body calls nothing."""
        found = self._named(fn_id) + self._structural(fn_id)
        for anchor in anchors or ():
            found += self._declarative(anchor)
        found.sort(key=lambda g: (RECOGNITIONS.index(g["how"]),
                                  g["guard_name"] or "", g["guard_id"]))
        return found

    def unknowns_for(self, fn_id: str) -> list[str]:
        """Recognition gaps this function is exposed to, stated plainly.

        A gap is not a finding and not an exoneration. It is the sentence a capsule
        has to carry so that "no guard was recognized" is never read as "no guard
        exists"."""
        gaps: list[str] = []
        profile = self.guards.profile(fn_id)
        if profile["class"] in ("validate", "guard"):
            gaps.append(
                "this function branches on something; a relational or ownership "
                "check (owner/tenant comparison) would not be recognized as a guard "
                "by name and is not modeled here")
        elif profile["conditions"] or profile["short_circuits"]:
            gaps.append(
                "conditions are present but no guard shape was recognized; a "
                "relational or ownership check is not modeled here")
        return gaps

    def stat(self, fn_ids) -> dict:
        counts = dict.fromkeys(RECOGNITIONS, 0)
        guarded = 0
        for fn_id in fn_ids:
            found = self.for_function(
                fn_id, self.entry_points.anchors_for(fn_id))
            if found:
                guarded += 1
            for guard in found:
                counts[guard["how"]] += 1
        return {"functions": len(list(fn_ids)) if hasattr(fn_ids, "__len__") else None,
                "with_a_recognized_guard": guarded, "by_how": counts}


def _resolve_fn(store: GraphStore, token: str) -> str | None:
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="A4 — guard recognition union")
    p.add_argument("graph")
    p.add_argument("--fn", metavar="ID|NAME", required=True,
                   help="recognize the guards on one function")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph)
    store.ensure_dataflow_tier()
    entry_points = EntryPoints(store)
    guard_set = GuardSet(store, entry_points=entry_points)
    fn = _resolve_fn(store, args.fn)
    if not fn:
        print(f"no function for {args.fn!r}", file=sys.stderr)
        return 2
    anchors = entry_points.anchors_for(fn)
    print(json.dumps({
        "function": fn,
        "name": store.gl.label(store.node(fn)),
        "anchors": len(anchors),
        "guards": guard_set.for_function(fn, anchors),
        "unknowns": guard_set.unknowns_for(fn),
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
