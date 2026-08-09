#!/usr/bin/env python3
"""Fix 3 — peer differential with guard transitivity (kills the centralized-helper FP).

A sibling family is a set of functions that do the *same job* across parallel
modules — `deleteTeamsMessage` / `deleteSlackMessage` / `deleteDiscordMessage`.
When most of a family guards an operation and one member doesn't, that outlier is a
strong, structure-derived anomaly (the differential the nereus prior art proved).

The trap the old sweep fell into is **centralized guards**: a member can look
unguarded *locally* while its guard lives one hop away in a shared helper
(`deleteTeamsMessage` → `callTeamsConnectorApi`, which does the auth). Flagging it is
a false positive. So before flagging, guardedness is resolved **transitively**: a
member is guarded if it guards locally *or* any callee within a small radius is a
guard (Fix 2 `class == guard`) or makes a guard-family call (Fix 4 role). A member
demoted by a callee guard is reported with `where = callee:<name>` so the FP-kill is
auditable, never silent.

Family formation is purely structural (no target literals): a member's *role key* is
its identifier tokens minus the tokens of its own directory segments (the platform/
package word), so functions that differ only by platform align into one family — the
same alignment `graphlib.directory_template_families` uses, done per-query.

Output is negative-space aware: a flagged outlier is shown *with* the guard its peers
have and it lacks. `--build-overlay` materializes the flag as a first-class
`UNGUARDED` edge.

  python3 nav/siblings.py graph.json --sym deleteTeamsMessage
  python3 nav/siblings.py graph.json --sym deleteTeamsMessage --build-overlay
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tier1_flag.graphlib import segment_tokens
from nav.graph_store import GraphStore
from nav.guards import GuardProfiles
from nav.call_roles import CallRoles, GUARD_FAMILY_ROLES
from nav.overlay import Overlay, sidecar_path

# how far to chase a centralized guard through callees before giving up
GUARD_RADIUS = 2


def _role_key(entry: dict) -> frozenset[str]:
    """Identifier tokens minus the function's own directory-segment tokens.

    `deleteTeamsMessage` in `adapter-teams/...` -> {delete, message} (the `teams`
    platform token drops out), so it aligns with `deleteSlackMessage` etc."""
    dir_tokens: set[str] = set()
    for seg in (entry.get("file") or "").split("/")[:-1]:
        dir_tokens |= segment_tokens(seg)
    return frozenset(t for t in entry.get("tokens", []) if t not in dir_tokens)


class SiblingDiff:
    def __init__(self, store: GraphStore) -> None:
        self.store = store
        self.gl = store.gl
        self.index = store.index
        self.guards = GuardProfiles(store)
        self.roles = CallRoles(store, guards=self.guards)
        self._by_key: dict[frozenset[str], list[dict]] | None = None

    # -- family formation ----------------------------------------------------

    def _families(self) -> dict[frozenset[str], list[dict]]:
        if self._by_key is None:
            groups: dict[frozenset[str], list[dict]] = {}
            for e in self.store.entries:
                if e["granularity"] not in ("function", "method"):
                    continue
                key = _role_key(e)
                if key:
                    groups.setdefault(key, []).append(e)
            self._by_key = groups
        return self._by_key

    def family_of(self, entry: dict) -> tuple[frozenset[str], list[dict]]:
        key = _role_key(entry)
        members = [m for m in self._families().get(key, [])
                   if (m["file"], m["line"]) != (entry["file"], entry["line"])]
        # distinct directories only — same-dir overloads aren't a cross-module peer set
        members = [entry] + members
        return key, members

    # -- guardedness (with transitivity) ------------------------------------

    def _guards_locally(self, fn_id: str) -> tuple[bool, str | None]:
        prof = self.guards.profile(fn_id)
        if prof["class"] == "guard":
            return True, "local:validate-and-throw"
        for rec in self.roles.roles_for(fn_id):
            if rec["role"] in GUARD_FAMILY_ROLES:
                return True, f"local:calls {rec['callee']} [{rec['role']}]"
        return False, None

    def guardedness(self, fn_id: str) -> dict:
        """Is this function guarded, locally or via a callee within GUARD_RADIUS?"""
        local, where = self._guards_locally(fn_id)
        if local:
            return {"guarded": True, "where": where, "transitive": False}
        # chase centralized guards through callees (bounded BFS)
        seen = {fn_id}
        frontier = [fn_id]
        for _depth in range(GUARD_RADIUS):
            nxt: list[str] = []
            for cur in frontier:
                for callee in self.gl.calls_from(cur):
                    cid = callee["id"]
                    if cid in seen:
                        continue
                    seen.add(cid)
                    g, w = self._guards_locally(cid)
                    if g:
                        return {"guarded": True,
                                "where": f"callee:{self.gl.label(callee)} ({w})",
                                "transitive": True}
                    nxt.append(cid)
            frontier = nxt
        return {"guarded": False, "where": None, "transitive": False}

    # -- the differential ----------------------------------------------------

    def diff(self, entry: dict) -> dict:
        key, members = self.family_of(entry)
        classified = []
        for m in members:
            g = self.guardedness(m["node_id"])
            classified.append({**m, **g})
        guarded = [c for c in classified if c["guarded"]]
        unguarded = [c for c in classified if not c["guarded"]]

        # flag the unguarded minority only when peers predominantly guard
        peers_guard = len(guarded) >= 2 and len(guarded) > len(unguarded)
        flagged = []
        if peers_guard:
            example = guarded[0]
            for c in unguarded:
                flagged.append({
                    "name": c["name"], "at": f"{c['file']}:{c['line']}",
                    "node_id": c["node_id"],
                    "missing": "a guard its peers have (see peer_guard)",
                    "peer_guard": {"node_id": example["node_id"],
                                   "name": example["name"],
                                   "at": f"{example['file']}:{example['line']}",
                                   "where": example["where"]},
                })
        return {
            "move": "siblings", "symbol": entry["name"],
            "role_key": sorted(key), "family_size": len(members),
            "verdict": {"guarded": len(guarded), "unguarded": len(unguarded),
                        "peers_guard": peers_guard},
            "members": [{
                "name": c["name"], "at": f"{c['file']}:{c['line']}",
                "guarded": c["guarded"], "where": c["where"],
                "transitive": c.get("transitive", False),
            } for c in classified],
            "flagged": flagged,
        }

    def shape(self, entry: dict, diff: dict) -> dict:
        """path_shape over the family, with a negative-space UNGUARDED edge from
        each flagged outlier to the guarded peer it differs from."""
        _key, members = self.family_of(entry)
        ids = list(dict.fromkeys(m["node_id"] for m in members))
        edges = []
        for f in diff["flagged"]:
            peer = f["peer_guard"]
            edges.append({
                "source": f["node_id"], "target": peer["node_id"],
                "kind": "UNGUARDED",
                "properties": {"reason": "sibling-diff: peers guard, this does not",
                               "role": "diff", "confidence": "medium",
                               "fact_origin": "sibling-differential"},
            })
        return self.store.path_shape(ids, edges, manifest={
            **{k: diff[k] for k in ("move", "symbol", "role_key",
                                    "family_size", "verdict")},
            "flagged": diff["flagged"],
        })

    # -- materialization -----------------------------------------------------

    def build_overlay(self, overlay: Overlay, entries: list[dict]) -> dict:
        # one family per role_key (the diff is symmetric within a family), and one
        # UNGUARDED edge per (outlier -> peer) pair.
        seen_keys: set[frozenset[str]] = set()
        seen_edges: set[tuple[str, str]] = set()
        flagged_total = 0
        for entry in entries:
            key = _role_key(entry)
            if not key or key in seen_keys:
                continue
            seen_keys.add(key)
            diff = self.diff(entry)
            for f in diff["flagged"]:
                pair = (f["node_id"], f["peer_guard"]["node_id"])
                if pair in seen_edges:
                    continue
                seen_edges.add(pair)
                overlay.add_derived_edge(
                    pair[0], pair[1], "UNGUARDED",
                    {"reason": "sibling-diff: peers guard, this member does not",
                     "peer_guard": f["peer_guard"], "confidence": "medium",
                     "fact_origin": "sibling-differential"})
                flagged_total += 1
        return {"unguarded_edges": flagged_total}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fix 3 — sibling guard differential")
    p.add_argument("graph")
    p.add_argument("--overlay", help="override sidecar overlay path")
    p.add_argument("--sym", metavar="NAME", help="diff a symbol against its peers")
    p.add_argument("--build-overlay", action="store_true",
                   help="materialize UNGUARDED edges for every flagged outlier")
    return p


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    store = GraphStore.load(args.graph, overlay_path=args.overlay)
    sd = SiblingDiff(store)
    if args.build_overlay:
        overlay = store.overlay
        overlay.source = Path(args.graph).name
        fam_seeds = [e for e in store.entries
                     if e["granularity"] in ("function", "method")]
        stats = sd.build_overlay(overlay, fam_seeds)
        path = Path(args.overlay) if args.overlay else sidecar_path(args.graph)
        overlay.write(path)
        print(json.dumps({"wrote": str(path), **stats, **overlay.summary()},
                         indent=2, ensure_ascii=False), file=sys.stderr)
        return 0
    if not args.sym:
        print("need --sym NAME or --build-overlay", file=sys.stderr); return 2
    hits = store.resolve(args.sym)
    if not hits:
        print(f"no node named {args.sym!r}", file=sys.stderr); return 2
    diff = sd.diff(hits[0])
    print(json.dumps(diff, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
