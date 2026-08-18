#!/usr/bin/env python3
"""Shape matcher over flow skeletons -- the consumer the renderer feeds.

Two matcher families, exactly mirroring the two skeleton kinds:

  * SINGLE-NODE (reach skeletons): each sink token presents a substrate fact
    {kind, tainted, value_bound, guarded}; the CLOSED evaluator set in patterns.py routes it
    by kind (reachability / relational / presence). This is the guarded-vs-unguarded
    differential -- an UNGUARDED size sink fires relational, its GUARDED sibling does not. We
    import patterns.py unchanged: the renderer feeds it, it is not rewritten here.

  * MULTI-NODE / TEMPORAL (typestate skeletons): shape queries over the ORDERED lifecycle
    token stream that a single sink node cannot express -- double-free (two frees, no realloc
    between), use-after-free (a use after a free), leak (an alloc that neither frees nor
    escapes). These are the patterns the skeleton exists FOR: they are about order and object
    identity across the call seam, not about one node.

A match is a LEAD, never a verdict -- provenance still has to be adjudicated against source.
"""
import argparse
import json
import os
from collections import deque

from .patterns import substrate, evaluate


def match_reach(skel):
    """Single-node evaluator over each sink token in a reach skeleton."""
    leads = []
    for t in skel["tokens"]:
        if t["t"] != "sink":
            continue
        fact = substrate(t["family"], t["tainted"], t["bound"], t["guarded"])
        ev = evaluate(t["family"], fact)
        if ev:
            leads.append({"pattern": ev, "family": t["family"],
                          "at": f"{t['callee']}#{t['arg']}", "entry": skel["entry"],
                          "value": t.get("var"), "guarded": t["guarded"],
                          "is_source": skel["is_source"], "truncated": t.get("truncated", False)})
    return leads


def _leak_lead(seq, var, entry):
    """Leak is a whole-object fact (an alloc that never frees nor escapes on ANY path), so it
    reads the same off the flat stream in both the flat and the path-sensitive matcher."""
    saw_alloc = any(t["t"] == "alloc" for t in seq)
    saw_free = any(t["t"] == "free" for t in seq)
    saw_escape = any(t["t"] == "escape" for t in seq)
    if saw_alloc and not saw_free and not saw_escape:
        return [{"pattern": "leak", "var": var, "entry": entry}]
    return []


def match_leak(skel):
    """Match only the allocation-without-free/escape property.

    Object mode owns double-free/UAF. Keeping this cheap property separate avoids
    running the legacy CFG automaton over every typestate skeleton merely to retain
    leak leads during the migration.
    """
    seq = [token for token in skel["tokens"]
           if token["t"] in ("alloc", "use", "free", "escape")]
    return _leak_lead(seq, skel["var"], skel["entry"])


def match_typestate(skel, cfg=None):
    """Temporal shape queries over one pointer's alloc/use/free/escape stream.

    With a CFG bundle (the product path) the walk is PATH-SENSITIVE: it replays the property
    automaton (START -> ALLOCATED -> FREED; free-on-FREED = double-free, use-on-FREED =
    use-after-free) as a forward may-analysis over the real control-flow graph, so two frees
    on mutually-exclusive branches never meet and a free across a loop back-edge does. Without
    a bundle (the bare CLI, which has no store) it falls back to the flat line-ordered walk --
    a sound-ish approximation that over-reports branch frees.

    A match is a LEAD, never a verdict."""
    seq = [t for t in skel["tokens"] if t["t"] in ("alloc", "use", "free", "escape")]
    var, entry = skel["var"], skel["entry"]
    if cfg is not None:
        cfg_leads = _match_typestate_cfg(seq, var, entry, cfg)
        if cfg_leads is not None:
            return cfg_leads + _leak_lead(seq, var, entry)
        # fall through to the flat walk when the stream can't be placed on the CFG

    leads = []
    freed = False
    for t in seq:
        k = t["t"]
        if k == "alloc":
            freed = False                                # realloc reopens the object
        elif k == "free":
            if freed:                                    # free with no intervening alloc/realloc
                leads.append({"pattern": "double-free", "var": var, "entry": entry,
                              "line": t.get("line")})
            freed = True
        elif k == "use" and freed:
            leads.append({"pattern": "use-after-free", "var": var, "entry": entry,
                          "line": t.get("line")})
    return leads + _leak_lead(seq, var, entry)


def _match_typestate_cfg(seq, var, entry, cfg):
    """Path-sensitive double-free / use-after-free over the CFG. Returns the (df, uaf) leads,
    or None if the stream can't be placed on the CFG (an event with no anchor node) so the
    caller falls back to the flat walk. Leak is added by the caller (a whole-object fact)."""
    succ, resolve = cfg["succ"], cfg["resolve"]
    if any(t.get("node") is None for t in seq):
        return None

    # place each event on its CFG-participating node, preserving stream order per node
    ev_at = {}
    placed = []
    for t in seq:
        n = resolve(t["node"])
        ev_at.setdefault(n, []).append(t)
        placed.append(n)

    # seed from the alloc (it dominates the object's whole lifetime); with no local alloc
    # (a freed-param skeleton) seed from every event node so each sits in the analysed cone.
    alloc_nodes = [resolve(t["node"]) for t in seq if t["t"] == "alloc"]
    seeds = alloc_nodes if alloc_nodes else list(dict.fromkeys(placed))

    reach = set()
    dq = deque(seeds)
    while dq:
        x = dq.popleft()
        if x in reach:
            continue
        reach.add(x)
        dq.extend(succ.get(x, ()))

    # The FREED state carries the IDENTITY of the free SITE that produced it -- a
    # ("FREED", free_node) token rather than a bare "FREED". This is what makes a double-free
    # require two DISTINCT frees. The back-edge of a loop unavoidably carries a free's own FREED
    # back to itself (and, in a `for`, is the only path from inside the loop to the code after
    # it), so a bare-FREED automaton flags a lone free in a `for(i=0;i<1;i++)` once-loop as a
    # double-free. Keyed by site, a free that meets only its OWN FREED (self-doubling around the
    # back-edge) is suppressed, while a free that meets a DIFFERENT site's FREED (two textual
    # frees on a forward path) still fires. Suppressing the single-site loop case is deliberate:
    # it is a real double-free only when the loop provably runs more than once, which needs a
    # trip count we do not have here.
    def apply(state, node):
        """Fold this node's events onto an incoming state set, returning the outgoing set."""
        out = set(state) or {"START"}
        for t in ev_at.get(node, []):
            if t["t"] == "alloc":
                out = {"ALLOCATED"}                          # (re)alloc reopens: drops all FREED sites
            elif t["t"] == "free":
                out = {("FREED", node)}                      # this site now dominates the object
            # use / escape do not change the object's state
        return out

    # forward may-analysis to a fixpoint: union incoming states at merges, re-enqueue on
    # change so loop back-edges are followed until stable.
    in_state = {n: set() for n in reach}
    wl = deque(reach)
    guard = 0
    while wl and guard < 200000:
        guard += 1
        n = wl.popleft()
        out = apply(in_state[n], n)
        for m in succ.get(n, ()):
            if m not in in_state:
                in_state[m] = set()
            before = frozenset(in_state[m])
            in_state[m] |= out
            if frozenset(in_state[m]) != before:
                wl.append(m)

    def freed_sites(state):
        return {s[1] for s in state if isinstance(s, tuple) and s[0] == "FREED"}

    # read findings at the fixpoint: replay each node's events against its incoming state
    leads, seen = [], set()
    for n in reach:
        cur = set(in_state[n]) or {"START"}
        for t in ev_at.get(n, []):
            if t["t"] == "free":
                # a double-free needs the incoming FREED to come from a DIFFERENT free site;
                # meeting only this site's own FREED is loop self-doubling (see apply) -> skip
                if freed_sites(cur) - {n}:
                    key = ("double-free", t.get("line"), n)
                    if key not in seen:
                        seen.add(key)
                        leads.append({"pattern": "double-free", "var": var,
                                      "entry": entry, "line": t.get("line")})
                cur = {("FREED", n)}
            elif t["t"] == "use":
                if freed_sites(cur):
                    key = ("use-after-free", t.get("line"), n)
                    if key not in seen:
                        seen.add(key)
                        leads.append({"pattern": "use-after-free", "var": var,
                                      "entry": entry, "line": t.get("line")})
            elif t["t"] == "alloc":
                cur = {"ALLOCATED"}
    return leads


def match_all(skels, cfg=None):
    leads = []
    for s in skels:
        leads += match_reach(s) if s["kind"] == "reach" else match_typestate(s, cfg=cfg)
    return leads


def main():
    ap = argparse.ArgumentParser(description="run the production flow pipeline and match shapes")
    ap.add_argument("--graph", required=True)
    ap.add_argument("--lang", default="c")
    ap.add_argument("--out", default=None)
    ap.add_argument(
        "--workers", type=int, default=None,
        help="object-summary worker processes (default: up to 4; env: "
             "LACHESIS_LIFETIME_WORKERS)")
    args = ap.parse_args()

    # This module's entrypoint is protected by the __main__ guard, so Python's spawn
    # workers are safe here. The lower-level library API remains single-process unless
    # its embedding application explicitly supplies the same environment setting.
    if args.workers is not None:
        os.environ["LACHESIS_LIFETIME_WORKERS"] = str(args.workers)
    elif "LACHESIS_LIFETIME_WORKERS" not in os.environ:
        os.environ["LACHESIS_LIFETIME_WORKERS"] = str(min(4, os.cpu_count() or 1))

    # Keep the CLI on the same entrypoint as MCP. Calling match_all directly here used
    # to bypass object identity and silently report legacy name-keyed results.
    from lachesis.flow.pipeline import run_pass
    from lachesis.nav.graph_store import GraphStore
    bundle = run_pass(GraphStore.load(args.graph), lang=args.lang)
    skels, leads = bundle["skeletons"], bundle["leads"]

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(leads, fh, indent=2)

    engine = bundle.get("lifetime", {}).get("active", "legacy")
    print(f"matched {len(leads)} lead(s) over {len(skels)} skeleton(s) "
          f"(lifetime={engine})"
          + (f" -> {args.out}" if args.out else "") + "\n")
    # single-node leads, source-rooted first (the maximal stitched flows)
    reach = [l for l in leads if l["pattern"] in ("reachability", "relational", "presence")]
    temporal = [l for l in leads if l not in reach]
    for l in sorted(reach, key=lambda x: (not x["is_source"], x["entry"])):
        src = "src " if l["is_source"] else "    "
        g = "GUARDED  " if l["guarded"] else "UNGUARDED"
        print(f"  {src}{l['pattern']:12} {g} {l['entry']:16} {l['at']:20} ({l['value']})")
    if temporal:
        print()
        for l in temporal:
            ln = f"@{l['line']}" if l.get("line") else ""
            print(f"  {l['pattern']:16} {l['entry']:16} {l['var']}{ln}")


if __name__ == "__main__":
    main()
