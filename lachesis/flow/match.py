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

from .patterns import substrate, evaluate
from .skeleton import build_skeletons, _summaries_for
from .translate import load_graph


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


def match_typestate(skel):
    """Temporal shape queries over the ordered alloc/use/free/escape stream of one pointer."""
    seq = [t for t in skel["tokens"] if t["t"] in ("alloc", "use", "free", "escape")]
    var, entry = skel["var"], skel["entry"]
    leads = []
    freed = False
    saw_alloc = saw_free = saw_escape = False
    for t in seq:
        k = t["t"]
        if k == "alloc":
            saw_alloc = True
            freed = False                                # realloc reopens the object
        elif k == "free":
            if freed:                                    # free with no intervening alloc/realloc
                leads.append({"pattern": "double-free", "var": var, "entry": entry,
                              "line": t.get("line")})
            freed = True
            saw_free = True
        elif k == "use" and freed:
            leads.append({"pattern": "use-after-free", "var": var, "entry": entry,
                          "line": t.get("line")})
        elif k == "escape":
            saw_escape = True
    if saw_alloc and not saw_free and not saw_escape:
        leads.append({"pattern": "leak", "var": var, "entry": entry})
    return leads


def match_all(skels):
    leads = []
    for s in skels:
        leads += match_reach(s) if s["kind"] == "reach" else match_typestate(s)
    return leads


def main():
    ap = argparse.ArgumentParser(description="match shape patterns over rendered flow skeletons")
    ap.add_argument("--graph", required=True)
    ap.add_argument("--lang", default="c")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    F, succ = load_graph(args.graph, lang=args.lang)
    summaries = _summaries_for(F, succ)
    skels = build_skeletons(F, summaries, lang=args.lang)
    leads = match_all(skels)

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(leads, fh, indent=2)

    print(f"matched {len(leads)} lead(s) over {len(skels)} skeleton(s)"
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
