#!/usr/bin/env python3
"""Integrated traverse + summarise pass (no detection yet).

For each weakly-connected component:
  1. TRAVERSE it (BFS up through callers, then down into callees) -> coverage +
     taxonomy classification, exactly as traverse.py.
  2. SUMMARISE it right away. A component is closed under callees (a function's callees
     live in its own component), so we can order just this component's members bottom-up
     (callees before callers, recursion as fixpoint groups) and compute each summary with
     its callees already done.

Emits enriched.json: one record per function carrying taxonomy + component + the
deterministic summary. This is the substrate the detectors will later read -- we compute
it whole and narrow NOTHING here on purpose.
"""
import argparse
import json
import random

from .order import tarjan_scc, is_cyclic
from .translate import load_graph
from .traverse import traverse_all, classify
from .summarize import summarize_one
from .skeleton import build_skeletons, render_text
from .match import match_all


def summarise_component(members, F, succ, summaries):
    """Summarise one component's members in bottom-up (callee-first) order.

    members is closed under callees, so tarjan_scc over them yields a valid schedule and
    every callee summary is ready before its caller. Recursive SCCs are iterated to a
    fixpoint."""
    for comp in tarjan_scc(members, succ):        # reverse-topological == callees first
        if not is_cyclic(comp, succ):
            summaries[comp[0]] = summarize_one(comp[0], F, summaries)
            continue
        for m in comp:                             # seed the fixpoint group empty
            summaries[m] = {"name": m, "params": F[m]["params"],
                            "taxonomy": F[m]["taxonomy"], "sink_flows": [],
                            "sink_params": {}, "typestate": {}, "param_typestate": {},
                            "frees_params": {}, "returns": "value", "returns_param": None}
        for _ in range(len(comp) + 3):
            before = json.dumps({m: summaries[m] for m in comp}, sort_keys=True)
            for m in comp:
                summaries[m] = summarize_one(m, F, summaries)
            if json.dumps({m: summaries[m] for m in comp}, sort_keys=True) == before:
                break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True,
                    help="path to a built Lachesis .kuzu store (enriched on load)")
    ap.add_argument("--out", default="enriched.json")
    ap.add_argument("--skeletons", default=None,
                    help="also write the rendered flow skeletons here (JSON)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    F, succ = load_graph(args.graph)

    order = sorted(F.keys())
    random.Random(args.seed).shuffle(order)
    components, visited = traverse_all(F, order)

    summaries = {}
    enriched = {}
    for cid, (seed, trace) in enumerate(components, 1):
        members = [t["name"] for t in trace]
        # summarise this component the moment its traversal finishes
        summarise_component(members, F, succ, summaries)
        for t in trace:
            enriched[t["name"]] = {
                "name": t["name"], "taxonomy": t["taxonomy"],
                "is_source": t["is_source"], "component": cid, "component_seed": seed,
                "summary": summaries[t["name"]],
            }

    with open(args.out, "w") as fh:
        json.dump(enriched, fh, indent=2)

    print(f"traversed + summarised {len(enriched)}/{len(F)} functions in "
          f"{len(components)} component(s) -> {args.out}\n")
    for cid, (seed, trace) in enumerate(components, 1):
        print(f"--- component {cid} (seed {seed}, {len(trace)} fns) ---")
        for t in trace:
            s = summaries[t["name"]]
            bits = []
            # complete flows: every value (param/local/field) that reaches a sink
            for f in s["sink_flows"]:
                if not f["guarded"]:
                    g = "UNGUARDED"
                elif f.get("site_guarded"):
                    g = "G[" + ",".join(f["guards"]) + "]"
                else:                                    # guard is inherited from callee
                    g = "G~[" + ",".join(f["guards"]) + "]"
                via = "" if f["via"] == "direct" else f"~{f['via']}"
                val = f["value"] or f["provenance"] or "expr"
                bits.append(f"{val}->{f['sink']}({g}){via}")
            # typestate: the ordered alloc/free/use/escape signature per pointer
            for v, evs in s["typestate"].items():
                sig = "->".join(e["kind"] for e in evs)
                bits.append(f"[{v}:{sig}]")
            # param typestate: a freed param's lifetime (interprocedural UAF material)
            for v, evs in s.get("param_typestate", {}).items():
                sig = "->".join(e["kind"] for e in evs)
                bits.append(f"[param {v}:{sig}]")
            if s["frees_params"]:
                bits.append("frees:" + ",".join(s["frees_params"]))
            if s["returns"] == "alloc":
                bits.append("returns:alloc")
            tag = t["taxonomy"] + ("*" if t["sink_ldf"] else "")
            print(f"  {t['name']:16} {tag:8} {'; '.join(bits) if bits else '-'}")
        print()

    # ---- render the stitched flow skeletons and match shape patterns over them -----
    skels = build_skeletons(F, summaries)
    leads = match_all(skels)
    if args.skeletons:
        with open(args.skeletons, "w") as fh:
            json.dump(skels, fh, indent=2)

    reach = [s for s in skels if s["kind"] == "reach"]
    life = [s for s in skels if s["kind"] == "typestate"]
    print("=" * 70)
    print(f"flow skeletons: {len(skels)} ({len(reach)} reach, {len(life)} lifetime)"
          + (f" -> {args.skeletons}" if args.skeletons else "") + "\n")
    for s in sorted(skels, key=lambda x: (not x["is_source"], x["entry"])):  # maximal first
        print(render_text(s))
        print()

    print("=" * 70)
    print(f"shape-matcher leads: {len(leads)}\n")
    reach_leads = [l for l in leads if l["pattern"] in ("reachability", "relational", "presence")]
    temporal = [l for l in leads if l not in reach_leads]
    for l in sorted(reach_leads, key=lambda x: (not x["is_source"], x["entry"])):
        src = "src " if l["is_source"] else "    "
        g = "GUARDED  " if l["guarded"] else "UNGUARDED"
        print(f"  {src}{l['pattern']:12} {g} {l['entry']:16} {l['at']:20} ({l['value']})")
    for l in temporal:
        ln = f"@{l['line']}" if l.get("line") else ""
        print(f"  {'':4}{l['pattern']:12} {'':9} {l['entry']:16} {l['var']}{ln}")
    print()


if __name__ == "__main__":
    main()
