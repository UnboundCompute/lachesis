#!/usr/bin/env python3
"""Summary-computation order for the flow pass.

Per-function summaries compose bottom-up: to instantiate F's summary at a call site in
G, F's summary must already exist. So we do NOT process sources-first -- we process
**callees before callers**. Recursion has no topological order, so:

  1. build the call graph  (edge F -> G  means "F calls G")
  2. condense strongly-connected components  (iterative Tarjan -- recursion in the
     *target* codebase must not blow our stack)
  3. emit SCCs in reverse-topological order == bottom-up: a component whose callees are
     all already emitted comes next.  Tarjan yields exactly this order for free.
  4. a cyclic SCC (size > 1, or a self-recursive singleton) is a **fixpoint group**:
     the summary phase iterates its members until summaries stop changing.

This module produces only the *schedule*; it computes no summaries yet.

Usage:  python3 order.py            # print the bottom-up schedule
"""
import argparse
import json


def load(path):
    g = json.load(open(path))
    F = {f["name"]: f for f in g["functions"]}
    # edge F -> G for each UDF callee G of F (intra-graph calls only)
    succ = {n: [c for c in F[n]["udf_callees"] if c in F] for n in F}
    return F, succ


def tarjan_scc(nodes, succ):
    """Iterative Tarjan. Returns SCCs in reverse-topological order (callees first)."""
    index = {}
    low = {}
    on_stack = set()
    stack = []
    sccs = []
    counter = [0]

    for root in nodes:
        if root in index:
            continue
        # work stack of (node, iterator-position) frames
        work = [(root, 0)]
        while work:
            node, pi = work[-1]
            if pi == 0:
                index[node] = low[node] = counter[0]
                counter[0] += 1
                stack.append(node)
                on_stack.add(node)
            recursed = False
            succs = succ[node]
            for j in range(pi, len(succs)):
                w = succs[j]
                if w not in index:
                    work[-1] = (node, j + 1)
                    work.append((w, 0))
                    recursed = True
                    break
                elif w in on_stack:
                    low[node] = min(low[node], index[w])
            if recursed:
                continue
            # done with node
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                sccs.append(comp)
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return sccs


def is_cyclic(comp, succ):
    """A component needs fixpoint iteration if it has >1 member or a self-edge."""
    if len(comp) > 1:
        return True
    n = comp[0]
    return n in succ[n]


def build_order(F, succ):
    sccs = tarjan_scc(list(F.keys()), succ)   # already callees-first
    schedule = []
    for comp in sccs:
        schedule.append({
            "members": sorted(comp),
            "cyclic": is_cyclic(comp, succ),
            "size": len(comp),
        })
    return schedule


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", default="graph.json")
    args = ap.parse_args()
    F, succ = load(args.graph)
    schedule = build_order(F, succ)

    cyclic = [s for s in schedule if s["cyclic"]]
    print(f"bottom-up summary schedule: {len(schedule)} groups over {len(F)} UDFs "
          f"({len(cyclic)} recursive fixpoint group(s))\n")
    print(f"{'#':>3} {'kind':<12} {'taxo(seed)':<10} members")
    print("-" * 70)
    for i, s in enumerate(schedule, 1):
        kind = "FIXPOINT" if s["cyclic"] else "single"
        taxo = F[s["members"][0]]["taxonomy"]
        marker = "  <-- recursion" if s["cyclic"] else ""
        print(f"{i:>3} {kind:<12} {taxo:<10} {', '.join(s['members'])}{marker}")

    print("\nread: compute summaries top-to-bottom; every callee's summary is ready "
          "before the caller that needs it.")


if __name__ == "__main__":
    main()
