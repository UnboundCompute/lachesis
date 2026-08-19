#!/usr/bin/env python3
"""Traversal step of the flow pass, run against a Lachesis graph.

The walk, exactly as specced:
  1. pick a UDF node (random by default, or --start NAME), classify it
     (LUDF / LS-UDF / S-UDF / UDF).
  2. PHASE 1 -- BFS UP through its callers to a fixpoint (every function that can
     reach the seed: the source cone feeding it).
  3. PHASE 2 -- once all callers are done, descend DOWN into the callees (the calls
     each visited function makes), BFS to a fixpoint.
  4. a function already visited is ignored (single visited-set across both phases).

Leaf nodes (LUDF / LS-UDF) simply have no UDF callees to descend into, so the walk
stops downward there on its own -- no special-casing needed.

Usage:
  python3 traverse.py                     # random seed-0 start
  python3 traverse.py --start raw_copy    # start at a specific node (e.g. a sink leaf)
  python3 traverse.py --seed 3            # different random pick
"""
import argparse
import json
import random
from collections import deque


def load(path):
    g = json.load(open(path))
    return {f["name"]: f for f in g["functions"]}


def classify(f):
    """Return the taxonomy tag the parser already stamped, plus leaf/sink flags."""
    return {
        "taxonomy": f["taxonomy"],
        "is_leaf": len(f["udf_callees"]) == 0,
        "is_source": f["is_source"],
        "sink_ldf": f["sink_ldf_callees"],
    }


def traverse_component(F, start, visited):
    """One full flow from `start`: BFS up through callers, then down into callees.

    Skips anything already in the shared `visited` set (so earlier components are not
    re-walked) and adds everything it reaches to it. Returns this component's trace.
    """
    trace = []
    local = set()

    def visit(name, phase, reason, via):
        visited.add(name)
        local.add(name)
        c = classify(F[name])
        trace.append({
            "phase": phase, "step": len(trace) + 1, "name": name,
            "taxonomy": c["taxonomy"], "is_leaf": c["is_leaf"],
            "is_source": c["is_source"], "sink_ldf": c["sink_ldf"],
            "reason": reason, "via": via,
        })

    visit(start, "seed", "picked", None)

    # PHASE 1: BFS up through callers to fixpoint
    q = deque(c for c in F[start]["callers"] if c not in visited)
    seen_q = set(q)
    up_edges = {c: start for c in q}
    while q:
        name = q.popleft()
        if name in visited:
            continue
        visit(name, "up:callers", "caller-of", up_edges.get(name))
        for parent in F[name]["callers"]:
            if parent not in visited and parent not in seen_q:
                seen_q.add(parent)
                up_edges[parent] = name
                q.append(parent)

    # PHASE 2: callers exhausted -> descend into callees of everything visited this pass
    q = deque()
    seen_q = set()
    down_edges = {}
    for parent in list(local):
        for callee in F[parent]["udf_callees"]:
            if callee not in visited and callee not in seen_q:
                seen_q.add(callee)
                down_edges[callee] = parent
                q.append(callee)
    while q:
        name = q.popleft()
        if name in visited:
            continue
        visit(name, "down:callees", "callee-of", down_edges.get(name))
        for callee in F[name]["udf_callees"]:
            if callee not in visited and callee not in seen_q:
                seen_q.add(callee)
                down_edges[callee] = name
                q.append(callee)

    return trace


def traverse_all(F, order):
    """Cover the whole graph: pick an unvisited node, complete its full flow, repeat
    until every UDF is classified. Each pass is one weakly-connected component."""
    visited = set()
    components = []
    for name in order:
        if name in visited:
            continue
        trace = traverse_component(F, name, visited)
        components.append((name, trace))
    return components, visited


def print_component(F, cid, start, trace):
    s = classify(F[start])
    print(f"\n=== COMPONENT {cid}: seed {start} [{s['taxonomy']}] "
          f"({len(trace)} nodes) ===")
    print(f"{'#':>3} {'phase':<13} {'function':<18} {'taxo':<7} {'via':<14} {'from'}")
    print("-" * 78)
    for t in trace:
        flags = []
        if t["is_source"]: flags.append("SRC")
        if t["is_leaf"]:   flags.append("leaf")
        tag = t["taxonomy"] + ("*" if t["sink_ldf"] else "")
        print(f"{t['step']:>3} {t['phase']:<13} {t['name']:<18} {tag:<7} "
              f"{t['reason']:<14} {t['via'] or '-':<14} {' '.join(flags)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", default="graph.json")
    ap.add_argument("--start", default=None,
                    help="force the FIRST component's seed (default: pick order)")
    ap.add_argument("--seed", type=int, default=0,
                    help="RNG seed shuffling the pick order of unvisited nodes")
    ap.add_argument("--single", action="store_true",
                    help="only walk the first seed's component, not the whole graph")
    args = ap.parse_args()

    F = load(args.graph)

    # pick order over unvisited nodes: seeded shuffle, optional forced first seed
    order = sorted(F.keys())
    random.Random(args.seed).shuffle(order)
    if args.start:
        if args.start not in F:
            raise SystemExit(f"no such UDF: {args.start}")
        order = [args.start] + [n for n in order if n != args.start]

    if args.single:
        visited = set()
        trace = traverse_component(F, order[0], visited)
        print_component(F, 1, order[0], trace)
        components = [(order[0], trace)]
    else:
        components, visited = traverse_all(F, order)
        for i, (start, trace) in enumerate(components, 1):
            print_component(F, i, start, trace)

    # coverage summary
    print("\n" + "=" * 78)
    print(f"coverage: {len(visited)}/{len(F)} UDFs in {len(components)} component(s)")
    sizes = sorted((len(t) for _, t in components), reverse=True)
    print(f"component sizes: {sizes}")
    unreached = sorted(set(F) - visited)
    print(f"unreached: {', '.join(unreached) if unreached else 'none (full coverage)'}")


if __name__ == "__main__":
    main()
