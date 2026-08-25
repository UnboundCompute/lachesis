#!/usr/bin/env python3
"""Enumerate obligation candidates across the WHOLE taxonomy -- leads, never verdicts.

The registry covers every family the graph carries, not one. This walks the census first (so you
see which families exist and how many sites each has), then lists the highest-ranked candidates.
Rank orders attention; it never filters -- every enumerated site is included, and a low rank does
not drop a candidate. Each row is a lead to adjudicate (with ``explain``), not a bug.

``--no-temporal`` takes the guaranteed-bounded structural fast path (no dataflow tier), so a large
graph answers immediately; the temporal families (double-free, UAF, ...) are then reported as
"not evaluated", never as absent.

Run it:

    python examples/find_candidates.py ~/.lachesis/graphs/fixture_p3.kuzu
    python examples/find_candidates.py ~/.lachesis/graphs/curl.kuzu --constructor memory.alloc.size
"""
from __future__ import annotations

import argparse

import lachesis


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    parser.add_argument("--constructor", help="pin one family (default: every family)")
    parser.add_argument("--limit", type=int, default=20, help="rows to print (default: 20)")
    parser.add_argument("--no-temporal", action="store_true",
                        help="structural families only -- the bounded fast path")
    args = parser.parse_args()

    analysis = lachesis.Analysis.open(args.graph)
    temporal = not args.no_temporal

    census = analysis.census(args.constructor, temporal=temporal)
    families = [c for c in census.get("constructors", [])
                if c.get("census", {}).get("enumerated", 0)]
    total = sum(c["census"]["enumerated"] for c in families)
    print(f"{len(families)} non-empty families, {total} candidates enumerated:")
    for entry in sorted(families, key=lambda c: c["census"]["enumerated"], reverse=True):
        meta = entry.get("metadata", {})
        print(f"  {entry['census']['enumerated']:5}  {meta.get('id') or meta.get('constructor')}")

    result = analysis.candidates(temporal=temporal, constructor=args.constructor, detail="compact")
    rows = [row for group in (result.get("groups") or [result])
            for row in group.get("candidates", [])]
    rows.sort(key=lambda r: r.get("rank") or 0.0, reverse=True)
    print(f"\ntop {min(args.limit, len(rows))} of {len(rows)} candidates "
          f"(rank orders attention; it never filters):")
    for row in rows[:args.limit]:
        obs = row.get("observations", {})
        where = f"{obs.get('file')}:{obs.get('line')}" if obs.get("file") else ""
        print(f"  {(row.get('rank') or 0.0):.2f}  {row.get('candidate_id')}  "
              f"{row.get('constructor')}  {obs.get('callee', '')}  {where}")

    if not result.get("temporal_evaluated"):
        print("\n(temporal families not evaluated -- an absent double-free/UAF here reads as "
              "'not evaluated', never 'clean'; drop --no-temporal to fold them in)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
