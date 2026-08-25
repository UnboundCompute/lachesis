#!/usr/bin/env python3
"""Analyze a graph and query its leads -- the whole flow in a handful of calls.

This is the friction this library exists to remove. Answering "where do the double-frees
land, and what's near tree.c:185?" used to mean hand-writing ``GraphStore.load(...)`` +
``run_pass(...)`` and re-deriving leads from cold every question. Here it is one warm session:
open once, ``analyze`` once (bounded by default so it can't run away), then filter the held
result as many ways as you like -- nothing recomputes.

Run it:

    python examples/analyze_leads.py ~/.lachesis/graphs/fixture_p3.kuzu
    python examples/analyze_leads.py ~/.lachesis/graphs/fixture_p3.kuzu --at main.c:1300-1320
    python examples/analyze_leads.py ~/.lachesis/graphs/curl.kuzu --pattern double-free -o leads.json
"""
from __future__ import annotations

import argparse
import json
import sys

import lachesis


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    parser.add_argument("--pattern", help="show only this bug-shape pattern")
    parser.add_argument("--function", help="show only leads in this function")
    parser.add_argument("--at", metavar="FILE[:LINE|:LO-HI]",
                        help="locate leads by source position")
    parser.add_argument("--hard-stop", type=float, default=None, metavar="SECONDS",
                        help="wall-clock budget for the pass (0 = unbounded)")
    parser.add_argument("-o", "--out", metavar="PATH",
                        help="persist the (filtered) leads as JSON")
    args = parser.parse_args()

    # A live progress line so a long pass is never silent -- the library defines the sink
    # shape (label, elapsed_seconds); here we just print it to stderr.
    def progress(label: str, elapsed: float) -> None:
        print(f"  [{elapsed:6.2f}s] {label}", file=sys.stderr, flush=True)

    analysis = lachesis.Analysis.open(args.graph, progress=progress)
    leads = analysis.analyze(hard_stop=args.hard_stop)

    # Filters return a new LeadSet each time and chain; the pass is never re-run.
    view = leads
    if args.pattern:
        view = view.by_pattern(args.pattern)
    if args.function:
        view = view.by_function(args.function)
    if args.at:
        file, _, span = args.at.partition(":")
        if "-" in span:
            lo, _, hi = span.partition("-")
            view = view.near(file, (int(lo), int(hi)))
        elif span:
            view = view.at(file, int(span))
        else:
            view = view.near(file)

    summary = leads.summary()
    print(f"\n{summary['total']} leads over the whole graph "
          f"(engine={summary['engine']}, timed_out={summary['timed_out']})")
    if summary["timed_out"]:
        # An empty or thin result over a partial run is not "clean" -- say so.
        print(f"  ! partial run: {len(summary['truncated_functions'])} functions truncated")
    print("  by pattern: " + ", ".join(f"{name}={count}"
                                        for name, count in sorted(summary["by_pattern"].items())))

    if view is not leads:
        print(f"\nfiltered to {len(view)} leads:")
        for lead in list(view)[:40]:
            where = f"{lead.get('entry')}:{lead.get('line')}"
            print(f"  {lead.get('pattern'):<28} {where}")
        if len(view) > 40:
            print(f"  ... and {len(view) - 40} more")

    if args.out:
        path = view.to_json(args.out)
        print(f"\nwrote {len(view)} leads to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
