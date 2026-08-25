#!/usr/bin/env python3
"""Warm a graph's sidecars once, so every later read is fast -- pass 2 as one call.

Building the graph is pass 1; enriching is pass 2. ``Analysis.enrich`` folds the dataflow tier
over the whole graph and binds the catalog, and persists both beside the store (``.dataflow.pb``
and ``.bind.pb``). After this a fresh process running ``analyze`` / ``candidates`` / ``explain``
skips those costs -- the difference between a >120s cold census and an instant one. Idempotent:
run it twice and the second run just reports what is already on disk.

Run it:

    python examples/enrich_graph.py ~/.lachesis/graphs/curl.kuzu
"""
from __future__ import annotations

import argparse

import lachesis


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    args = parser.parse_args()

    report = lachesis.Analysis.open(args.graph).enrich()

    tier = "present" if report["dataflow_tier"] else "not built"
    print(f"dataflow tier : {tier}")
    print(f"  {report['dataflow_sidecar']}  "
          f"({'written' if report['dataflow_written'] else 'absent'})")
    print(f"catalog bind  : {report['bind_sidecar']}  "
          f"({'written' if report['bind_written'] else 'not cached'})")
    if not report["temporal_evaluated"]:
        # The temporal families (double-free, UAF, ...) were not folded in -- an absent one of
        # those reads as "not evaluated", never "clean".
        print("  ! temporal families were not evaluated on this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
