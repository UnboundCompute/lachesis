#!/usr/bin/env python3
"""Build a graph from source and open it warm -- pass 1, then straight into a session.

``Analysis.build`` is the plain single-process build: parse the tree, compose one graph, write it
to the path you name, and hand back an open session over it. ``--enrich`` also materializes the
dataflow tier at build time (pass 2 folded in) so the very first ``analyze``/``candidates`` is
already warm. The full flag surface (parallel packages, incremental, sharding) lives on the
``lachesis build`` CLI verb; this is the common case in one call.

Run it:

    python examples/build_graph.py lachesis/frontends/typescript/fixtures/project /tmp/example.kuzu
    python examples/build_graph.py ./my-c-project /tmp/proj.kuzu --enrich
"""
from __future__ import annotations

import argparse
import sys

import lachesis


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", help="a source tree to analyze (~ is expanded)")
    parser.add_argument("out", help="where to write the .kuzu graph (~ is expanded)")
    parser.add_argument("--enrich", action="store_true",
                        help="also materialize the dataflow tier at build time (pass 2)")
    parser.add_argument("--timeout", type=int, default=300, metavar="SECONDS",
                        help="per-frontend build budget (default: 300)")
    args = parser.parse_args()

    def progress(label: str, elapsed: float) -> None:
        print(f"  [{elapsed:6.2f}s] {label}", file=sys.stderr, flush=True)

    analysis = lachesis.Analysis.build(args.source, args.out, enrich=args.enrich,
                                       timeout_seconds=args.timeout, progress=progress)
    # The session is live -- one cheap structural call to prove it, no second load. The
    # taxonomy families it can reason about are the sink shapes the catalog knows.
    families = analysis.constructors()
    print(f"\nbuilt {args.out}  ({len(families)} obligation families available)")
    print(f"next: python examples/analyze_leads.py {args.out}")
    print(f"      python examples/find_candidates.py {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
