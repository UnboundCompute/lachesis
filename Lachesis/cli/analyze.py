#!/usr/bin/env python3
"""Run all registered compiler frontends and write one composed graph."""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Lachesis.kuzu_store import write_kuzu_graph
from Lachesis.pipeline import (run_project, run_project_incremental,
                               run_project_parallel)
from Lachesis.projections import build_layered_graph, write_layered_graph


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir")
    parser.add_argument(
        "output_path", nargs="?", default="graph_out/compiler_project.kuzu",
        help="Kùzu store directory to write (holds graph.kuzu plus the store "
             "manifest). This is the graph: nav and lachesis-query both read it.",
    )
    parser.add_argument(
        "--frontend-out", default="graph_out/frontends",
        help="directory retaining each compiler's native layered snapshot",
    )
    parser.add_argument(
        "--layered-out", metavar="DIR", default=None,
        help="also write the layered-v2 projection here: one file per tier (T0-T4) "
             "plus node_index.json and manifest.json. This is the progressive, "
             "LLM-drillable view of the same canonical graph.",
    )
    parser.add_argument(
        "--prune", action="store_true",
        help="drop the pure-lexical `token` and `source-span` nodes (and the edges "
             "that touch them) from the store. Every navigation tool answers "
             "identically without them (source excerpts are read from the file by "
             "offset), so this is lossless for nav and roughly halves the store — but "
             "it does drop real T0 graph content, so it is off by default.",
    )
    parser.add_argument(
        "--enrich", action="store_true",
        default=os.environ.get("LACHESIS_ENRICH_AT_BUILD") == "1",
        help="fold the overlay dataflow tier (taint, CFG, points-to, routes) into the "
             "store at build time. Off by default: the tier is a pure function of the "
             "core graph plus the store manifest, so nav rebuilds it on first use and "
             "caches it beside the store, keeping it off the critical path of every "
             "build. Set LACHESIS_ENRICH_AT_BUILD=1 for the same effect.",
    )
    parser.add_argument(
        "--incremental", action="store_true",
        help="reuse each frontend's prior on-disk bundle (under --frontend-out) when "
             "none of its source files changed, recompiling only the ones that did; "
             "the composed graph is identical to a full run.",
    )
    parser.add_argument(
        "--parallel-packages", action="store_true",
        help="compile each first-party package (a directory with a package.json, "
             "outside node_modules) in its own process. OFF by default because it is "
             "a semantic change, not just a scheduling one: each package becomes its "
             "own compiler program, so types resolve within a package rather than "
             "across the whole tree, and cross-package edges whose far endpoint lands "
             "in another unit are dropped (the count is printed). Wall time is floored "
             "by the largest single package, so this is not linear scaling.",
    )
    parser.add_argument(
        "--max-workers", type=int, default=None, metavar="N",
        help="cap the --parallel-packages pool (default: one worker per package, "
             "never more than the core count). N=1 runs the same partition serially.",
    )
    args = parser.parse_args()
    if args.parallel_packages and args.incremental:
        parser.error("--parallel-packages and --incremental cannot be combined: the "
                     "incremental manifest keys bundles by frontend, not by package")
    # The layered projection is by definition a view of the enriched tier (T4 is the
    # dataflow layer), so asking for it forces enrichment rather than silently emitting
    # an empty top tier.
    enrich = args.enrich or bool(args.layered_out)
    dropped = 0
    if args.parallel_packages:
        graph, snapshots, dropped = run_project_parallel(
            args.source_dir, args.frontend_out, enrich=enrich,
            max_workers=args.max_workers,
        )
    elif args.incremental:
        graph, snapshots = run_project_incremental(args.source_dir, args.frontend_out,
                                                   enrich=enrich)
    else:
        graph, snapshots = run_project(args.source_dir, args.frontend_out, enrich=enrich)
    written = write_kuzu_graph(graph, snapshots, args.output_path, prune=args.prune,
                               enriched=enrich)
    if args.layered_out:
        layered_files = write_layered_graph(build_layered_graph(graph), args.layered_out)
        print(f"Layered projection: {len(layered_files)} files in {args.layered_out}")
    kinds = Counter(node["kind"] for node in graph["nodes"])
    # a parallel build runs one frontend per package, so snapshots counts units, not frontends
    unit = "package units" if args.parallel_packages else "frontends"
    print(
        f"Composed {len(snapshots)} {unit} into {len(graph['nodes'])} nodes "
        f"and {len(graph['edges'])} edges: {written}"
    )
    if args.parallel_packages:
        print(f"Dropped {dropped} cross-package edges (parallel build)")
    print("Tier: " + ("enriched (core + overlay dataflow)" if enrich else
                      "core-only (nav rebuilds the dataflow tier on first use)"))
    print("Frontends: " + ", ".join(sorted({item.frontend_id for item in snapshots})))
    print("Node kinds: " + ", ".join(f"{kind}={count}" for kind, count in sorted(kinds.items())))


if __name__ == "__main__":
    main()
