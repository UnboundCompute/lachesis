#!/usr/bin/env python3
"""Run all registered compiler frontends and write one composed graph."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Lachesis.kuzu_store import write_kuzu_graph
from Lachesis.pipeline import run_project, run_project_incremental
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
        "--incremental", action="store_true",
        help="reuse each frontend's prior on-disk bundle (under --frontend-out) when "
             "none of its source files changed, recompiling only the ones that did; "
             "the composed graph is identical to a full run.",
    )
    args = parser.parse_args()
    if args.incremental:
        graph, snapshots = run_project_incremental(args.source_dir, args.frontend_out)
    else:
        graph, snapshots = run_project(args.source_dir, args.frontend_out)
    written = write_kuzu_graph(graph, snapshots, args.output_path, prune=args.prune)
    if args.layered_out:
        layered_files = write_layered_graph(build_layered_graph(graph), args.layered_out)
        print(f"Layered projection: {len(layered_files)} files in {args.layered_out}")
    kinds = Counter(node["kind"] for node in graph["nodes"])
    print(
        f"Composed {len(snapshots)} frontends into {len(graph['nodes'])} nodes "
        f"and {len(graph['edges'])} edges: {written}"
    )
    print("Frontends: " + ", ".join(item.frontend_id for item in snapshots))
    print("Node kinds: " + ", ".join(f"{kind}={count}" for kind, count in sorted(kinds.items())))


if __name__ == "__main__":
    main()
