#!/usr/bin/env python3
"""Run all registered compiler frontends and write one composed graph."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Arachne.pipeline import (
    run_project, run_project_incremental, write_project_graph,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir")
    parser.add_argument("output_path", nargs="?", default="graph_out/compiler_project.json")
    parser.add_argument(
        "--frontend-out", default="graph_out/frontends",
        help="directory retaining each compiler's native layered snapshot",
    )
    parser.add_argument(
        "--kuzu-out", metavar="DIR", default=None,
        help="also write the composed graph to a Kùzu DB directory (dual-write; "
             "the JSON output is unchanged). Requires Python 3.10+ with `kuzu`.",
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
    written = write_project_graph(graph, snapshots, args.output_path)
    if args.kuzu_out:
        from Arachne.kuzu_store import write_kuzu_graph
        kuzu_dir = write_kuzu_graph(graph, snapshots, args.kuzu_out)
        print(f"Kùzu store: {kuzu_dir}")
    kinds = Counter(node["kind"] for node in graph["nodes"])
    print(
        f"Composed {len(snapshots)} frontends into {len(graph['nodes'])} nodes "
        f"and {len(graph['edges'])} edges: {written}"
    )
    print("Frontends: " + ", ".join(item.frontend_id for item in snapshots))
    print("Node kinds: " + ", ".join(f"{kind}={count}" for kind, count in sorted(kinds.items())))


if __name__ == "__main__":
    main()
