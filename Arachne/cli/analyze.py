#!/usr/bin/env python3
"""Run all registered compiler frontends and write one composed graph."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Arachne.pipeline import run_project, write_project_graph


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir")
    parser.add_argument("output_path", nargs="?", default="graph_out/compiler_project.json")
    parser.add_argument(
        "--frontend-out", default="graph_out/frontends",
        help="directory retaining each compiler's native layered snapshot",
    )
    args = parser.parse_args()
    graph, snapshots = run_project(args.source_dir, args.frontend_out)
    written = write_project_graph(graph, snapshots, args.output_path)
    kinds = Counter(node["kind"] for node in graph["nodes"])
    print(
        f"Composed {len(snapshots)} frontends into {len(graph['nodes'])} nodes "
        f"and {len(graph['edges'])} edges: {written}"
    )
    print("Frontends: " + ", ".join(item.frontend_id for item in snapshots))
    print("Node kinds: " + ", ".join(f"{kind}={count}" for kind, count in sorted(kinds.items())))


if __name__ == "__main__":
    main()
