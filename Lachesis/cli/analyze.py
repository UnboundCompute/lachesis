#!/usr/bin/env python3
"""Run all registered compiler frontends and write one composed graph."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from Lachesis.pipeline import (
    run_project, run_project_incremental, write_project_graph,
)
from Lachesis.projections import build_layered_graph, write_layered_graph


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
        help="Kùzu DB directory to write (defaults to a sibling <output>.kuzu). Nav "
             "prefers this low-RAM store over the JSON when it exists. Requires "
             "Python 3.10+ with `kuzu`.",
    )
    parser.add_argument(
        "--no-kuzu", action="store_true",
        help="skip the Kùzu store (JSON only). Nav then serves from the JSON graph.",
    )
    parser.add_argument(
        "--layered-out", metavar="DIR", default=None,
        help="also write the layered-v2 projection here: one file per tier (T0-T4) "
             "plus node_index.json and manifest.json. This is the progressive, "
             "LLM-drillable view of the same canonical graph.",
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
    if args.layered_out:
        layered_files = write_layered_graph(build_layered_graph(graph), args.layered_out)
        print(f"Layered projection: {len(layered_files)} files in {args.layered_out}")
    # Dual-write by default: the JSON stays the canonical artifact (and the
    # LACHESIS_FORCE_JSON fallback), while the sibling Kùzu store becomes the
    # low-RAM default nav serves from. Best-effort — a 3.9 env without kuzu still
    # produces the JSON.
    if not args.no_kuzu:
        import importlib.util
        kuzu_out = args.kuzu_out or str(Path(args.output_path).with_suffix(".kuzu"))
        if importlib.util.find_spec("kuzu") is None:
            print("Kùzu store skipped (needs Python 3.10+ with kuzu); wrote JSON only.",
                  file=sys.stderr)
        else:
            from Lachesis.kuzu_store import write_kuzu_graph
            kuzu_dir = write_kuzu_graph(graph, snapshots, kuzu_out)
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
