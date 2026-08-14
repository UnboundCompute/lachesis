#!/usr/bin/env python3
"""Time and weigh a graph build, stage by stage and overlay by overlay.

This reproduces the table in ``LAZY_GRAPH_SPEC.md`` §1, which was produced by something
that never made it into the repo. Before/after numbers are only comparable if they come
out of the same instrument, so the instrument is the first thing the lazy-resolution work
needs — and the way to know it is right is to point it at an unchanged tree and check
that it lands near the numbers the spec already published.

Wall time and memory are deliberately measured on separate passes. ``tracemalloc``
roughly doubles wall time, so a run that reports both at once reports neither: use
``--repeat`` for a trustworthy wall figure and read the memory column off the single
traced pass.

Usage:
    python3 tools/profile_build.py <source_dir> [--json out.json] [--repeat 3] [--no-trace]
"""
from __future__ import annotations

import argparse
import json
import os
import resource
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lachesis.core.runner import run_frontend  # noqa: E402
from lachesis.frontends.registry import default_registry  # noqa: E402
from lachesis.pipeline import (  # noqa: E402
    _combined_capabilities,
    _release_payloads,
    combine_graphs,
    enrich_graph,
    snapshot_graph,
    source_inventory,
)


def _rss_mb() -> float:
    """Process peak RSS in MB.

    ``ru_maxrss`` is bytes on Darwin and kilobytes on Linux, and getting that backwards
    is a 1024x error in the one column the spec quotes.
    """
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


class Stopwatch:
    """One row of the report: a stage's wall time and what the process peak did over it."""

    def __init__(self, rows: list) -> None:
        self._rows = rows

    def __call__(self, name: str):
        return _Stage(self._rows, name)


class _Stage:
    def __init__(self, rows: list, name: str) -> None:
        self._rows, self._name = rows, name

    def __enter__(self):
        self._started = time.perf_counter()
        self._rss = _rss_mb()
        self._traced = tracemalloc.get_traced_memory()[0] if tracemalloc.is_tracing() else 0
        return self

    def __exit__(self, *exc):
        traced = tracemalloc.get_traced_memory()[0] if tracemalloc.is_tracing() else 0
        self._rows.append({
            "stage": self._name,
            "wall": time.perf_counter() - self._started,
            "peak_rss_delta_mb": _rss_mb() - self._rss,
            "python_heap_delta_mb": (traced - self._traced) / (1024 * 1024),
        })
        return False


def profile_once(source_dir: str, include_tests: bool = False) -> dict:
    """Build the graph the way ``run_project`` does, with a stopwatch on each stage."""
    stages: list = []
    overlays: list = []
    watch = Stopwatch(stages)
    registry = default_registry()
    groups = registry.partition(source_inventory(source_dir, include_tests=include_tests))

    snapshots = []
    with watch("frontends"):
        for frontend_id in sorted(groups):
            snapshots.append(run_frontend(
                registry.get(frontend_id), source_dir, None, 300,
                roots=groups[frontend_id],
            ))

    with watch("combine_graphs"):
        graph = combine_graphs(snapshot_graph(snapshot) for snapshot in snapshots)
        # ``run_project`` releases here, and enrichment's peak is measured on top of
        # whatever is still live at this point, so an instrument that skipped this
        # would weigh a build nobody runs.
        _release_payloads(snapshots)
    core_size = (len(graph["nodes"]), len(graph["edges"]))

    def observe(overlay_id: str, wall: float, nodes: int, edges: int) -> None:
        overlays.append({
            "overlay": overlay_id, "wall": wall,
            "delta_nodes": nodes, "delta_edges": edges,
        })

    languages = {lang for snapshot in snapshots for lang in snapshot.languages}
    with watch("enrich"):
        enriched = enrich_graph(
            graph, languages, _combined_capabilities(snapshots), observe,
        )

    return {
        "source_dir": os.path.abspath(source_dir),
        "file_count": sum(len(files) for files in groups.values()),
        "frontends": sorted(groups),
        "stages": stages,
        "overlays": overlays,
        "core_nodes": core_size[0], "core_edges": core_size[1],
        "enriched_nodes": len(enriched["nodes"]),
        "enriched_edges": len(enriched["edges"]),
        "total_wall": sum(row["wall"] for row in stages),
        "peak_rss_mb": _rss_mb(),
    }


def render(report: dict) -> str:
    """The §1 table, in the shape the spec prints it, so the two can be read side by side."""
    lines = [
        f"{report['file_count']} files, {len(report['frontends'])} frontends "
        f"({', '.join(report['frontends'])})",
        "",
        "| stage | wall | Δ peak RSS | result |",
        "|---|---|---|---|",
    ]
    for row in report["stages"]:
        result = ""
        if row["stage"] == "combine_graphs":
            result = f"{report['core_nodes']:,} nodes / {report['core_edges']:,} edges"
        elif row["stage"] == "enrich":
            result = f"{report['enriched_nodes']:,} / {report['enriched_edges']:,}"
        lines.append(
            f"| {row['stage']} | {row['wall']:.2f}s | "
            f"+{row['peak_rss_delta_mb']:.0f} MB | {result} |"
        )
    lines.append(
        f"| **total** | **{report['total_wall']:.2f}s** | "
        f"**{report['peak_rss_mb']:.0f} MB peak** | |"
    )
    if report["overlays"]:
        lines += [
            "", "| overlay | wall | Δ nodes / Δ edges |", "|---|---|---|",
        ]
        for row in sorted(report["overlays"], key=lambda item: -item["wall"]):
            lines.append(
                f"| {row['overlay']} | {row['wall']:.2f}s | "
                f"{row['delta_nodes']:,} / {row['delta_edges']:,} |"
            )
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir")
    parser.add_argument("--json", help="write the raw report here for diffing")
    parser.add_argument("--repeat", type=int, default=1,
                        help="untraced wall passes; the fastest is reported")
    parser.add_argument("--no-trace", action="store_true",
                        help="skip the tracemalloc pass (process RSS only)")
    parser.add_argument("--include-tests", action="store_true")
    args = parser.parse_args(argv)

    best = None
    for _ in range(max(1, args.repeat)):
        report = profile_once(args.source_dir, args.include_tests)
        if best is None or report["total_wall"] < best["total_wall"]:
            best = report

    if not args.no_trace:
        tracemalloc.start()
        traced = profile_once(args.source_dir, args.include_tests)
        tracemalloc.stop()
        best["python_heap"] = {
            row["stage"]: row["python_heap_delta_mb"] for row in traced["stages"]
        }

    print(render(best))
    if args.json:
        Path(args.json).write_text(json.dumps(best, indent=2, sort_keys=True))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
