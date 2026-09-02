#!/usr/bin/env python3
"""Profile the three production passes under one process-tree memory ceiling.

This is an acceptance harness, not a benchmark suite.  It invokes the same path-only
native boundaries as the product, records wall time and aggregate RSS for each pass,
and fingerprints the published binary contracts.  A saved report can then be used as
an exact-output gate while the implementations behind those contracts are optimized.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


DEFAULT_MEMORY_MB = 5120.0
ROOT = Path(__file__).resolve().parents[1]
BOUNDED_RUN = ROOT / "tools" / "bounded_run.py"
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _artifact_fingerprints(graph: Path) -> dict[str, dict[str, Any]]:
    base = os.fspath(graph).rstrip("/")
    paths = {
        "pass1_input": Path(f"{base}.pass2.input.pb"),
        "pass1_translation_facts": Path(f"{base}.pass2.facts.pb"),
        "pass2_dataflow": Path(f"{base}.dataflow.pb"),
        "pass3_semantic": Path(f"{base}.pass3.semantic.pb"),
        "pass3_events": Path(f"{base}.pass3.semantic.pb.events.pb"),
        "pass3_findings": Path(f"{base}.pass3.semantic.pb.events.pb.match.pb"),
    }
    result: dict[str, dict[str, Any]] = {}
    for name, path in paths.items():
        if path.is_file():
            result[name] = {
                "path": os.fspath(path),
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
    return result


def _run_bounded(name: str, command: list[str], *, memory_mb: float,
                 timeout: float, report_dir: Path) -> dict[str, Any]:
    stage_report = report_dir / f"{name}.json"
    stage_report.unlink(missing_ok=True)
    invocation = [
        sys.executable, os.fspath(BOUNDED_RUN),
        "--timeout", str(timeout),
        "--memory-mb", str(memory_mb),
        "--sample-ms", "10",
        "--report", os.fspath(stage_report),
        "--", *command,
    ]
    completed = subprocess.run(invocation, cwd=ROOT, check=False)
    try:
        report = json.loads(stage_report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"{name} did not publish a valid resource report") from error
    report["stage"] = name
    if completed.returncode:
        raise RuntimeError(
            f"{name} failed with status {completed.returncode}: "
            f"termination={report.get('termination')}")
    return report


def _catalog_path(graph: Path) -> Path | None:
    from lachesis.integrations.atropos.enrich import locate_atropos

    root = locate_atropos()
    if root is None:
        return None
    from lachesis.integrations.atropos.native_bind import compiled_catalog

    return Path(compiled_catalog(root, graph))


def _run_internal(stage: str, graph: Path) -> int:
    """Execute one native pass in a clean process for attributable peak RSS."""
    from lachesis.flow.native_lifetime import (
        match_semantic_path,
        run_pass2_path,
        write_semantic_path,
    )
    from lachesis.nav.dataflow.substrate import pass2_input_cache_path
    from lachesis.nav.graph_store import dataflow_overlay_path

    pass2_input = pass2_input_cache_path(graph)
    if not pass2_input.is_file():
        raise RuntimeError(f"Pass-1 contract is missing: {pass2_input}")
    catalog = _catalog_path(graph)
    if stage == "pass2":
        run_pass2_path(pass2_input, dataflow_overlay_path(graph), catalog)
        return 0
    if stage == "pass3":
        semantic = Path(f"{os.fspath(graph).rstrip('/')}.pass3.semantic.pb")
        write_semantic_path(pass2_input, semantic, catalog)
        events = Path(f"{semantic}.events.pb")
        match_semantic_path(events, Path(f"{events}.match.pb"), catalog)
        return 0
    raise ValueError(f"unknown internal stage: {stage}")


def _compare_artifacts(current: dict[str, Any], baseline_path: Path) -> None:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    expected = baseline.get("artifacts", {})
    actual = current.get("artifacts", {})
    mismatches = []
    for name in sorted(set(expected) | set(actual)):
        expected_hash = expected.get(name, {}).get("sha256")
        actual_hash = actual.get(name, {}).get("sha256")
        if expected_hash != actual_hash:
            mismatches.append({"artifact": name, "expected": expected_hash,
                               "actual": actual_hash})
    current["equivalence"] = {
        "baseline": os.fspath(baseline_path),
        "exact": not mismatches,
        "mismatches": mismatches,
    }
    if mismatches:
        names = ", ".join(item["artifact"] for item in mismatches)
        raise RuntimeError(f"exact-output gate failed: {names}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?",
                        help="source tree (omit with --reuse-pass1)")
    parser.add_argument("graph", type=Path, help="Pass-1 .kuzu output/store")
    parser.add_argument("--memory-mb", type=float, default=DEFAULT_MEMORY_MB,
                        help=f"aggregate process-tree RSS limit (default: {DEFAULT_MEMORY_MB:g})")
    parser.add_argument("--timeout", type=float, default=3600.0,
                        help="wall limit for each pass in seconds (default: 3600)")
    parser.add_argument("--report", type=Path, required=True,
                        help="combined JSON report path")
    parser.add_argument("--baseline", type=Path,
                        help="prior report whose artifact hashes must match exactly")
    parser.add_argument("--reuse-pass1", action="store_true",
                        help="profile Pass 2/3 using an existing Pass-1 store")
    parser.add_argument("--internal-stage", choices=("pass2", "pass3"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.memory_mb <= 0 or args.timeout <= 0:
        parser.error("--memory-mb and --timeout must be greater than zero")
    if args.internal_stage:
        return _run_internal(args.internal_stage, args.graph)
    if not args.reuse_pass1 and args.source is None:
        parser.error("source is required unless --reuse-pass1 is used")
    if args.reuse_pass1 and not args.graph.exists():
        parser.error(f"Pass-1 store does not exist: {args.graph}")
    if not args.reuse_pass1 and args.graph.exists():
        parser.error(f"refusing to replace existing Pass-1 store: {args.graph}")

    args.report.parent.mkdir(parents=True, exist_ok=True)
    resource_dir = args.report.parent / f"{args.report.stem}.stages"
    resource_dir.mkdir(parents=True, exist_ok=True)
    stages = []
    if not args.reuse_pass1:
        frontend_timeout = (str(int(args.timeout)) if args.timeout.is_integer()
                            else str(max(1, int(args.timeout))))
        stages.append(_run_bounded(
            "pass1",
            [sys.executable, "-m", "lachesis.cli.main", "build",
             os.fspath(args.source), os.fspath(args.graph),
             "--timeout", frontend_timeout],
            memory_mb=args.memory_mb, timeout=args.timeout, report_dir=resource_dir,
        ))
    for stage in ("pass2", "pass3"):
        stages.append(_run_bounded(
            stage,
            [sys.executable, os.fspath(Path(__file__).resolve()),
             os.fspath(args.graph), "--report", os.fspath(args.report),
             "--internal-stage", stage],
            memory_mb=args.memory_mb, timeout=args.timeout, report_dir=resource_dir,
        ))

    result: dict[str, Any] = {
        "format": "lachesis-pipeline-profile/1",
        "memory_limit_mb": args.memory_mb,
        "graph": os.fspath(args.graph),
        "stages": stages,
        "artifacts": _artifact_fingerprints(args.graph),
    }
    try:
        if args.baseline:
            _compare_artifacts(result, args.baseline)
    finally:
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
