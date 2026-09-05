#!/usr/bin/env python3
"""Run a command with wall-clock and aggregate resident-memory limits.

macOS does not provide a dependable shell ``ulimit`` for resident memory, and graph
stores legitimately mmap files that make an address-space limit misleading.  This
supervisor therefore samples RSS for the complete child process tree, terminates the
process group when either bound is crossed, and writes a small JSON report suitable for
real-world frontend/MCP smoke-test evidence.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def _process_table() -> dict[int, tuple[int, int]]:
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,rss="], capture_output=True, text=True, check=False
    )
    table: dict[int, tuple[int, int]] = {}
    for line in result.stdout.splitlines():
        try:
            pid, parent, rss_kib = (int(value) for value in line.split())
        except ValueError:
            continue
        table[pid] = (parent, rss_kib)
    return table


def _descendants(root: int, table: dict[int, tuple[int, int]] | None = None) -> set[int]:
    """Every process transitively parented by root, discovered by walking ppid
    (NOT process group). A child that opened its own session -- e.g. a build
    frontend worker that calls setsid -- leaves root's process group but keeps
    root somewhere on its ppid chain, so a ppid walk still finds it where a
    killpg would miss it."""
    table = _process_table() if table is None else table
    descendants = {root}
    changed = True
    while changed:
        changed = False
        for pid, (parent, _) in table.items():
            if parent in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    return descendants


def _tree_rss_kib(root: int) -> int:
    table = _process_table()
    return sum(table.get(pid, (0, 0))[1] for pid in _descendants(root, table))


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the ENTIRE descendant tree, not just the process group. killpg
    reaches only same-session children; a frontend worker that setsid'd into its
    own group would survive a killpg and keep running -- concurrently with the
    NEXT bounded_run, which risks the OOM the memory cap exists to prevent. So we
    snapshot the whole tree by ppid BEFORE signalling (after the root dies its
    children reparent to init and the chain is lost), then signal the group AND
    every snapshot pid individually."""
    root = process.pid
    victims = _descendants(root)

    def _signal_all(sig: int) -> None:
        try:
            os.killpg(root, sig)
        except (ProcessLookupError, PermissionError):
            pass
        for pid in victims:
            try:
                os.kill(pid, sig)
            except (ProcessLookupError, PermissionError):
                pass

    _signal_all(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # SIGKILL the original snapshot plus anything newly spawned that is still
    # reachable by ppid, then reap the root.
    victims |= _descendants(root)
    _signal_all(signal.SIGKILL)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, required=True, help="wall seconds")
    parser.add_argument("--memory-mb", type=float, required=True, help="process-tree RSS")
    parser.add_argument("--sample-ms", type=float, default=50.0,
                        help="RSS sampling interval in milliseconds (default: 50)")
    parser.add_argument("--report", type=Path, help="optional JSON report path")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    if args.timeout <= 0 or args.memory_mb <= 0 or args.sample_ms <= 0:
        parser.error("limits and --sample-ms must be greater than zero")

    started = time.monotonic()
    process = subprocess.Popen(command, start_new_session=True)

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    peak_kib = 0
    reason = "exit"
    try:
        while True:
            elapsed = time.monotonic() - started
            rss_kib = _tree_rss_kib(process.pid)
            peak_kib = max(peak_kib, rss_kib)
            if rss_kib > args.memory_mb * 1024:
                reason = "memory"
                _terminate_group(process)
                break
            if elapsed > args.timeout:
                reason = "timeout"
                _terminate_group(process)
                break
            if process.poll() is not None:
                break
            time.sleep(args.sample_ms / 1000)
    except KeyboardInterrupt:
        reason = "interrupted"
        _terminate_group(process)

    elapsed = time.monotonic() - started
    returncode = process.poll()
    report = {
        "command": command,
        "elapsed_seconds": round(elapsed, 3),
        "peak_rss_mb": round(peak_kib / 1024, 3),
        "limit_rss_mb": args.memory_mb,
        "timeout_seconds": args.timeout,
        "sample_interval_ms": args.sample_ms,
        "termination": reason,
        "returncode": returncode,
    }
    rendered = json.dumps(report, sort_keys=True)
    print(rendered, file=sys.stderr)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(rendered + "\n", encoding="utf-8")
    if reason == "memory":
        return 125
    if reason == "timeout":
        return 124
    if reason == "interrupted":
        return 130
    return int(returncode or 0)


if __name__ == "__main__":
    raise SystemExit(main())
