#!/usr/bin/env python3
"""The planner command line: a graph in, a ranked investigation queue out.

  lachesis plan graph.kuzu
  lachesis plan graph.kuzu --limit 20
  lachesis plan graph.kuzu --json > queue.json

The census line is printed to stderr on every run, including the JSON one, because
the counts are how a reader tells a short queue from a truncated scan. A suppressed
candidate is reported, not hidden: "44 suppressed" is the claim that 44 questions were
answered without an agent, and it is only worth anything if it is auditable, which is
what ``--suppressions`` prints.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lachesis.nav.graph_store import GraphStore
from lachesis.cache import _version
from lachesis.planner.constructors import GuardDifferential


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def _census_line(census: dict) -> str:
    return (f"{census['candidates']} candidate(s) from "
            f"{census['entrypoints_scanned']}/{census['entrypoints_total']} "
            f"entrypoint(s): {census['suppressed']} suppressed, "
            f"{census['queued']} queued"
            + (f", {census['entrypoints_skipped']} entrypoint(s) not scanned"
               if census["entrypoints_skipped"] else "")
            + (f", {census['closures_truncated']} closure(s) truncated"
               if census["closures_truncated"] else ""))


def _render(capsule: dict, position: int) -> str:
    entry = capsule["entrypoint"]
    effect = capsule["sensitive_effect"]
    where = f"{entry.get('file')}:{entry.get('line')}"
    lines = [
        f"{position:>3}. [{capsule['rank']:.3f}] {capsule['id']}  {capsule['state']}"
        f" / {capsule['completeness']}",
        f"     {entry['symbol']} ({where}, {entry['how']})"
        f" -> {effect['symbol']} [{effect['kind']}]"
        f" {effect.get('file')}:{effect.get('line')}",
        f"     {capsule['objective']}",
    ]
    guards = capsule.get("guards_present") or []
    if guards:
        lines.append("     guards: " + ", ".join(
            f"{g['predicate']}{'' if g.get('dominates') else ' (does not suppress)'}"
            for g in guards))
    cross = capsule.get("cross_reference")
    if cross:
        lines.append(f"     peer that guards: {cross['symbol']} ({cross['at']})")
    for note in capsule.get("uncertainty") or ():
        lines.append(f"     unknown: {note}")
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lachesis plan",
        description="rank investigation capsules from a Lachesis graph")
    p.add_argument("--version", action="version", version=_version())
    p.add_argument("graph", help="path to a .kuzu store")
    p.add_argument("--limit", type=_nonnegative_int, default=20,
                   help="how many queued capsules to print (0 = all)")
    p.add_argument("--entrypoints", type=_nonnegative_int, default=0, metavar="N",
                   help="scan only the first N entrypoints (0 = all)")
    p.add_argument("--json", action="store_true",
                   help="print the full result as JSON on stdout")
    p.add_argument("--suppressions", action="store_true",
                   help="print what was suppressed and which guard did it")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        store = GraphStore.load(args.graph)
        store.ensure_dataflow_tier()
    except Exception as error:  # noqa: BLE001 - CLI converts store errors to one-line guidance
        if os.environ.get("LACHESIS_TRACEBACK"):
            raise
        print(f"lachesis plan: {error}", file=sys.stderr)
        print("set LACHESIS_TRACEBACK=1 for the full traceback", file=sys.stderr)
        return 2
    result = GuardDifferential(store).run(limit_entrypoints=args.entrypoints)

    print(_census_line(result["census"]), file=sys.stderr)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    queue = result["queue"]
    shown = queue[:args.limit] if args.limit else queue
    for position, capsule in enumerate(shown, start=1):
        print(_render(capsule, position))
        print()
    if len(shown) < len(queue):
        print(f"... {len(queue) - len(shown)} more queued capsule(s); "
              f"--limit 0 prints them all")
    if args.suppressions:
        print("\nsuppressed, with the guard that did it:")
        for capsule in result["suppressions"]:
            names = ", ".join(g["predicate"] for g in capsule["guards_present"]
                              if g.get("dominates"))
            print(f"  {capsule['entrypoint']['symbol']} -> "
                  f"{capsule['sensitive_effect']['symbol']}: {names}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
