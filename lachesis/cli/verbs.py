#!/usr/bin/env python3
"""The reader verbs, each a thin shell over one ``Analysis`` method.

These are the pass-mirroring commands the top-level ``lachesis`` parser dispatches:
``enrich`` (pass 2 -> warm sidecars), ``analyze`` (pass 3 -> leads), ``candidates`` (the
obligation registry), and ``explain`` (the one-shot adjudication capsule). Each takes a built
``.kuzu`` graph and calls the matching :class:`lachesis.session.Analysis` method, so the library
is the single implementation and the CLI is a front door, never a second copy of the logic.

Two conventions hold across all of them: progress narrates to stderr (never stdout, so ``--json``
stays a clean document), and ``--json`` prints the method's structured result verbatim while the
default output is a compact human rendering of the same thing. The heavy imports stay inside the
handlers so ``lachesis --help`` and the fast verbs never pay for the flow pipeline.
"""
from __future__ import annotations

import argparse

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FAILURE = 4


def progress_to(progress) -> "callable":
    """Adapt a CLI :class:`~lachesis.cli.progress.Progress` to the library's ``ProgressFn``.

    The library emits ``(label, elapsed)`` at each phase boundary and never imports the CLI's
    spinner; here each new label just opens a new ``Progress`` phase (which ends the prior one),
    so a long pass narrates on the terminal without the library knowing how.
    """
    def sink(label: str, _elapsed: float) -> None:
        progress.phase(label)
    return sink


def _dump(result) -> int:
    import json
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return EXIT_OK


def _open(args, *, progress=None, defer_maps=False):
    """Open the graph warm, or fail with a legible message. ``~`` is expanded by ``open``."""
    from lachesis.session import Analysis

    return Analysis.open(args.graph, overlay=getattr(args, "overlay", None),
                        progress=progress, defer_maps=defer_maps)


# --------------------------------------------------------------------------- enrich

def command_enrich(args: argparse.Namespace) -> int:
    """Pass 2: materialize the dataflow tier and the catalog bind to disk (``.dataflow.pb`` /
    ``.bind.pb``), so later ``analyze``/``candidates``/``explain`` on a fresh process are warm."""
    from lachesis.cli.progress import Progress

    with Progress(enabled=not args.json) as progress:
        progress.phase("loading graph")
        # Pass 2 materializes the complete graph itself; defer navigation-only maps
        # until the temporal bind enters Pass 3, avoiding another graph-sized set of
        # references during the cold materialization peak.
        analysis = _open(args, defer_maps=True)
        progress.phase("materializing dataflow tier + catalog bind")
        report = analysis.enrich(hard_stop=args.hard_stop,
                                 workers=args.lifetime_workers)
    if args.json:
        return _dump(report)
    tier = "present" if report["dataflow_tier"] else "not built (in-memory or unsupported)"
    print(f"dataflow tier: {tier}")
    print(f"  {report['dataflow_sidecar']}  "
          f"({'written' if report['dataflow_written'] else 'absent'})")
    print(f"catalog bind:  {report['bind_sidecar']}  "
          f"({'written' if report['bind_written'] else 'not cached'})")
    if not report["temporal_evaluated"]:
        print("  ! temporal families were not evaluated within the budget -- the bind was not "
              "fully warmed; rerun `lachesis enrich --hard-stop 0` to finish it unbounded")
    return EXIT_OK


# -------------------------------------------------------------------------- analyze

def command_analyze(args: argparse.Namespace) -> int:
    """Pass 3: run the flow pass and query its leads. In memory by default; ``-o`` persists."""
    from lachesis.cli.progress import Progress

    with Progress(enabled=not args.json) as progress:
        analysis = _open(args, progress=progress_to(progress))
        leads = analysis.analyze(engine=args.engine, hard_stop=args.hard_stop,
                                 workers=args.lifetime_workers)

    # --summary is the rollup alone; it wins over any filter so `analyze --summary` always
    # reads the same whether or not a stray --pattern/--at rode along.
    view = leads
    if not args.summary:
        if args.pattern:
            view = view.by_pattern(args.pattern)
        if args.function:
            view = view.by_function(args.function)
        if args.at:
            file, lines = _parse_at(args.at)
            view = view.near(file, lines)

    if args.out:
        path = view.to_json(args.out)
    if args.json:
        result = {"summary": leads.summary(), "leads": list(view)}
        if args.out:
            result["written"] = args.out
        return _dump(result)

    summary = leads.summary()
    print(f"{summary['total']} leads  (engine={summary['engine']}, "
          f"timed_out={summary['timed_out']})")
    if summary["timed_out"]:
        # An empty or thin result over a partial run is not "clean" -- say so, and name the
        # fix. Stopping before object analysis means setup (the dataflow tier) alone spent the
        # budget: warming the graph once removes that cost from every later analyze.
        if summary.get("stopped_before"):
            print(f"  ! stopped before {summary['stopped_before']}: setup (the dataflow tier) "
                  f"alone spent the budget, so no leads were computed -- this is not 'clean'. "
                  f"Warm the graph once with `lachesis enrich {args.graph}` (writes the "
                  f".dataflow.pb sidecar so analyze skips the tier), or raise --hard-stop.")
        else:
            print(f"  ! partial run: {len(summary['truncated_functions'])} functions truncated")
    if summary["by_pattern"]:
        print("  by pattern: " + ", ".join(f"{name}={count}"
              for name, count in sorted(summary["by_pattern"].items())))
    if view is not leads:
        print(f"\nfiltered to {len(view)}:")
        for lead in list(view)[:60]:
            print(f"  {str(lead.get('pattern')):<28} {lead.get('entry')}:{lead.get('line')}")
        if len(view) > 60:
            print(f"  ... and {len(view) - 60} more")
    if args.out:
        print(f"\nwrote {len(view)} leads to {args.out}")
    return EXIT_OK


# ----------------------------------------------------------------------- candidates

def command_candidates(args: argparse.Namespace) -> int:
    """The obligation registry across the whole taxonomy (never scoped to one family unless the
    caller pins ``--constructor``). ``--census`` reports coverage; a list is leads, not verdicts."""
    from lachesis.cli.progress import Progress

    temporal = not args.no_temporal
    with Progress(enabled=not args.json) as progress:
        progress.phase("loading graph")
        analysis = _open(args)
        progress.phase("binding catalog" + (" + temporal skeleton" if temporal else ""))
        if args.census:
            result = analysis.census(args.constructor, temporal=temporal,
                                     hard_stop=args.hard_stop)
        else:
            result = analysis.candidates(
                temporal=temporal, hard_stop=args.hard_stop,
                constructor=args.constructor, domain=args.domain, language=args.language,
                limit=args.limit, detail=args.detail)
    if args.json:
        return _dump(result)
    _render_candidates(result, census=args.census)
    return EXIT_OK


def _render_candidates(result: dict, *, census: bool) -> None:
    evaluated = result.get("temporal_evaluated")
    if census:
        constructors = result.get("constructors", [])
        total = sum(c.get("census", {}).get("enumerated", 0) for c in constructors)
        print(f"{len(constructors)} constructors, {total} candidates enumerated")
        for entry in constructors:
            meta, cen = entry.get("metadata", {}), entry.get("census", {})
            count = cen.get("enumerated", 0)
            if count:
                print(f"  {count:5}  {meta.get('id') or meta.get('constructor')}")
    else:
        groups = result.get("groups") or [result]
        rows = [row for group in groups for row in group.get("candidates", [])]
        rows.sort(key=lambda r: r.get("rank") or 0.0, reverse=True)
        print(f"{len(rows)} candidates (rank orders attention; it never filters)")
        for row in rows[:60]:
            obs = row.get("observations", {})
            where = f"{obs.get('file')}:{obs.get('line')}" if obs.get("file") else ""
            print(f"  {(row.get('rank') or 0.0):.2f}  {row.get('candidate_id')}  "
                  f"{row.get('constructor')}  {obs.get('callee', '')}  {where}")
        if len(rows) > 60:
            print(f"  ... and {len(rows) - 60} more")
    if not evaluated:
        print("  (temporal families not evaluated -- an absent double-free/UAF here reads as "
              "'not evaluated', never 'clean'; run without --no-temporal, or `lachesis enrich`)")


# -------------------------------------------------------------------------- explain

def command_explain(args: argparse.Namespace) -> int:
    """The census->candidates->detail->sources_of->read_body chain composed into one capsule,
    by candidate id or by the sink's ``file:line``."""
    from lachesis.cli.progress import Progress

    temporal = not args.no_temporal
    with Progress(enabled=not args.json) as progress:
        progress.phase("loading graph")
        analysis = _open(args)
        progress.phase("composing explanation")
        target = args.target
        if ":" in target and not target.startswith("obl_") and not target.startswith("life_"):
            file, lines = _parse_at(target)
            line = lines[0] if lines else None
            if line is None:
                print("explain by position needs FILE:LINE", file=_stderr_stream())
                return EXIT_USAGE
            result = analysis.explain_sink(file, line, temporal=temporal,
                                           hard_stop=args.hard_stop)
        else:
            result = analysis.explain(target, temporal=temporal, hard_stop=args.hard_stop)
    if args.json:
        return _dump(result)
    return _render_explain(result)


def _render_explain(result: dict) -> int:
    if "error" in result:
        print(result["error"], file=_stderr_stream())
        if result.get("note"):
            print(f"  note: {result['note']}", file=_stderr_stream())
        return EXIT_FAILURE
    sink = result.get("sink", {})
    print(f"{result['candidate_id']}  [{result['constructor']}]  rank={result.get('rank')}")
    print(f"  obligation : {result.get('obligation')}")
    print(f"  sink       : {sink.get('callee')} at {sink.get('file')}:{sink.get('line')}")
    if sink.get("site"):
        print(f"               {sink['site']}")
    guard = result.get("guard", {})
    dominance = (guard.get("dominance") or {}).get("status", "unknown")
    print(f"  guard      : conditions={guard.get('status')}, size-dominance={dominance}")
    provenance = result.get("provenance", {})
    print(f"  provenance : reached={provenance.get('reached')} "
          f"shown={provenance.get('shown')} truncated={provenance.get('truncated')}")
    for source in (provenance.get("sources") or [])[:8]:
        where = f"{source.get('file')}:{source.get('line')}" if source.get("file") else "?"
        print(f"                <- {source.get('name')}  ({where})")
    source = result.get("source") or {}
    if source.get("body"):
        print(f"  source     : {source.get('name')} "
              f"({source.get('file')}:{source.get('start_line')}-{source.get('end_line')})")
    if result.get("other_matches"):
        print(f"  other sinks at this line: {', '.join(result['other_matches'])}")
    if not result.get("temporal_evaluated"):
        print("  (temporal families not evaluated on this run)")
    return EXIT_OK


# --------------------------------------------------------------------------- shared

def _parse_at(value: str) -> tuple[str, tuple[int, int] | None]:
    """``FILE`` | ``FILE:LINE`` | ``FILE:LO-HI`` -> ``(file, lines|None)``.

    Split from the right so a path that contains no line suffix is returned whole, and a trailing
    ``:N``/``:LO-HI`` is consumed only when it parses as numbers -- a colon in the name is not
    mistaken for a line spec.
    """
    head, sep, tail = value.rpartition(":")
    if sep and head:
        if "-" in tail:
            lo, _, hi = tail.partition("-")
            if lo.isdigit() and hi.isdigit():
                return head, (int(lo), int(hi))
        elif tail.isdigit():
            return head, (int(tail), int(tail))
    return value, None


def _stderr_stream():
    import sys
    return sys.stderr


def add_reader_verbs(subcommands) -> None:
    """Register enrich/analyze/candidates/explain on the top-level ``lachesis`` subparsers.

    Kept here (not in ``main``) so the verb set and its one implementation live together; ``main``
    only wires the dispatch. Each parser sets ``handler`` to its command function above.
    """
    enrich = subcommands.add_parser(
        "enrich", help="pass 2: warm the dataflow tier + catalog bind sidecars for a graph")
    enrich.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    enrich.add_argument("--overlay", help="optional overlay path")
    enrich.add_argument("--hard-stop", type=float, default=None, metavar="SECONDS",
                        dest="hard_stop",
                        help="wall-clock budget for the temporal bind (default: "
                             "LACHESIS_HARD_STOP or 180s; 0 = unbounded)")
    enrich.add_argument("--lifetime-workers", type=int, default=2, metavar="N",
                        help="object-summary worker processes (default: 2; use 1 for lower "
                             "memory/heat)")
    enrich.add_argument("--json", action="store_true", help="emit the report as JSON")
    enrich.set_defaults(handler=command_enrich)

    analyze = subcommands.add_parser(
        "analyze", help="pass 3: run the flow pass and query its leads")
    analyze.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    analyze.add_argument("--overlay", help="optional overlay path")
    analyze.add_argument("--summary", action="store_true",
                         help="the by-pattern rollup (the default when no filter is given)")
    analyze.add_argument("--pattern", help="show only this bug-shape pattern")
    analyze.add_argument("--function", help="show only leads in this function")
    analyze.add_argument("--at", metavar="FILE[:LINE|:LO-HI]",
                         help="locate leads by source position")
    analyze.add_argument("--engine", default="object", help="lifetime engine (default: object)")
    analyze.add_argument("--hard-stop", type=float, default=None, metavar="SECONDS",
                         dest="hard_stop", help="wall-clock budget (0 = unbounded)")
    analyze.add_argument("--lifetime-workers", type=int, default=2, metavar="N",
                         help="object-summary worker processes (default: 2; use 1 for lower "
                              "memory/heat)")
    analyze.add_argument("-o", "--out", metavar="PATH", help="persist the (filtered) leads as JSON")
    analyze.add_argument("--json", action="store_true", help="emit the result as JSON")
    analyze.set_defaults(handler=command_analyze)

    candidates = subcommands.add_parser(
        "candidates", help="the obligation registry across the whole taxonomy")
    candidates.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    candidates.add_argument("--overlay", help="optional overlay path")
    candidates.add_argument("--constructor", help="pin one family (default: every family)")
    candidates.add_argument("--domain", help="restrict to one domain")
    candidates.add_argument("--language", help="restrict to one language")
    candidates.add_argument("--limit", type=int, default=40, help="rows per family (default: 40)")
    candidates.add_argument("--detail", choices=("brief", "compact", "full"), default="compact")
    candidates.add_argument("--census", action="store_true",
                            help="report coverage counts instead of rows")
    candidates.add_argument("--no-temporal", action="store_true", dest="no_temporal",
                            help="structural families only -- the guaranteed-bounded fast path")
    candidates.add_argument("--hard-stop", type=float, default=None, metavar="SECONDS",
                            dest="hard_stop", help="wall-clock budget for the temporal families")
    candidates.add_argument("--json", action="store_true", help="emit the result as JSON")
    candidates.set_defaults(handler=command_candidates)

    explain = subcommands.add_parser(
        "explain", help="one-shot capsule for a candidate (by id, or by the sink's file:line)")
    explain.add_argument("graph", help="path to a built .kuzu graph (~ is expanded)")
    explain.add_argument("target", help="a candidate id (obl_.../life_...) or FILE:LINE")
    explain.add_argument("--overlay", help="optional overlay path")
    explain.add_argument("--no-temporal", action="store_true", dest="no_temporal",
                         help="structural families only -- the guaranteed-bounded fast path")
    explain.add_argument("--hard-stop", type=float, default=None, metavar="SECONDS",
                         dest="hard_stop", help="wall-clock budget for the temporal families")
    explain.add_argument("--json", action="store_true", help="emit the capsule as JSON")
    explain.set_defaults(handler=command_explain)
