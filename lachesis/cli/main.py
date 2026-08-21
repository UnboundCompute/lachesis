#!/usr/bin/env python3
"""The `lachesis` command: one verb, a directory, an answer.

The engine's own tools take a graph path, a store manifest, an overlay and a profile,
because that is what they operate on. None of that is a thing a person arrives wanting.
This surface is arranged around what they do arrive wanting — "tell me about this
repository" and "let my agent read this repository" — and it treats the graph as an
implementation detail of answering, which is what it is.

The engine tools remain, unchanged, one word further in: `lachesis analyze`, `query`
and `plan` are the same programs for the case where somebody genuinely wants to hold
the artifact. The split is deliberate. Depth stays available; it just stops being the
first thing anyone meets.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

EXIT_OK = 0
EXIT_FINDINGS = 1      # scan found something and was asked to care
EXIT_USAGE = 2         # argparse's own
EXIT_ENVIRONMENT = 3   # a tool this machine does not have
EXIT_FAILURE = 4       # the build or the query broke

EPILOG = """\
examples:
  lachesis scan                     analyse the current directory and report findings
  lachesis scan ~/src/app --json    the same, as JSON, for a script
  lachesis mcp                      serve the current directory to an AI agent
  lachesis doctor                   check this machine can analyse what it has

Graphs are cached under ~/.lachesis/cache and rebuilt when the source changes,
so the first run of a project is slow and every run after it is not.
"""


def _stderr(message: str = "") -> None:
    print(message, file=sys.stderr)


def _report_environment(error) -> int:
    _stderr("lachesis cannot analyse this tree yet:")
    for check in error.checks:
        _stderr(f"  ✗ {check.name}: {check.detail}")
        if check.fix:
            _stderr(f"    → {check.fix}")
    _stderr()
    _stderr("`lachesis doctor` reports everything this machine has and is missing.")
    return EXIT_ENVIRONMENT


def _resolved(path: str | None) -> Path:
    return Path(path or ".").expanduser().resolve()


# --------------------------------------------------------------------------- scan

def command_scan(args: argparse.Namespace) -> int:
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                      ensure_graph)
    from lachesis.cli.progress import Progress
    from lachesis.planner.cli import _census_line, _render

    source = _resolved(args.path)
    # Progress narrates to stderr; with --json stdout has to stay a clean document, and
    # with --quiet the caller has said they want neither.
    progress = Progress(enabled=not args.quiet)
    if not args.quiet:
        _stderr(f"lachesis: {source}")
    try:
        graph_path, _ = ensure_graph(source, refresh=args.refresh, progress=progress,
                                     timeout_seconds=args.timeout)
    except EnvironmentProblem as error:
        return _report_environment(error)
    except NoSourceFound as error:
        _stderr(f"lachesis: {error}")
        return EXIT_USAGE

    from lachesis.nav.graph_store import GraphStore
    from lachesis.planner.constructors import GuardDifferential

    progress.phase("loading dataflow")
    store = GraphStore.load(str(graph_path))
    store.ensure_dataflow_tier()
    progress.done()

    progress.phase("finding entrypoints that reach sensitive effects")
    result = GuardDifferential(store).run(limit_entrypoints=args.entrypoints)
    progress.done()

    queue = [capsule for capsule in result["queue"] if capsule["rank"] >= args.min_rank]
    if args.json:
        import json
        payload = dict(result)
        payload["queue"] = queue
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _stderr()
        print(_census_line(result["census"]), file=sys.stderr)
        shown = queue[:args.limit] if args.limit else queue
        for position, capsule in enumerate(shown, start=1):
            print(_render(capsule, position))
            print()
        if len(shown) < len(queue):
            print(f"... {len(queue) - len(shown)} more; --limit 0 prints them all")
        if queue and not args.quiet:
            _stderr("Each of these is a question, not a verdict. To hand them to an "
                    "agent that can\nanswer them against the same graph, run: lachesis mcp")
    if args.fail_on_findings and queue:
        return EXIT_FINDINGS
    return EXIT_OK


# ---------------------------------------------------------------------------- mcp

def command_mcp(args: argparse.Namespace) -> int:
    """Index if needed, then speak MCP on stdio.

    The chicken-and-egg this removes: the server used to require a graph path, but a
    graph only exists after a build the user had to know to run. Here the directory is
    enough, and an agent client's config is a command with no paths in it at all.
    """
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                      ensure_graph)
    from lachesis.cli.progress import Progress
    from lachesis.nav import mcp_server

    source = _resolved(args.path)
    # stdout is the JSON-RPC channel from the first byte, so every human-facing word
    # here goes to stderr — which is exactly where an MCP client shows server logs.
    progress = Progress(enabled=True)
    _stderr(f"lachesis mcp: {source}")
    try:
        graph_path, _ = ensure_graph(source, refresh=args.refresh, progress=progress,
                                     timeout_seconds=args.timeout)
    except EnvironmentProblem as error:
        return _report_environment(error)
    except NoSourceFound as error:
        _stderr(f"lachesis mcp: {error}")
        return EXIT_USAGE

    # The server reads its configuration from argv/env, so hand it a graph the same way
    # a person would have, rather than reaching into its module state.
    os.environ["LACHESIS_GRAPH"] = str(graph_path)
    if args.profile:
        os.environ["LACHESIS_PROFILE"] = args.profile
    sys.argv = ["lachesis-mcp"]
    return mcp_server.main() or EXIT_OK


# -------------------------------------------------------------------------- index

def command_index(args: argparse.Namespace) -> int:
    from lachesis.cache import directory_size, entry_for, human_size
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                      ensure_graph)
    from lachesis.cli.progress import Progress

    source = _resolved(args.path)
    _stderr(f"lachesis index: {source}")
    try:
        graph_path, rebuilt = ensure_graph(source, refresh=args.refresh,
                                           progress=Progress(enabled=True),
                                           timeout_seconds=args.timeout)
    except EnvironmentProblem as error:
        return _report_environment(error)
    except NoSourceFound as error:
        _stderr(f"lachesis index: {error}")
        return EXIT_USAGE
    entry = entry_for(source)
    meta = entry.meta() or {}
    _stderr()
    _stderr(f"  {'built' if rebuilt else 'already current'}: "
            f"{meta.get('nodes', 0):,} nodes, {meta.get('edges', 0):,} edges, "
            f"{human_size(directory_size(entry.directory))}")
    _stderr(f"  {graph_path}")
    return EXIT_OK


# -------------------------------------------------------------------------- cache

def command_cache(args: argparse.Namespace) -> int:
    from lachesis.cache import (cache_root, directory_size, entries,
                                human_size)

    if args.cache_action == "clear":
        root = cache_root()
        if args.path:
            from lachesis.cache import entry_for
            entry = entry_for(args.path)
            if not entry.directory.is_dir():
                _stderr(f"nothing cached for {entry.source_dir}")
                return EXIT_OK
            freed = directory_size(entry.directory)
            entry.discard()
            _stderr(f"removed the index for {entry.source_dir} ({human_size(freed)})")
            return EXIT_OK
        if not args.all:
            _stderr("refusing to clear every cached index; pass --all to confirm")
            return EXIT_USAGE
        if not root.is_dir():
            _stderr("cache is already empty")
            return EXIT_OK
        freed = directory_size(root)
        shutil.rmtree(root, ignore_errors=True)
        _stderr(f"removed every cached index ({human_size(freed)})")
        return EXIT_OK

    found = entries()
    if args.cache_action == "prune":
        cutoff = time.time() - (args.older_than * 86400)
        candidates = []
        for entry in found:
            meta = entry.meta() or {}
            missing_source = not entry.source_dir.is_dir()
            old = float(meta.get("built_at", 0.0)) <= cutoff
            if missing_source or old:
                reason = "source missing" if missing_source else (
                    f"older than {args.older_than:g} days"
                )
                candidates.append((entry, reason))
        if not candidates:
            _stderr("no cache entries match the prune policy")
            return EXIT_OK
        total = 0
        for entry, reason in candidates:
            size = directory_size(entry.directory)
            total += size
            action = "would remove" if not args.apply else "removed"
            _stderr(f"{action} {human_size(size):>8}  {reason}: {entry.source_dir}")
            if args.apply:
                entry.discard()
        action = "would reclaim" if not args.apply else "reclaimed"
        _stderr(f"{action} {human_size(total)} across {len(candidates)} index(es)")
        return EXIT_OK

    if not found:
        _stderr(f"no cached indexes (cache lives in {cache_root()})")
        return EXIT_OK
    for entry in found:
        meta = entry.meta() or {}
        state = "gone" if not entry.source_dir.is_dir() else entry.status()
        _stderr(f"  {state:<7} {human_size(directory_size(entry.directory)):>8}  "
                f"{meta.get('nodes', 0):>9,} nodes  {entry.source_dir}")
    _stderr()
    _stderr(f"  {len(found)} index(es), "
            f"{human_size(directory_size(cache_root()))} in {cache_root()}")
    return EXIT_OK


# ------------------------------------------------------------------------- doctor

def command_doctor(args: argparse.Namespace) -> int:
    from lachesis.cli.doctor import full_report, languages_present

    _stderr("lachesis doctor")
    _stderr()
    report = full_report()
    for check in report:
        _stderr(f"  {check.mark} {check.name:<11} {check.detail}")
        if not check.ok and check.fix:
            _stderr(f"    → {check.fix}")
    _stderr()
    here = _resolved(args.path)
    try:
        present = languages_present(here)
    except Exception as error:  # noqa: BLE001 - a doctor must not itself crash
        _stderr(f"  could not inventory {here}: {error}")
        return EXIT_OK
    if present:
        _stderr(f"  {here} contains: {', '.join(sorted(present))}")
    else:
        _stderr(f"  {here} contains no source any frontend reads")
    blocked = [check for check in report if not check.ok and check.required]
    if blocked:
        _stderr()
        _stderr("  this install is not usable until the ✗ items above are resolved")
        return EXIT_ENVIRONMENT
    return EXIT_OK


# ------------------------------------------------------------------ concept model

def command_concept_model(args: argparse.Namespace) -> int:
    """Inspect or explicitly download the optional local embedding model."""
    import json
    from lachesis.nav.concept import download_model, model_status

    if args.model_action == "download":
        try:
            result = download_model(args.model)
        except RuntimeError as error:
            _stderr(f"lachesis: {error}")
            return EXIT_ENVIRONMENT
    else:
        result = model_status(args.model)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _stderr(f"concept runtime: {result['runtime']}")
        _stderr(f"concept model:   {result['model']} "
                f"({'ready' if result['model_ready'] else 'not downloaded'})")
        _stderr(f"model cache:     {result['cache']}")
        if result["runtime"] != "installed":
            _stderr(f"install runtime: {result['install']}")
        if not result["model_ready"]:
            _stderr(f"download model:  {result['download']}")
    return EXIT_OK


# ------------------------------------------------------------------------ parsing

def _add_source_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".",
                        help="directory to analyse (default: the current one)")
    parser.add_argument("--refresh", action="store_true",
                        help="rebuild the index even if the source has not changed")
    parser.add_argument("--timeout", type=int, default=300, metavar="SECONDS",
                        help="how long one frontend may run (default 300)")


def _positive_days(value: str) -> float:
    try:
        days = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number of days") from error
    if days <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return days


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="lachesis",
        description="Read a codebase the way a compiler does.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument("--version", action="store_true",
                      help="print the installed version and exit")
    subcommands = root.add_subparsers(dest="command", metavar="<command>")

    scan = subcommands.add_parser(
        "scan", help="report what an attacker could reach in a codebase",
        description="Index the tree if needed, then rank the reachable sensitive "
                    "effects that no recognised guard covers.")
    _add_source_flags(scan)
    scan.add_argument("--limit", type=int, default=20, metavar="N",
                      help="how many findings to print (0 = all, default 20)")
    scan.add_argument("--min-rank", type=float, default=0.0, metavar="R",
                      help="drop findings ranked below R (0.0-1.0)")
    scan.add_argument("--entrypoints", type=int, default=0, metavar="N",
                      help="scan only the first N entrypoints (0 = all)")
    scan.add_argument("--json", action="store_true",
                      help="write the full result to stdout as JSON")
    scan.add_argument("--fail-on-findings", action="store_true",
                      help="exit 1 when anything is reported, for CI")
    scan.add_argument("--quiet", "-q", action="store_true",
                      help="findings only, no progress or guidance")
    scan.set_defaults(handler=command_scan)

    mcp = subcommands.add_parser(
        "mcp", help="serve a codebase to an AI agent over MCP",
        description="Index the tree if needed, then speak MCP on stdin/stdout. "
                    "Point an agent client at this command with no other arguments.")
    _add_source_flags(mcp)
    mcp.add_argument("--profile", choices=("all", "comprehension"), default=None,
                     help="'comprehension' hides hunting-only tools")
    mcp.set_defaults(handler=command_mcp)

    index = subcommands.add_parser(
        "index", help="build or refresh the index for a codebase",
        description="Do the slow part now, so a later scan or mcp session is instant.")
    _add_source_flags(index)
    index.set_defaults(handler=command_index)

    cache = subcommands.add_parser("cache", help="inspect or delete cached indexes")
    cache_actions = cache.add_subparsers(dest="cache_action", metavar="<action>")
    cache_actions.add_parser("list", help="what is cached, and whether it is current")
    clear = cache_actions.add_parser("clear", help="delete cached indexes")
    clear.add_argument("path", nargs="?", default=None,
                       help="a project to forget")
    clear.add_argument("--all", action="store_true",
                       help="delete every cached index (required without a project path)")
    prune = cache_actions.add_parser(
        "prune", help="remove missing or old indexes (dry-run unless --apply)")
    prune.add_argument("--older-than", type=_positive_days, default=30.0,
                       metavar="DAYS", help="age threshold (default: 30 days)")
    prune.add_argument("--apply", action="store_true",
                       help="actually delete matching entries")
    cache.set_defaults(handler=command_cache, cache_action="list", path=None)

    doctor = subcommands.add_parser(
        "doctor", help="check this machine can analyse what it has")
    doctor.add_argument("path", nargs="?", default=".",
                        help="directory to report on (default: the current one)")
    doctor.set_defaults(handler=command_doctor)

    concept = subcommands.add_parser(
        "concept-model", help="manage the optional local concept-search model")
    concept_actions = concept.add_subparsers(dest="model_action", metavar="<action>")
    for action in ("status", "download"):
        action_parser = concept_actions.add_parser(action)
        action_parser.add_argument("--model", default="BAAI/bge-small-en-v1.5")
        action_parser.add_argument("--json", action="store_true")
    concept.set_defaults(handler=command_concept_model, model_action="status",
                         model="BAAI/bge-small-en-v1.5", json=False)

    # The engine's own programs, one word in. Their arguments are passed through
    # untouched, which is why these take REMAINDER rather than a parsed shape: they
    # are a different, lower-level surface and should behave exactly as documented
    # for themselves.
    for name, help_text in (
        ("analyze", "engine: build a graph to a path you choose"),
        ("query", "engine: query a graph directly"),
        ("plan", "engine: rank capsules from a graph you already have"),
    ):
        passthrough = subcommands.add_parser(
            name, help=help_text, add_help=False,
            description=f"{help_text}. Arguments are passed through unchanged; "
                        f"run `lachesis {name} --help` for its own options.")
        passthrough.add_argument("rest", nargs=argparse.REMAINDER)

    return root


ENGINE_COMMANDS = ("analyze", "query", "plan")


def _run_engine(name: str, rest: list[str]) -> int:
    """Hand the rest of the line to an engine program verbatim.

    Dispatched before argparse touches anything: a REMAINDER positional still loses
    `--help` to the root parser, and an engine tool whose own `--help` is unreachable
    is not really available. So these three words are routed, not parsed.
    """
    from lachesis.cli import analyze, query
    from lachesis.planner import cli as planner_cli
    sys.argv = [f"lachesis-{name}", *rest]
    if name == "analyze":
        return analyze.main()
    return (query.main() if name == "query" else planner_cli.main()) or EXIT_OK


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments and arguments[0] in ENGINE_COMMANDS:
        return _run_engine(arguments[0], arguments[1:])
    parser = build_parser()
    args = parser.parse_args(arguments)
    if getattr(args, "version", False):
        from lachesis.cache import _version
        print(_version())
        return EXIT_OK
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        return handler(args)
    except KeyboardInterrupt:
        _stderr("\ninterrupted")
        return 130
    except BrokenPipeError:
        # `lachesis scan | head` is a normal thing to do and is not an error.
        return EXIT_OK
    except Exception as error:  # noqa: BLE001 - the top of a command line
        if os.environ.get("LACHESIS_TRACEBACK"):
            raise
        _stderr(f"lachesis: {type(error).__name__}: {error}")
        _stderr("set LACHESIS_TRACEBACK=1 for the full traceback")
        return EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
