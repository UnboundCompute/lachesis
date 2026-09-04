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
import json
import os
import sys
import time
from pathlib import Path

EXIT_OK = 0
EXIT_FINDINGS = 1      # scan found something and was asked to care
EXIT_USAGE = 2         # argparse's own
EXIT_ENVIRONMENT = 1   # a required tool or runtime is unavailable
EXIT_FAILURE = 1       # the build or the query broke

EPILOG = """\
CORE
  scan       point at a repository and get ranked leads
  explain    inspect the evidence for one lead
  mcp        serve the repository to an AI agent

GRAPH PIPELINE
  build      pass 1: create a named structural graph
  enrich     pass 2: warm native binary sidecars
  analyze    pass 3: inspect leads from a named graph
  trace      export a lachesis-explorer bundle.json for a repository

MORE
  candidates, query, plan, report, communities, doctor, cache, concept-model

examples:
  lachesis scan                     analyse the current directory and report findings
  lachesis scan ~/src/app --json    the same, as JSON, for a script
  lachesis mcp                      serve the current directory to an AI agent
  lachesis doctor                   check this machine can analyse what it has

Graphs are cached under ~/.lachesis/cache and rebuilt when the source changes,
so the first run of a project is slow and every run after it is not.
"""

_ANSI = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "cyan": "\033[36m",
    "yellow": "\033[33m",
}


class _RootParser(argparse.ArgumentParser):
    """Keep root help focused on the curated command groups in ``EPILOG``."""

    def format_help(self) -> str:
        text = super().format_help()
        start = text.find("positional arguments:\n")
        end = text.find("optional arguments:\n", start)
        if start >= 0 and end >= 0:
            text = text[:start] + text[end:]
        return text


def _stderr(message: str = "") -> None:
    print(message, file=sys.stderr)


def _color(text: str, tone: str, mode: str = "auto") -> str:
    """Apply terminal emphasis without ever putting ANSI escapes in piped data."""
    enabled = mode == "always" or (
        mode == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    )
    return f"{_ANSI[tone]}{text}{_ANSI['reset']}" if enabled else text


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


def _native_status() -> str:
    """Return a short native-kernel status for ``--version`` without doing analysis."""
    try:
        from lachesis.flow.native_lifetime import _library_candidates
        candidates = _library_candidates()
    except Exception:
        return "missing"
    configured = os.environ.get("LACHESIS_NATIVE_LIFETIME_LIB")
    if configured and Path(configured).is_file():
        return f"override:{configured}"
    if any("/lachesis/_native/" in str(path) and path.is_file() for path in candidates):
        return "bundled"
    if any(path.is_file() for path in candidates):
        return "dev-build"
    return "missing"


# ---------------------------------------------------------------------- completion

def command_completion(args: argparse.Namespace) -> int:
    """Print a dependency-free completion script for the selected shell."""
    commands = "scan explain mcp build enrich analyze candidates query plan trace report communities doctor cache completion"
    if args.shell == "bash":
        print(f'''_lachesis_complete() {{
  local cur="${{COMP_WORDS[COMP_CWORD]}}"
  local commands="{commands}"
  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
  elif [[ "${{COMP_WORDS[1]}}" == "scan" ]]; then
    COMPREPLY=( $(compgen -W "--lens --limit --min-rank --hard-stop --json --quiet --verbose --color --refresh" -- "$cur") )
  fi
}}
complete -F _lachesis_complete lachesis''')
    elif args.shell == "zsh":
        print(f'''#compdef lachesis
_arguments '1:command:({commands})' '*:option:(--lens --limit --min-rank --hard-stop --json --quiet --verbose --color --refresh)' ''')
    else:
        print(f'''complete -c lachesis -f -n "__fish_use_subcommand" -a "{commands}"
complete -c lachesis -n "__fish_seen_subcommand_from scan" -l lens -a "all guard-diff flow"
complete -c lachesis -n "__fish_seen_subcommand_from scan" -l json -l quiet -s q -l verbose -s v -l refresh''')
    return EXIT_OK


# --------------------------------------------------------------------- query / plan

def command_query(args: argparse.Namespace) -> int:
    """Run the structured graph query parser without a REMAINDER passthrough."""
    # Bind json at function entry. The except clause below references
    # json.JSONDecodeError, and a later `import json` inside the format branch
    # made json a function-local everywhere -- so a store-open failure hit the
    # except with json unbound and raised UnboundLocalError instead of the clean
    # one-line error every other verb gives on a bad graph path.
    import json
    from lachesis.cli import query
    values = vars(args).copy()
    values["command"] = values.pop("query_command")
    query_args = argparse.Namespace(**values)
    try:
        result = query.execute(query_args)
    except (KeyError, ValueError, json.JSONDecodeError, OSError) as error:
        _stderr(json.dumps({"error": str(error), "query": query_args.command}))
        return EXIT_FAILURE
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(query.render_text(result), end="")
    return EXIT_OK


def command_plan(args: argparse.Namespace) -> int:
    """Run the ranked guard-differential view from the parsed top-level command."""
    from lachesis.nav.graph_store import GraphStore
    from lachesis.planner.cli import _census_line, _render
    try:
        store = GraphStore.load(args.graph)
        store.ensure_dataflow_tier()
        from lachesis.planner.constructors import GuardDifferential
        result = GuardDifferential(store).run(limit_entrypoints=args.entrypoints)
    except Exception as error:  # noqa: BLE001 - CLI converts store errors to one line
        _stderr(f"lachesis plan: {error}")
        return EXIT_FAILURE
    _stderr(_census_line(result["census"]))
    if args.json:
        import json
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return EXIT_OK
    queue = result["queue"]
    shown = queue[:args.limit] if args.limit else queue
    for position, capsule in enumerate(shown, start=1):
        print(_render(capsule, position))
        print()
    if len(shown) < len(queue):
        print(f"... {len(queue) - len(shown)} more leads; --limit 0 prints them all")
    if args.suppressions:
        print("\nsuppressed, with the guard that did it:")
        for capsule in result["suppressions"]:
            names = ", ".join(g["predicate"] for g in capsule["guards_present"]
                               if g.get("dominates"))
            print(f"  {capsule['entrypoint']['symbol']} -> "
                  f"{capsule['sensitive_effect']['symbol']}: {names}")
    return EXIT_OK


# --------------------------------------------------------------------------- scan

def command_scan(args: argparse.Namespace) -> int:
    from lachesis.cli.source import resolve_source

    # A source may be a local path or a remote git URL (optionally ``url#subdir``
    # to scan one subtree of a monorepo). resolve_source fetches a URL into a
    # managed temp clone and returns a cleanup hook; a local path resolves in
    # place with a no-op cleanup. The analysis below only ever sees a local dir,
    # and cleanup runs on every exit path (findings, error, or exception).
    note = None if args.quiet else (lambda m: _stderr(f"  {m}"))
    try:
        resolved = resolve_source(args.path, note=note)
    except (RuntimeError, ValueError) as error:
        _stderr(f"lachesis: could not fetch source: {error}")
        return EXIT_USAGE
    try:
        return _scan_source(args, resolved.path)
    finally:
        resolved.cleanup()


def _scan_source(args: argparse.Namespace, source: Path) -> int:
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                      ensure_graph)
    from lachesis.cli.progress import Progress
    from lachesis.planner.cli import _census_line, _render

    # Progress narrates to stderr; with --json stdout has to stay a clean document, and
    # with --quiet the caller has said they want neither.
    progress = Progress(enabled=not args.quiet)
    if not args.quiet:
        _stderr(f"lachesis: {source}")
        if getattr(args, "_bare_invocation", False):
            _stderr("  scanning ./ — pass a path to scan elsewhere")
        if args.verbose:
            _stderr(f"  native-kernel: {_native_status()}")
    try:
        is_graph = source.is_dir() and (
            source.name.endswith(".kuzu")
            or (source / "lachesis-manifest.pb").is_file()
            or (source / "manifest.pb").is_file()
        )
        if is_graph and not args.refresh:
            graph_path = source
        else:
            graph_path, _ = ensure_graph(source, refresh=args.refresh, progress=progress,
                                         timeout_seconds=args.timeout)
    except EnvironmentProblem as error:
        return _report_environment(error)
    except NoSourceFound as error:
        _stderr(f"lachesis: {error}")
        return EXIT_USAGE

    from lachesis.nav.graph_store import GraphStore

    progress.phase("loading dataflow")
    store = GraphStore.load(str(graph_path))
    store.ensure_dataflow_tier()
    progress.done()

    if args.lens == "guard-diff":
        from lachesis.planner.constructors import GuardDifferential
        progress.phase("finding guard-differential leads")
        result = GuardDifferential(store).run(limit_entrypoints=args.entrypoints)
        queue = [row for row in result.get("queue", ())
                 if (row.get("rank") or 0.0) >= args.min_rank]
        census = result.get("census", {})
    elif args.lens == "flow":
        from lachesis.session import Analysis
        progress.phase("finding native flow leads")
        leads = Analysis(store).analyze(hard_stop=args.hard_stop)
        queue = [lead.to_dict() for lead in leads.top(args.limit or len(leads))
                 if (lead.rank or 0.0) >= args.min_rank]
        census = leads.summary()
        result = {"lens": args.lens, "queue": queue, "census": census}
    else:
        from lachesis.session import Analysis
        progress.phase("finding taxonomy leads")
        leads = Analysis(store).scan(
            lens="all", hard_stop=args.hard_stop,
            limit=None if args.limit == 0 else args.limit,
        )
        queue = [lead.to_dict() for lead in leads
                 if (lead.rank or 0.0) >= args.min_rank]
        census = leads.summary()
        result = {"lens": args.lens, "queue": queue, "census": census}
    progress.done()
    if args.json:
        import json
        payload = dict(result)
        payload.pop("queue", None)
        payload["leads"] = queue
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _stderr()
        if args.lens == "guard-diff":
            print(_census_line(census), file=sys.stderr)
        else:
            print(f"{len(queue)} leads  (lens={args.lens})", file=sys.stderr)
        shown = queue[:args.limit] if args.limit else queue
        for position, lead in enumerate(shown, start=1):
            if args.lens == "guard-diff":
                rendered = _render(lead, position)
            else:
                observations = lead.get("observations") or {}
                # Always surface the file. The old form printed `{symbol}:{line}` from
                # entry/callee only, so a temporal lead -- which carries no callee and no
                # entry -- rendered as a location-less `:6`, dropping the one coordinate a
                # reader needs to open it. Show `file:line` (the file is in observations),
                # keeping the symbol ahead of it when there is one.
                symbol = (lead.get("entry") or observations.get("callee")
                          or observations.get("site") or "")
                where = observations.get("file") or lead.get("file") or ""
                line = lead.get("line") or observations.get("line") or ""
                location = f"{where}:{line}" if where else f":{line}"
                rendered = (f"{position:>3}. [{(lead.get('rank') or 0.0):.3f}] "
                            f"{lead.get('pattern') or lead.get('constructor') or 'lead'}  "
                            f"{symbol + '  ' if symbol else ''}{location}")
            print(_color(rendered, "cyan", args.color))
            print()
        if len(shown) < len(queue):
            print(f"... {len(queue) - len(shown)} more; --limit 0 prints them all")
        if queue and not args.quiet:
            _stderr("Each of these is a question, not a verdict. To hand them to an "
                    "agent that can\nanswer them against the same graph, run: lachesis mcp")
    if args.fail_on_findings and queue:
        return EXIT_FINDINGS
    return EXIT_OK


# ----------------------------------------------------------------------- trace

def _repo_meta(source: Path) -> tuple[str | None, str | None]:
    """Best-effort (repo, commit) from git; either may be None."""
    import subprocess

    def git(*a: str) -> str | None:
        try:
            out = subprocess.run(["git", "-C", str(source), *a],
                                 capture_output=True, text=True, timeout=10)
            return (out.stdout.strip() or None) if out.returncode == 0 else None
        except Exception:
            return None

    commit = git("rev-parse", "--short", "HEAD")
    remote = git("config", "--get", "remote.origin.url")
    repo = None
    if remote:
        slug = remote.rstrip("/").removesuffix(".git")
        parts = slug.replace(":", "/").split("/")
        if len(parts) >= 2:
            repo = "/".join(parts[-2:])
    return repo, commit


def command_trace(args: argparse.Namespace) -> int:
    """Build (or reuse) a graph and export a lachesis-explorer bundle.json."""
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                      ensure_graph)
    from lachesis.cli.progress import Progress
    from lachesis.nav import bundle as bundle_mod

    source = _resolved(args.repo)
    progress = Progress(enabled=not args.quiet)
    if not args.quiet:
        _stderr(f"lachesis trace: {source}")
    try:
        is_graph = source.is_dir() and (
            source.name.endswith(".kuzu")
            or (source / "lachesis-manifest.pb").is_file()
            or (source / "manifest.pb").is_file()
        )
        if is_graph and not args.refresh:
            graph_path = source
        else:
            graph_path, _ = ensure_graph(source, refresh=args.refresh,
                                         progress=progress,
                                         timeout_seconds=args.timeout)
    except EnvironmentProblem as error:
        return _report_environment(error)
    except NoSourceFound as error:
        _stderr(f"lachesis trace: {error}")
        return EXIT_USAGE

    repo, commit = _repo_meta(source)
    progress.phase("exporting bundle")
    try:
        bundle = bundle_mod.build_bundle(
            str(graph_path),
            repo=args.repo_name or repo,
            commit=args.commit or commit,
            lang=args.lang,
            source_dir=str(source),
            per_family=args.per_family,
            max_flows=args.max_flows,
            schema_version=args.schema_version,
        )
    except Exception as error:  # noqa: BLE001 - CLI turns export errors into one line
        _stderr(f"lachesis trace: {error}")
        return EXIT_FAILURE
    progress.done()

    out = Path(args.out).expanduser()
    if out.parent and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
    graph = bundle["graph"]
    findings = bundle.get("findings") or (bundle.get("security") or {}).get("findings") or []
    _stderr(f"wrote {len(graph['nodes'])} nodes, {len(graph['edges'])} edges, "
            f"{len(findings)} findings -> {out}")
    return EXIT_OK


# ------------------------------------------------------------------- communities

def _load_store_for(args: argparse.Namespace, verb: str):
    """Index the tree if needed and load its store — the scan/mcp acquisition, shared."""
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound, ensure_graph)
    from lachesis.cli.progress import Progress
    from lachesis.nav.graph_store import GraphStore

    source = _resolved(args.path)
    quiet = getattr(args, "json", False) or getattr(args, "stdout", False)
    progress = Progress(enabled=not quiet)
    if not quiet:
        _stderr(f"lachesis {verb}: {source}")
    try:
        graph_path, _ = ensure_graph(source, refresh=args.refresh, progress=progress,
                                     timeout_seconds=args.timeout)
    except EnvironmentProblem as error:
        return None, _report_environment(error), source
    except NoSourceFound as error:
        _stderr(f"lachesis {verb}: {error}")
        return None, EXIT_USAGE, source
    progress.phase("loading graph")
    store = GraphStore.load(str(graph_path)).ensure_dataflow_tier()
    progress.done()
    return store, None, source


def command_communities(args: argparse.Namespace) -> int:
    store, failure, _ = _load_store_for(args, "communities")
    if store is None:
        return failure
    from lachesis.nav.communities import Communities
    comm = Communities(store.gl, include_dispatch=args.include_dispatch)
    result = comm.summary(n=args.limit or 20, members=args.members,
                          min_size=args.min_size)
    if args.json:
        import json
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return EXIT_OK
    _stderr()
    print(f"{result['communities']} subsystems over {result['nodes']} functions  "
          f"(modularity {result['modularity']})")
    if result["connectors_removed"]:
        names = ", ".join(f"{m['name']} ({m['degree']})" for m in result["connectors"])
        print(f"cross-cutting connectors lifted out: {names}")
    for r in result["partitions"]:
        print(f"\n  #{r['id']}  {r['label']}  "
              f"({r['size']} funcs, cohesion {r['cohesion']})")
        for m in r["members"]:
            print(f"      {m['degree']:4}  {m['name']}  {m['handle'] or ''}")
        if r["files"]:
            print(f"      spans: {', '.join(r['files'])}")
    return EXIT_OK


# ------------------------------------------------------------------------ report

def command_report(args: argparse.Namespace) -> int:
    store, failure, source = _load_store_for(args, "report")
    if store is None:
        return failure
    from lachesis.nav.report import build_report
    text = build_report(store, title=args.title or source.name)
    if args.stdout:
        print(text)
        return EXIT_OK
    from pathlib import Path
    out = Path(args.out)
    out.write_text(text, encoding="utf-8")
    _stderr()
    _stderr(f"wrote {out} ({len(text.splitlines())} lines)")
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
    sys.argv = ["lachesis mcp"]
    return mcp_server.main() or EXIT_OK


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
            try:
                entry.discard()
            except OSError as error:
                _stderr(f"could not remove the index for {entry.source_dir}: {error}")
                return EXIT_FAILURE
            _stderr(f"removed the index for {entry.source_dir} ({human_size(freed)})")
            return EXIT_OK
        if not args.all:
            _stderr("refusing to clear every cached index; pass --all to confirm")
            return EXIT_USAGE
        if not root.is_dir():
            _stderr("cache is already empty")
            return EXIT_OK
        # Only remove entries with a valid Lachesis metadata envelope. The cache
        # directory may be user-configured and can contain unrelated files; never
        # recursively delete those just because --all was requested.
        cached = entries()
        if not cached:
            _stderr(f"no recognized cached indexes under {root}; leaving it intact")
            return EXIT_OK
        freed = 0
        for entry in cached:
            size = directory_size(entry.directory)
            try:
                entry.discard()
            except OSError as error:
                _stderr(f"could not remove {entry.directory}: {error}")
                return EXIT_FAILURE
            freed += size
        try:
            root.rmdir()
        except OSError:
            # An unrelated file or directory remains; that is intentional and
            # safer than recursively deleting it.
            _stderr(f"removed {len(cached)} cached index(es) ({human_size(freed)}); "
                    f"left other files under {root}")
            return EXIT_OK
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
                try:
                    entry.discard()
                except OSError as error:
                    _stderr(f"could not remove {entry.directory}: {error}")
                    return EXIT_FAILURE
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


# -------------------------------------------------------------------------- build

def command_build(args: argparse.Namespace) -> int:
    """Build a named structural graph using the same implementation as the library."""
    from lachesis.cli import analyze

    forwarded = [args.source_dir, args.output_path, "--timeout", str(args.timeout)]
    if args.memory_budget_mb is not None:
        forwarded.extend(["--memory-budget-mb", str(args.memory_budget_mb)])
    if args.output_flag:
        forwarded.extend(["--output", args.output_flag])
    if args.frontend_out:
        forwarded.extend(["--frontend-out", args.frontend_out])
    if args.no_prune:
        forwarded.append("--no-prune")
    if args.incremental:
        forwarded.append("--incremental")
    if args.parallel_packages:
        forwarded.append("--parallel-packages")
    if args.max_workers is not None:
        forwarded.extend(["--max-workers", str(args.max_workers)])
    if args.shard_large_packages is not None:
        forwarded.extend(["--shard-large-packages", str(args.shard_large_packages)])
    if args.stream_shards:
        forwarded.extend(["--stream-shards", args.stream_shards])
    for included in getattr(args, "include_paths", None) or []:
        forwarded.extend(["--include", included])
    return analyze.main(forwarded)


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
        # A failed inventory means the requested diagnostic is incomplete. Returning
        # success would make CI and wrappers treat an inaccessible tree as healthy.
        return EXIT_FAILURE
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
    parser.add_argument("--timeout", type=_positive_seconds, default=300, metavar="SECONDS",
                        help="how long one frontend may run (default 300)")


def _positive_seconds(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer number of seconds") from error
    if seconds < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return seconds


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def _positive_int(value: str) -> int:
    parsed = _nonnegative_int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _rank(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number from 0.0 to 1.0") from error
    if not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be a number from 0.0 to 1.0")
    return parsed


def _positive_days(value: str) -> float:
    try:
        days = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number of days") from error
    if days <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return days


def build_parser() -> argparse.ArgumentParser:
    root = _RootParser(
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
                    "effects that no recognised guard covers. The source may be a "
                    "local path or a git URL (https://…, git@…, ….git), optionally "
                    "with a #subdir fragment to scan one subtree of a monorepo; a "
                    "URL is shallow-cloned to a temp dir and removed when done.")
    _add_source_flags(scan)
    # scan additionally accepts a remote URL in the same positional slot; the
    # other source commands stay local-only, so override just scan's help here.
    for _action in scan._actions:
        if _action.dest == "path":
            _action.help = ("directory or git URL to analyse (default: the current "
                            "directory); append #subdir to scan one subtree of a repo")
            break
    scan.add_argument("--limit", type=_nonnegative_int, default=20, metavar="N",
                      help="how many findings to print (0 = all, default 20)")
    scan.add_argument("--min-rank", type=_rank, default=0.0, metavar="R",
                      help="drop findings ranked below R (0.0-1.0)")
    scan.add_argument("--entrypoints", type=_nonnegative_int, default=0, metavar="N",
                      help="scan only the first N entrypoints (0 = all)")
    scan.add_argument("--lens", choices=("all", "guard-diff", "flow"), default="all",
                      help="analysis view: all families, guard differential, or flow leads")
    scan.add_argument("--hard-stop", type=float, default=None, metavar="SECONDS",
                      help="analysis budget (0 = unbounded; default is bounded)")
    scan.add_argument("--json", action="store_true",
                      help="write the full result to stdout as JSON")
    scan.add_argument("--error-on-findings", "--fail-on-findings", dest="fail_on_findings",
                      action="store_true",
                      help="exit 1 when anything is reported, for CI")
    scan.add_argument("--quiet", "-q", action="store_true",
                      help="findings only, no progress or guidance")
    scan.add_argument("--verbose", "-v", action="store_true",
                      help="include native-kernel details in progress output")
    scan.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                      help="colour human output (default: auto; NO_COLOR disables it)")
    scan.set_defaults(handler=command_scan)

    communities = subcommands.add_parser(
        "communities", help="partition a codebase into subsystems (call-graph clusters)",
        description="Index the tree if needed, then cluster the call graph into "
                    "subsystems that call each other more than the rest of the tree — "
                    "the structure the code has, independent of the directory layout.")
    _add_source_flags(communities)
    communities.add_argument("--limit", type=_nonnegative_int, default=20, metavar="N",
                             help="how many subsystems to print (default 20)")
    communities.add_argument("--members", type=_nonnegative_int, default=8, metavar="N",
                             help="members and files listed per subsystem (default 8)")
    communities.add_argument("--min-size", type=_nonnegative_int, default=2, metavar="N",
                             help="drop subsystems smaller than this (default 2)")
    communities.add_argument("--include-dispatch", action="store_true",
                             help="also cluster over indirect dispatch (C function "
                                  "pointers); noisy on duck-typed Python/TS")
    communities.add_argument("--json", action="store_true",
                             help="write the full result to stdout as JSON")
    communities.set_defaults(handler=command_communities)

    report = subcommands.add_parser(
        "report", help="write a Markdown architecture report for a codebase",
        description="Index the tree if needed, then assemble a one-page architecture "
                    "report — the spine, the subsystems, and where to start reading.")
    _add_source_flags(report)
    report.add_argument("-o", "--out", default="GRAPH_REPORT.md",
                        help="output path (default: GRAPH_REPORT.md)")
    report.add_argument("--title", default=None, help="report title (default: dir name)")
    report.add_argument("--stdout", action="store_true",
                        help="print the report instead of writing a file")
    report.set_defaults(handler=command_report)

    mcp = subcommands.add_parser(
        "mcp", help="serve a codebase to an AI agent over MCP",
        description="Index the tree if needed, then speak MCP on stdin/stdout. "
                    "Point an agent client at this command with no other arguments.")
    _add_source_flags(mcp)
    mcp.add_argument("--profile", choices=("all", "comprehension"), default=None,
                     help="'comprehension' hides hunting-only tools")
    mcp.set_defaults(handler=command_mcp)

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

    completion = subcommands.add_parser(
        "completion", help="print shell completion code")
    completion.add_argument("shell", choices=("bash", "zsh", "fish"),
                            help="shell to generate completion for")
    completion.set_defaults(handler=command_completion)

    # The reader verbs, each a thin shell over one Analysis method: enrich (pass 2),
    # analyze (pass 3 -> leads), candidates (the registry), explain (the one-shot capsule).
    # These are parsed, not passed through -- they are the ergonomic front door.
    from lachesis.cli.verbs import add_reader_verbs
    add_reader_verbs(subcommands)

    build = subcommands.add_parser(
        "build", help="pass 1: build a structural graph to a path you choose",
        description="Parse a source tree into the named binary graph artifact. "
                    "This is pass 1; enrichment is a separate `lachesis enrich` command.")
    build.add_argument("source_dir", help="source tree to analyse")
    build.add_argument("output_path", nargs="?", default="graph_out/compiler_project.kuzu",
                       help="graph store to write")
    build.add_argument("-o", "--output", dest="output_flag", metavar="PATH",
                       help="same as the output path positional")
    build.add_argument("--frontend-out", metavar="DIR",
                       help="retain frontend bundles for inspection or incremental builds")
    build.add_argument("--no-prune", action="store_true",
                       help="keep lexical token/proof records (pruned by default)")
    build.add_argument("--timeout", type=_positive_seconds, default=300, metavar="SECONDS",
                       help="maximum seconds per frontend (default: 300)")
    build.add_argument("--memory-budget-mb", type=_positive_int, default=None, metavar="MiB",
                       help="total memory budget for the build process tree (default 5120). "
                            "Sizes the frontend chunking so a Linux-scale tree builds without "
                            "OOM; the emitted graph is identical at any budget. Same as "
                            "LACHESIS_MEMORY_BUDGET_MB; the flag wins.")
    build.add_argument("--incremental", action="store_true",
                       help="reuse unchanged frontend bundles")
    build.add_argument("--parallel-packages", action="store_true",
                       help="compile first-party packages independently")
    build.add_argument("--max-workers", type=_positive_int, default=None, metavar="N",
                       help="cap parallel package workers")
    build.add_argument("--shard-large-packages", type=_positive_int, default=None,
                       metavar="FILES", help="split large packages into bounded jobs")
    build.add_argument("--stream-shards", metavar="DIR",
                       help="stream frontend shards directly into the graph store")
    build.add_argument("--include", metavar="PATH", action="append", dest="include_paths",
                       help="also analyse this file or directory even if it is outside "
                            "source_dir (repeatable); point it at an advisory's file so a "
                            "narrowed scope never excludes the file the run must reach")
    build.set_defaults(handler=command_build, no_prune=False)

    trace = subcommands.add_parser(
        "trace", help="build a graph and export a lachesis-explorer bundle.json",
        description="Point at a repository (or an existing .kuzu graph) and write a "
                    "lachesis-explorer bundle.json: the sink families the graph carries, "
                    "each with the reachability cone that feeds it, in the shape the "
                    "explorer renders. Every flow is a fact, not a verdict.")
    trace.add_argument("repo", nargs="?", default=".",
                       help="source tree or existing graph to trace (default: .)")
    trace.add_argument("--repo", dest="repo", metavar="PATH",
                       help="same as the positional repo argument")
    trace.add_argument("-o", "--out", default="bundle.json", metavar="FILE",
                       help="bundle path to write (default: bundle.json)")
    trace.add_argument("--repo-name", metavar="OWNER/REPO",
                       help="override the repo slug recorded in bundle meta")
    trace.add_argument("--commit", metavar="SHA", help="override the commit in meta")
    trace.add_argument("--lang", metavar="LANG", help="override the language in meta")
    trace.add_argument("--schema-version", choices=("1.0", "2.0"), default="2.0",
                       help="Explorer bundle contract to emit (default: 2.0 graph-first)")
    trace.add_argument("--per-family", type=_positive_int, default=6, metavar="N",
                       help="max leads to draw from each sink family (default: 6)")
    trace.add_argument("--max-flows", type=_positive_int, default=40, metavar="N",
                       help="max flows in the bundle (default: 40)")
    trace.add_argument("--timeout", type=_positive_seconds, default=600, metavar="SECONDS",
                       help="maximum seconds per frontend when building (default: 600)")
    trace.add_argument("--refresh", action="store_true",
                       help="rebuild the graph even if a current cache exists")
    trace.add_argument("--quiet", "-q", action="store_true",
                       help="suppress progress narration on stderr")
    trace.set_defaults(handler=command_trace)

    query = subcommands.add_parser(
        "query", help="ask a focused question of a named graph",
        description="Query a named graph with a bounded, structured question.")
    query.add_argument("graph", help="path to a .kuzu graph")
    query.add_argument("--budget-tokens", type=_positive_int, default=12000,
                       metavar="N", help="approximate answer budget")
    # Default to text like every other verb (scan/analyze/candidates emit text unless
    # --json). query alone used to default to json, which surprised a reader who ran it
    # after the others; pass --format json to restore the machine-readable document.
    query.add_argument("--format", choices=("json", "text"), default="text",
                       help="output format (default: text; use json for a machine-readable slice)")
    query_commands = query.add_subparsers(dest="query_command", metavar="<question>",
                                          required=True)
    query_commands.add_parser("overview", help="summarize the graph")
    locate = query_commands.add_parser("locate", help="locate a node id")
    locate.add_argument("node_id")
    expand = query_commands.add_parser("expand", help="expand a node neighbourhood")
    expand.add_argument("node_id")
    expand.add_argument("--depth", type=_nonnegative_int, default=1)
    find = query_commands.add_parser("find-entity", help="find a symbol")
    find.add_argument("name")
    find.add_argument("--kind")
    find.add_argument("--file")
    function = query_commands.add_parser("function", help="read one function slice")
    function.add_argument("focus")
    function.add_argument("--file")
    value = query_commands.add_parser("value-history", help="trace a value")
    value.add_argument("node_id")
    call = query_commands.add_parser("call", help="explain a call")
    call.add_argument("node_id")
    security = query_commands.add_parser("security-path", help="read one security path")
    security.add_argument("node_id")
    query_commands.add_parser("security-paths", help="read security path slices")
    handler = query_commands.add_parser("handler-security", help="read handler security")
    handler.add_argument("focus")
    handler.add_argument("--file")
    unresolved = query_commands.add_parser("unresolved", help="read unresolved calls")
    unresolved.add_argument("node_id", nargs="?")
    # Accept the common `query GRAPH QUESTION --format json` spelling as well as the
    # parent-option form. SUPPRESS prevents a child default from overwriting the parent.
    for question in query_commands.choices.values():
        question.add_argument("--format", choices=("json", "text"),
                              default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        question.add_argument("--budget-tokens", type=_positive_int, metavar="N",
                              default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    query.set_defaults(handler=command_query)

    plan = subcommands.add_parser(
        "plan", help="rank guard-differential leads from a named graph",
        description="Rank leads from a named graph. Each lead is a question, not a verdict.")
    plan.add_argument("graph", help="path to a .kuzu graph")
    plan.add_argument("--limit", type=_nonnegative_int, default=20,
                      help="how many leads to print (0 = all)")
    plan.add_argument("--entrypoints", type=_nonnegative_int, default=0, metavar="N",
                      help="scan only the first N entrypoints (0 = all)")
    plan.add_argument("--json", action="store_true", help="print the result as JSON")
    plan.add_argument("--suppressions", action="store_true",
                      help="print what was suppressed and which guard did it")
    plan.set_defaults(handler=command_plan)

    return root


KNOWN_COMMANDS = {
    "scan", "communities", "report", "mcp", "cache", "doctor",
    "concept-model", "enrich", "analyze", "candidates", "explain", "build",
    "query", "plan", "completion", "trace",
}


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    # A path is the product's default command: `lachesis ./repo` is exactly
    # `lachesis scan ./repo`, and a bare invocation scans the current directory.
    if not arguments:
        arguments = ["scan"]
        bare_invocation = True
    else:
        bare_invocation = False
    if arguments and arguments[0] == "index":
        _stderr("lachesis: 'index' was removed; use 'lachesis build <path>' "
                "or run 'lachesis scan <path>' to index on demand")
        return EXIT_USAGE
    elif (not arguments[0].startswith("-")
          and arguments[0] not in KNOWN_COMMANDS):
        arguments = ["scan", *arguments]
    parser = build_parser()
    args = parser.parse_args(arguments)
    args._bare_invocation = bare_invocation
    if getattr(args, "version", False):
        from lachesis.cache import _version
        print(f"lachesis {_version()} (native-kernel: {_native_status()})")
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
