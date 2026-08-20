"""Manifest-aware end-to-end flow runner used by ``lachesis run``.

This is deliberately a product-layer adapter.  The graph builder remains unchanged:
the manifest is loaded beside the target, graph-checkable facts are validated, the
existing flow pass consumes the facts it understands, and source exclusions are
applied only after a lead's entry function has been resolved back to its file.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from lachesis.manifest.loader import discover_manifest, load_manifest
from lachesis.manifest.validate import validate_manifest


def _manifest_path(start: Path, explicit: str | None) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            path = start / path
        path = path.resolve()
    else:
        path = discover_manifest(start)
    if path is None:
        raise ValueError(
            f"no lachesis.toml found at or above {start}; add one or pass --manifest"
        )
    return path


def _graph_path(value: str, manifest_path: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = manifest_path.parent / path
    return path.resolve()


def _relative_file(file: str, project_root: Path) -> str:
    path = Path(file)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(project_root)
        except ValueError:
            return path.as_posix()
    return path.as_posix().lstrip("./")


def _matches_exclude(file: str, patterns: tuple[str, ...]) -> bool:
    """Match both directory shorthand (``tests``) and portable glob spelling.

    ``fnmatch`` does not make a leading ``**/`` optional, so test both the declared
    pattern and its root-level form.  This makes ``**/vendor/**`` cover ``vendor/x.c``
    as well as ``lib/vendor/x.c`` without introducing a filesystem walk.
    """
    file = file.replace("\\", "/").lstrip("./")
    for raw in patterns:
        pattern = raw.replace("\\", "/").strip().lstrip("./").rstrip("/")
        if not pattern:
            continue
        if not any(mark in pattern for mark in "*?["):
            if file == pattern or file.startswith(pattern + "/"):
                return True
            continue
        variants = {pattern}
        if pattern.startswith("**/"):
            variants.add(pattern[3:])
        if any(fnmatch.fnmatchcase(file, variant) for variant in variants):
            return True
    return False


def _entry_files(store, entry: str, project_root: Path) -> list[str]:
    candidates = [item for item in store.resolve(entry)
                  if item.get("name") == entry and item.get("file")]
    definitions = [item for item in candidates if not item.get("declaration_only")]
    chosen = definitions or candidates
    return sorted({_relative_file(str(item["file"]), project_root) for item in chosen})


def scope_leads(leads, store, project_root: Path, exclude: tuple[str, ...]):
    """Attach entry files and return ``(kept, excluded)``.

    A homonymous entry may resolve to more than one file.  Such a lead is excluded only
    when every possible definition is excluded; uncertainty must not suppress signal.
    """
    kept, dropped = [], []
    for original in leads:
        lead = dict(original)
        files = _entry_files(store, str(lead.get("entry", "")), project_root)
        if files:
            lead["files"] = files
            if len(files) == 1:
                lead["file"] = files[0]
        if files and all(_matches_exclude(file, exclude) for file in files):
            dropped.append(lead)
        else:
            kept.append(lead)
    return kept, dropped


def _report_dict(report) -> dict:
    def item(check):
        return {"location": check.location, "symbol": check.symbol,
                "status": check.status.value, "detail": check.detail}
    return {
        "validated": len(report.validated),
        "external": len(report.external),
        "warnings": len(report.warnings),
        "checks": [item(check) for check in report.checks],
    }


def execute_manifest_run(source: Path, manifest_path: Path, graph_path: Path, store) -> dict:
    """Validate and run an already-opened store; split out for focused tests."""
    from lachesis.flow.pipeline import run_pass

    manifest = load_manifest(manifest_path)
    validation = validate_manifest(manifest, store)
    bundle = run_pass(store, lang=manifest.project.language, manifest=manifest)
    exclude = manifest.project.source.exclude
    leads, excluded = scope_leads(
        bundle["leads"], store, manifest_path.parent.resolve(), exclude)

    applied = bundle["lifetime"].setdefault("applied_config", {})
    applied["analysis.graph"] = str(graph_path)
    if exclude:
        applied["project.source.exclude"] = (
            f"{list(exclude)} excluded {len(excluded)} of "
            f"{len(leads) + len(excluded)} lead(s) after entry-to-file resolution"
        )

    diagnostics = bundle["lifetime"].get("diagnostics", {})
    semantic = bundle["lifetime"].get("semantic_warnings", [])
    summary = {
        "project": manifest.project.name or source.name,
        "manifest": str(manifest_path),
        "graph": str(graph_path),
        "language": manifest.project.language,
        "functions": len(bundle["F"]),
        "skeletons": len(bundle["skeletons"]),
        "leads": len(leads),
        "excluded_leads": len(excluded),
        "excluded_patterns": list(exclude),
        "applied_config": dict(applied),
        "manifest_validation": _report_dict(validation),
        "semantic_warnings": semantic,
        "coverage": {
            key: diagnostics[key] for key in (
                "functions", "analyzed", "capped", "summary_capped",
                "cfg_failures", "unplaced", "unsafe_functions",
            ) if key in diagnostics
        },
        "timings": bundle.get("timings", {}),
    }
    return {"run_summary": summary, "leads": leads}


def command_run(args) -> int:
    """CLI handler.  Imports the Kuzu-backed pieces lazily for loader-only installs."""
    from lachesis.cli.indexer import (EnvironmentProblem, NoSourceFound,
                                      ensure_graph)
    from lachesis.cli.main import (_report_environment, _stderr, EXIT_OK,
                                   EXIT_USAGE)
    from lachesis.cli.progress import Progress
    from lachesis.nav.graph_store import GraphStore

    source = Path(args.path or ".").expanduser().resolve()
    manifest_path = _manifest_path(source, args.manifest)
    manifest = load_manifest(manifest_path)
    progress = Progress(enabled=not args.quiet)
    if not args.quiet:
        _stderr(f"lachesis run: {source}")
        _stderr(f"manifest: {manifest_path}")

    if manifest.analysis.graph:
        graph_path = _graph_path(manifest.analysis.graph, manifest_path)
        if not graph_path.exists():
            raise ValueError(f"analysis.graph does not exist: {graph_path}")
    else:
        try:
            graph_path, _ = ensure_graph(
                source, refresh=args.refresh, progress=progress,
                timeout_seconds=args.timeout)
        except EnvironmentProblem as error:
            return _report_environment(error)
        except NoSourceFound as error:
            _stderr(f"lachesis run: {error}")
            return EXIT_USAGE

    payload = execute_manifest_run(
        source, manifest_path, graph_path, GraphStore.load(str(graph_path)))
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _render(payload)
    return EXIT_OK


def _render(payload: dict) -> None:
    summary = payload["run_summary"]
    validation = summary["manifest_validation"]
    print(
        f"run summary: {summary['leads']} lead(s) over {summary['functions']} "
        f"function(s); {summary['excluded_leads']} excluded"
    )
    print(
        f"manifest: {validation['validated']} grounded, "
        f"{validation['external']} external, {validation['warnings']} warning(s)"
    )
    for check in validation["checks"]:
        if check["status"] == "warning":
            print(f"  ! {check['location']} '{check['symbol']}' — {check['detail']}")
    for warning in summary["semantic_warnings"]:
        print(f"  ! {warning['location']} '{warning['symbol']}' — {warning['detail']}")
    print("applied config:")
    if summary["applied_config"]:
        for key, value in summary["applied_config"].items():
            print(f"  {key}: {value}")
    else:
        print("  (defaults)")
    coverage = summary["coverage"]
    if coverage:
        print("coverage: " + ", ".join(f"{key}={value}" for key, value in coverage.items()))
    for lead in payload["leads"]:
        where = lead.get("file") or ",".join(lead.get("files", ())) or lead.get("entry", "?")
        if lead.get("line") is not None:
            where += f":{lead['line']}"
        print(f"  {lead['pattern']}: {where} ({lead.get('entry', '?')})")
