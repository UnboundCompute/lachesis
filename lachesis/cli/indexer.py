#!/usr/bin/env python3
"""Turn a directory into a ready graph, reusing one when the source has not changed.

This is the step the product surface hides. Everything above it says "a directory" and
gets back a store path it never has to think about; the decision of whether that meant
seconds or minutes is made here, from the content hash.
"""
from __future__ import annotations

import os
from pathlib import Path

from lachesis.cache import CacheEntry, entry_for
from lachesis.cli.doctor import preflight
from lachesis.cli.progress import Progress


class EnvironmentProblem(RuntimeError):
    """A prerequisite this machine does not have. Actionable, not a crash."""

    def __init__(self, checks) -> None:
        self.checks = checks
        super().__init__("; ".join(check.detail for check in checks))


class NoSourceFound(RuntimeError):
    """Pointed at a tree with nothing any frontend can read."""


def ensure_graph(
    source_dir: str | os.PathLike,
    *,
    refresh: bool = False,
    progress: Progress | None = None,
    timeout_seconds: int = 300,
) -> tuple[Path, bool]:
    """Return ``(graph_path, rebuilt)`` for ``source_dir``.

    ``rebuilt`` is False when the cache answered, which is the common case and the one
    the whole design is arranged around: the second run of anything is instant.
    """
    from lachesis.kuzu_store import write_kuzu_graph
    from lachesis.pipeline import run_project_incremental, source_content_hash

    progress = progress or Progress(enabled=False)
    entry = entry_for(source_dir)
    source = entry.source_dir
    if not source.is_dir():
        raise NoSourceFound(f"{source} is not a directory")

    failures = preflight(source)
    if failures:
        raise EnvironmentProblem(failures)

    progress.phase("reading source tree")
    content_hash = source_content_hash(str(source))
    status = entry.status(content_hash)
    progress.done()

    if status == "fresh" and not refresh:
        progress.note(f"index is current ({_age(entry)})")
        return entry.graph_path, False

    if status == "stale":
        progress.note("source changed since the last index, rebuilding")
    # Rebuild the graph itself, but retain per-frontend bundles.  The incremental
    # pipeline validates each bundle against its source digests and build options, so
    # unchanged translation units can be loaded instead of reparsed.  The old graph
    # and its derived dataflow tier must still go: they describe the previous source.
    import shutil
    for stale in (entry.graph_path, Path(str(entry.graph_path) + ".enriched")):
        if stale.is_dir():
            shutil.rmtree(stale)
        elif stale.exists():
            stale.unlink()
    entry.directory.mkdir(parents=True, exist_ok=True)
    frontend_cache = entry.directory / "frontend-cache"

    progress.phase("compiling")
    try:
        graph, snapshots = run_project_incremental(
            str(source), str(frontend_cache), enrich=False,
            timeout_seconds=timeout_seconds,
            manifest_path=str(frontend_cache / "incremental_manifest.pb"),
        )
    except Exception:
        progress.fail()
        entry.discard()
        raise
    progress.done()
    progress.note(f"{len(graph['nodes']):,} nodes, {len(graph['edges']):,} edges from "
                  + ", ".join(sorted({item.frontend_id for item in snapshots})))

    progress.phase("writing index")
    try:
        write_kuzu_graph(graph, snapshots, str(entry.graph_path), enriched=False)
        entry.write_meta(
            content_hash,
            nodes=len(graph["nodes"]),
            edges=len(graph["edges"]),
            frontends=sorted({item.frontend_id for item in snapshots}),
        )
    except Exception:
        progress.fail()
        entry.discard()
        raise
    progress.done()
    return entry.graph_path, True


def _age(entry: CacheEntry) -> str:
    import time
    meta = entry.meta() or {}
    seconds = time.time() - meta.get("built_at", 0.0)
    if seconds < 90:
        return "built moments ago"
    if seconds < 5400:
        return f"built {seconds / 60:.0f} minutes ago"
    if seconds < 172800:
        return f"built {seconds / 3600:.0f} hours ago"
    return f"built {seconds / 86400:.0f} days ago"
