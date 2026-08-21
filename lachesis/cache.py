#!/usr/bin/env python3
"""Where a graph lives when the user has not asked to know.

A graph is a derived artifact: a pure function of a source tree plus the build settings
that shaped it. Treating it as a file the user names, passes around, and remembers to
rebuild makes them responsible for a cache-invalidation problem we can just solve. So
the product surface never takes a graph path. It takes a directory, and this module
answers with a store that is either already correct or gets rebuilt.

Freshness is content, not mtime. ``source_content_hash`` walks the same inventory the
build would and digests it, so a touched-but-unchanged file keeps the cache and a
restored older file loses it. That read costs a fraction of a compile, which is the
trade that makes an implicit cache safe enough to hide.

Layout, one directory per source tree::

    ~/.lachesis/cache/<basename>-<path-digest>/
        graph.kuzu           the store
        graph.kuzu.enriched  the dataflow tier, cached beside it by nav
        meta.pb              what tree this is, and what it hashed to

Keyed by path so re-indexing a project replaces its entry instead of accumulating one
per edit; the content hash rides in meta.pb and decides whether that entry still
describes what is on disk.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from lachesis.core.graph_wire import decode_document, encode_document

# 1 -> 2: the Python frontend stopped folding a call site's resolved kind into its node
# id, and the store gained the v9 index tables. Neither changes a source byte, and
# `CacheEntry.status()` compares only `source_content_hash` — so every existing entry
# would report "fresh" while holding a store whose ids this code no longer agrees with.
# Bumping is what turns that into a miss instead of a wrong answer.
CACHE_VERSION = 2
_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def cache_root() -> Path:
    """The cache directory, overridable so a CI job can point it at a restorable path."""
    override = os.environ.get("LACHESIS_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    home = os.environ.get("LACHESIS_HOME")
    if home:
        return Path(home).expanduser() / "cache"
    return Path.home() / ".lachesis" / "cache"


def _slug(source_dir: Path) -> str:
    name = _SLUG.sub("-", source_dir.name).strip("-") or "root"
    # The digest is over the resolved path, so two checkouts of the same project in
    # different directories get separate entries rather than fighting over one.
    digest = hashlib.sha256(str(source_dir).encode("utf-8")).hexdigest()[:8]
    return f"{name}-{digest}"


@dataclass
class CacheEntry:
    """One cached build of one source tree."""

    source_dir: Path
    directory: Path

    @property
    def graph_path(self) -> Path:
        return self.directory / "graph.kuzu"

    @property
    def meta_path(self) -> Path:
        return self.directory / "meta.pb"

    def meta(self) -> dict | None:
        try:
            data = decode_document(self.meta_path.read_bytes())
        except (OSError, ValueError):
            return None
        # A cache written by a layout we no longer speak is a miss, not an error: the
        # rebuild is cheap relative to explaining the incompatibility to anyone.
        if data.get("cache_version") != CACHE_VERSION:
            return None
        return data

    def status(self, content_hash: str | None = None) -> str:
        """``missing``, ``stale`` or ``fresh``.

        ``content_hash`` is accepted so a caller that already paid for the digest does
        not pay twice; omit it and this computes one.
        """
        meta = self.meta()
        if meta is None or not self.graph_path.exists():
            return "missing"
        if content_hash is None:
            from lachesis.pipeline import source_content_hash
            content_hash = source_content_hash(str(self.source_dir))
        return "fresh" if meta.get("content_hash") == content_hash else "stale"

    def write_meta(self, content_hash: str, **extra) -> None:
        payload = {
            "cache_version": CACHE_VERSION,
            "source_dir": str(self.source_dir),
            "content_hash": content_hash,
            "built_at": time.time(),
            "lachesis_version": _version(),
            **extra,
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        # Written last and atomically: a meta.pb beside a half-written store would
        # claim a build that did not finish, and every later run would trust it.
        temporary = self.meta_path.with_suffix(".pb.tmp")
        temporary.write_bytes(encode_document(payload))
        temporary.replace(self.meta_path)

    def discard(self) -> None:
        """Remove the entry, so a failed or superseded build cannot be read back."""
        shutil.rmtree(self.directory)


def _version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("lachesis-cpg")
    except Exception:  # noqa: BLE001 - metadata is absent in a source checkout
        return "0+unknown"


def entry_for(source_dir: str | os.PathLike) -> CacheEntry:
    resolved = Path(source_dir).expanduser().resolve()
    return CacheEntry(source_dir=resolved, directory=cache_root() / _slug(resolved))


def entries() -> list[CacheEntry]:
    """Every cached build, newest first, skipping directories we did not write."""
    root = cache_root()
    if not root.is_dir():
        return []
    found = []
    for directory in root.iterdir():
        if not directory.is_dir():
            continue
        entry = CacheEntry(source_dir=Path("?"), directory=directory)
        meta = entry.meta()
        if meta is None:
            continue
        entry.source_dir = Path(meta["source_dir"])
        found.append((meta.get("built_at", 0.0), entry))
    return [entry for _, entry in sorted(found, key=lambda pair: -pair[0])]


def directory_size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def human_size(count: int) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}GB"
