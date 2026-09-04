"""Resolve a scan *source* that may be a local path or a remote repository URL.

``lachesis scan`` (and any verb that indexes a tree) takes a positional source.
Historically that was always a local directory; this module lets the same slot
accept a git URL so ``lachesis scan https://github.com/org/repo`` fetches the
source and analyses it with no manual clone step.

The seam is deliberately narrow and dependency-free: a local path resolves
exactly as before (``Path.expanduser().resolve()``) with a no-op cleanup, and a
remote spec is shallow-cloned into a managed temp directory that is removed when
the caller is done. Nothing else in the pipeline needs to know which it was --
downstream code only ever sees a local ``Path``.

A remote spec may carry a ``#subdir`` fragment
(``https://github.com/microsoft/playwright#packages/playwright-core/src/tools``)
to analyse just one subtree of a large monorepo. When present we drive a partial
(``--filter=blob:none``) sparse checkout of only that subtree, so cloning the
Playwright monorepo to reach its MCP tools costs ~1 MB, not the whole history.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# A spec is "remote" if it names a transport git understands. We match the
# common URL schemes plus the ``scp``-style ``user@host:path`` form and a
# trailing ``.git``; everything else is treated as a local filesystem path.
_URL_SCHEME = re.compile(r"^(https?|git|ssh|ftps?)://", re.IGNORECASE)
_SCP_LIKE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:")


def is_remote_spec(spec: str | None) -> bool:
    """True when ``spec`` should be fetched with git rather than read from disk.

    A ``#subdir`` fragment is allowed on a remote spec, so we test the part
    before ``#``. A bare local path -- even one that happens to contain ``#`` --
    stays local; only recognised transports count as remote.
    """
    if not spec:
        return False
    head = spec.split("#", 1)[0]
    if _URL_SCHEME.match(head):
        return True
    if head.endswith(".git") and ("/" in head or ":" in head):
        return True
    # scp-like git@github.com:org/repo(.git). Guard against a Windows drive
    # letter (C:\...) by requiring a non-drive host of at least two chars.
    if _SCP_LIKE.match(head) and not re.match(r"^[A-Za-z]:[\\/]", head):
        return True
    return False


def _split_fragment(spec: str) -> tuple[str, Optional[str]]:
    """Split ``url#subdir`` into ``(url, subdir_or_None)``.

    The subdir is normalised to a repo-relative POSIX path with no leading
    slash and no ``..`` segments -- it selects a subtree of the checkout, so a
    parent-escaping fragment is rejected rather than silently clamped.
    """
    url, _, frag = spec.partition("#")
    frag = frag.strip().strip("/")
    if not frag:
        return url, None
    parts = [p for p in frag.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(f"subdirectory fragment may not contain '..': {frag!r}")
    return url, "/".join(parts)


@dataclass
class ResolvedSource:
    """A local path to analyse plus a cleanup hook for any fetched clone.

    Usable as a context manager: the clone (if any) is removed on exit. For a
    local source ``cleanup`` is a no-op and ``path`` is the resolved directory.
    """

    path: Path
    cleanup: Callable[[], None]
    remote: bool = False

    def __enter__(self) -> "ResolvedSource":
        return self

    def __exit__(self, *_exc) -> None:
        self.cleanup()


def _run_git(args: list[str], *, cwd: Optional[Path] = None) -> None:
    """Run one git command, raising ``RuntimeError`` with git's stderr on failure.

    ``GIT_TERMINAL_PROMPT=0`` stops a private/nonexistent repo from blocking on
    an interactive credential prompt -- we want a clean error, not a hang.
    """
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ADVICE_SET_UPSTREAM_FAILED="0")
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None,
        env=env, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else f"git exited {proc.returncode}"
        raise RuntimeError(tail)


def _clone(url: str, subdir: Optional[str], dest: Path,
           *, note: Optional[Callable[[str], None]] = None) -> Path:
    """Shallow-clone ``url`` into ``dest``; return the directory to analyse.

    Without a subdir this is a plain ``--depth 1`` clone. With one we do a
    blobless sparse checkout of just that subtree and return the subtree path,
    so a monorepo costs only the files under the fragment.
    """
    if note:
        note(f"fetching {url}" + (f" (#{subdir})" if subdir else ""))
    if subdir is None:
        _run_git(["clone", "--depth", "1", "--quiet",
                  "--no-tags", "--recurse-submodules=no", url, str(dest)])
        return dest
    # Monorepo subtree: clone metadata only, then materialise one path.
    _run_git(["clone", "--depth", "1", "--quiet", "--no-tags",
              "--filter=blob:none", "--sparse", url, str(dest)])
    _run_git(["sparse-checkout", "set", subdir], cwd=dest)
    target = dest / subdir
    if not target.is_dir():
        raise RuntimeError(
            f"subdirectory {subdir!r} does not exist in the repository")
    return target


def resolve_source(spec: str | None,
                   *, note: Optional[Callable[[str], None]] = None) -> ResolvedSource:
    """Turn a source spec into a local ``Path`` plus a cleanup hook.

    A local path resolves in place with a no-op cleanup (unchanged behaviour). A
    git URL -- optionally ``url#subdir`` -- is shallow-cloned into a temp
    directory that ``cleanup`` removes. ``note`` is an optional progress sink for
    a one-line "fetching ..." message.
    """
    if not is_remote_spec(spec):
        return ResolvedSource(Path(spec or ".").expanduser().resolve(),
                              cleanup=lambda: None, remote=False)

    assert spec is not None  # is_remote_spec is False for None
    url, subdir = _split_fragment(spec)
    workdir = Path(tempfile.mkdtemp(prefix="lachesis-src-"))
    _cleaned = {"done": False}

    def cleanup() -> None:
        if _cleaned["done"]:
            return
        _cleaned["done"] = True
        shutil.rmtree(workdir, ignore_errors=True)

    try:
        target = _clone(url, subdir, workdir / "repo", note=note)
    except Exception:
        cleanup()
        raise
    return ResolvedSource(target, cleanup=cleanup, remote=True)
