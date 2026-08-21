#!/usr/bin/env python3
"""What this machine can and cannot analyse, checked before it matters.

Two of the three frontends shell out — TypeScript to ``node``, C to ``clang`` — and
neither is a Python dependency, so ``pip install`` cannot supply them. Without a check
the failure surfaces as a frontend that died mid-build, which reads like a bug in the
source it was pointed at rather than a missing tool. So the tools are probed up front,
and probed *against the tree in front of us*: a pure-Python repository has no business
being told to install a C compiler.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Extension -> the frontend that claims it, mirroring the registry's own table. Kept
# here as a language question rather than imported as a frontend question: this runs
# before a build exists, and it answers "what would this tree need".
_TYPESCRIPT = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx"}
_C = {".c", ".h"}
_PYTHON = {".py", ".pyi"}


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""
    required: bool = True

    @property
    def mark(self) -> str:
        return "✓" if self.ok else ("✗" if self.required else "–")


def _version_of(command: list[str]) -> str:
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return ""
    return (done.stdout or done.stderr).strip().splitlines()[0] if done.returncode == 0 else ""


def check_node(required: bool = True) -> Check:
    binary = shutil.which("node")
    if not binary:
        return Check("node", False,
                     "not on PATH — TypeScript and JavaScript files cannot be analysed",
                     "install Node.js 20 or newer: https://nodejs.org/", required)
    version = _version_of([binary, "--version"])
    # The TypeScript compiler API we vendor is built against modern Node; an ancient
    # one fails deep inside the frontend rather than at startup, so say so here.
    major = 0
    if version.startswith("v"):
        try:
            major = int(version[1:].split(".", 1)[0])
        except ValueError:
            major = 0
    if major and major < 20:
        return Check("node", False, f"{version} at {binary} — too old, need 20 or newer",
                     "install Node.js 20 or newer: https://nodejs.org/", required)
    return Check("node", True, f"{version or 'present'} at {binary}", required=required)


def check_clang(required: bool = True) -> Check:
    configured = shlex.split(os.environ.get("CLANG", "clang"))
    binary = shutil.which(configured[0]) if configured else None
    if not binary:
        hint = ("install Xcode command line tools: xcode-select --install"
                if sys.platform == "darwin" else "install clang from your package manager")
        return Check("clang", False,
                     f"{configured[0] if configured else 'clang'} not on PATH"
                     " — C files cannot be analysed", hint, required)
    return Check("clang", True, f"{_version_of([binary, '--version']) or 'present'}",
                 required=required)


def check_vendored_typescript() -> Check:
    library = (Path(__file__).resolve().parents[1] / "frontends" / "typescript"
               / "vendor" / "typescript" / "lib" / "typescript.js")
    if library.exists():
        size = library.stat().st_size / (1024 * 1024)
        return Check("typescript", True, f"vendored ({size:.1f}MB), no npm install needed")
    # A source checkout has no vendor directory until the fetch script runs; an
    # installed wheel always does. Both are legitimate, so this is a note, not a fault:
    # the frontend also accepts a TypeScript resolvable from the working directory.
    return Check("typescript", False,
                 "not vendored — the frontend will look for an installed typescript",
                 "python tools/vendor_typescript.py  (source checkouts only)",
                 required=False)


def check_kuzu() -> Check:
    try:
        import kuzu  # noqa: F401
        return Check("kuzu", True, f"{getattr(kuzu, '__version__', 'present')}")
    except ImportError as error:
        return Check("kuzu", False, f"import failed: {error}",
                     "python -m pip install --force-reinstall lachesis-cpg")


def check_cache() -> Check:
    from lachesis.cache import cache_root
    root = cache_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".write-probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError as error:
        return Check("cache", False, f"{root} is not writable: {error}",
                     "set LACHESIS_CACHE_DIR to a writable directory")
    return Check("cache", True, str(root))


def languages_present(source_dir: str | os.PathLike) -> set[str]:
    """Which language families this tree actually contains.

    Walks the build's own inventory rather than globbing, so what we probe for is
    exactly what the build would try to compile — the same exclusions for
    node_modules, virtualenvs and test files.
    """
    from lachesis.pipeline import source_inventory
    found: set[str] = set()
    for path in source_inventory(str(source_dir)):
        suffix = Path(path).suffix
        if suffix in _TYPESCRIPT:
            found.add("typescript")
        elif suffix in _C:
            found.add("c")
        elif suffix in _PYTHON:
            found.add("python")
    return found


def preflight(source_dir: str | os.PathLike) -> list[Check]:
    """Only the checks that this tree's contents make load-bearing."""
    present = languages_present(source_dir)
    checks = [check_kuzu()]
    if "typescript" in present:
        checks.append(check_node())
    if "c" in present:
        checks.append(check_clang())
    return [check for check in checks if not check.ok]


def full_report() -> list[Check]:
    """Everything, whether or not the current directory needs it."""
    return [
        Check("python", sys.version_info >= (3, 10),
              f"{sys.version.split()[0]} at {sys.executable}",
              "lachesis needs Python 3.10 or newer"),
        check_kuzu(),
        check_vendored_typescript(),
        # Neither tool is required in general — only for a tree that contains those
        # languages — so a machine without them is still a working install.
        check_node(required=False),
        check_clang(required=False),
        check_cache(),
    ]
