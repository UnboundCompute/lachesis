"""Group source files by the package that owns them.

A monorepo is many packages, and a frontend compiled per package is a unit of work
that can run concurrently with its siblings. Nothing else in the builder had a notion
of a first-party package: the TypeScript frontend's ``packageIdentity`` only keys off
``/node_modules/``, so first-party files carry ``package_name: null``.

A "package" here is deliberately shallow — a directory holding a package manifest,
outside vendored trees. For JavaScript that is ``package.json``; for Python it is
``pyproject.toml``, ``setup.py`` or ``setup.cfg``, which mark exactly the same
boundary for the same reason. That is the boundary the ecosystem tooling uses and
the one a ``tsconfig.json`` usually follows, so compiling one package as one program
matches how the package is built for real.

**This is a real semantic boundary, not just a scheduling one.** One program per
package resolves types across that package's files only; a whole-repo program resolves
across everything. That is why the parallel build is opt-in.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, List

ROOT_PACKAGE_KEY = "<root>"

_IGNORED_DIRECTORIES = {
    ".git", "node_modules", "graph_out", "dist", "build", ".venv", "venv",
    "site-packages", ".tox", ".nox", ".eggs",
}

# A directory holding any one of these is a package root. An installed dependency
# carries the same files, which is what the ignore list above is for.
_MANIFESTS = ("package.json", "pyproject.toml", "setup.py", "setup.cfg")


def find_package_roots(source_dir: str) -> List[str]:
    """Absolute directories under ``source_dir`` that hold a package manifest.

    ``source_dir`` itself counts when it holds one. Vendored trees are skipped: a
    dependency's manifest describes code we are not compiling.
    """
    source_dir = os.path.abspath(source_dir)
    roots = []
    for root, directories, files in os.walk(source_dir):
        directories[:] = sorted(name for name in directories
                                if name not in _IGNORED_DIRECTORIES)
        if any(manifest in files for manifest in _MANIFESTS):
            roots.append(root)
    return sorted(roots)


def package_key(source_dir: str, package_root: str | None) -> str:
    """The stable, path-shaped name a package is reported and keyed by."""
    if package_root is None:
        return ROOT_PACKAGE_KEY
    relative = os.path.relpath(package_root, os.path.abspath(source_dir))
    return "." if relative == os.curdir else relative


def detect_packages(source_dir: str, files: Iterable[str]) -> Dict[str, List[str]]:
    """Bucket ``files`` by the package that owns each one.

    A file belongs to its *deepest* enclosing package root, so a nested package inside
    a workspace takes precedence over the workspace itself. Files under no package root
    at all collect into ``<root>``, which is compiled as one more unit — never dropped.
    """
    source_dir = os.path.abspath(source_dir)
    roots = find_package_roots(source_dir)
    buckets: Dict[str, List[str]] = {}
    for path in files:
        absolute = os.path.abspath(path)
        # deepest match wins; roots are compared as path prefixes with a separator so
        # `/a/pkg-two` is never treated as living inside `/a/pkg`
        owner = None
        for root in roots:
            if absolute == root or absolute.startswith(root.rstrip(os.sep) + os.sep):
                if owner is None or len(root) > len(owner):
                    owner = root
        buckets.setdefault(package_key(source_dir, owner), []).append(absolute)
    for grouped in buckets.values():
        grouped.sort()
    return dict(sorted(buckets.items()))


def package_root_for(source_dir: str, key: str) -> str:
    """Invert ``package_key``: the directory a bucket should be compiled from."""
    source_dir = os.path.abspath(source_dir)
    return source_dir if key == ROOT_PACKAGE_KEY else os.path.join(source_dir, key)
