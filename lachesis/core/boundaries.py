"""Mechanical dependency-boundary checks for the Lachesis package."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, List


CORE_FORBIDDEN_IMPORTS = (
    "lachesis.frontends", "lachesis.compatibility",
)


def _absolute_import(module: str | None, level: int, package: str) -> str:
    if level == 0:
        return module or ""
    package_parts = package.split(".")
    prefix = package_parts[:max(0, len(package_parts) - level + 1)]
    if module:
        prefix.extend(module.split("."))
    return ".".join(prefix)


def import_boundary_violations(package_root: str | Path) -> List[str]:
    """Return forbidden core dependency imports using Python's AST."""
    root = Path(package_root).resolve()
    violations = []
    core_root = root / "core"
    for path in sorted(core_root.rglob("*.py")):
        relative = path.relative_to(root).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts.pop()
        package = ".".join([root.name, *parts[:-1]])
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.append(_absolute_import(node.module, node.level, package))
            for name in names:
                if any(name == prefix or name.startswith(prefix + ".")
                       for prefix in CORE_FORBIDDEN_IMPORTS):
                    violations.append(
                        f"{path.relative_to(root)}:{node.lineno} imports {name}"
                    )
    return violations


def assert_import_boundaries(package_root: str | Path) -> None:
    violations = import_boundary_violations(package_root)
    if violations:
        raise AssertionError("forbidden Lachesis dependencies:\n" + "\n".join(violations))
