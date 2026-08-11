"""Module naming, import resolution, and the export surface.

Python has no compiler-supplied module map: what ``import a.b`` means depends on
where the interpreter was started and what is on ``sys.path``. Probing the running
interpreter would make the graph depend on the analyst's virtualenv, which is
exactly the non-determinism ``LACHESIS_ROOTS_FILE`` exists to prevent, so
resolution here is purely a function of the root file set and the directory
layout. Anything the layout cannot decide becomes an ``external-module`` rather
than a guess.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

from .emit import Graph, SourceFile, stable_id

PACKAGE_MARKERS = ("__init__.py", "__init__.pyi")

# CPython's own static list of standard-library top-level names (3.10+). It is a
# frozenset baked into the interpreter, not a filesystem probe, so consulting it
# does not make the graph depend on the environment's installed packages.
STDLIB_MODULES = frozenset(getattr(sys, "stdlib_module_names", ()))


class ImportRecord(NamedTuple):
    """One import clause, flattened out of its statement.

    ``module`` is the dotted text as written (empty for ``from . import x``),
    ``name`` the imported attribute (empty for a plain ``import a.b``), ``alias``
    the local binding, and ``level`` the number of leading dots.
    """
    module: str
    name: str
    alias: str
    level: int
    position: dict
    statement_form: str  # "import" or "from-import"
    module_level: bool   # a top-level statement, so its alias is a module binding


def collect_imports(source: SourceFile, module: ast.Module) -> List[ImportRecord]:
    """Every import clause in a module, including ones nested inside functions.

    Nested imports are real dependencies (the deferred-import idiom is common), so
    they are collected too; the DEPENDS_ON edge they produce is still file to file.
    Only a top-level clause binds a module-level name, which is what decides
    whether the alias joins the module's export surface.
    """
    top_level = {id(statement) for statement in module.body}
    records: List[ImportRecord] = []
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                records.append(ImportRecord(
                    module=alias.name, name="",
                    # `import a.b` with no `as` binds the *top* name `a`.
                    alias=alias.asname or alias.name.split(".")[0],
                    level=0, position=source.position(node),
                    statement_form="import",
                    module_level=id(node) in top_level,
                ))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                records.append(ImportRecord(
                    module=node.module or "", name=alias.name,
                    alias=alias.asname or alias.name,
                    level=int(node.level or 0), position=source.position(node),
                    statement_form="from-import",
                    module_level=id(node) in top_level,
                ))
    return records


def dunder_all(module: ast.Module) -> Optional[List[str]]:
    """The names in a module-level ``__all__`` list, or None when there is none.

    Only a literal list or tuple of strings is read. ``__all__ += other.__all__``
    is computed at import time and is not decidable here, so it is ignored rather
    than half-answered.
    """
    for statement in module.body:
        targets: Sequence[ast.expr] = ()
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        else:
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in targets
        ):
            continue
        value = statement.value
        if not isinstance(value, (ast.List, ast.Tuple)):
            return None
        names = [
            element.value for element in value.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        ]
        return names
    return None


class ModuleIndex:
    """Dotted module name to file, derived from the directory layout alone.

    Two registries, deliberately ranked. The *primary* name is the one an
    ``__init__.py`` chain proves: walk up from the file while each ancestor is a
    package, and the first directory that is not one is the import root. The
    *alias* registry holds every path-shaped suffix of the file's location, which
    is how a PEP 420 namespace package would be named. A primary hit is exact; an
    alias hit is only accepted when it is unique, and an ambiguous one resolves to
    nothing rather than to a guess.
    """

    def __init__(self, files: Sequence[Path], source_dir: Path) -> None:
        self.source_dir = source_dir
        self.dotted_of: Dict[Path, str] = {}
        self.package_root_of: Dict[Path, Path] = {}
        self._primary: Dict[str, Path] = {}
        self._ambiguous: Set[str] = set()
        self._aliases: Dict[str, Set[Path]] = {}
        for path in files:
            root = self._import_root(path)
            dotted = self._dotted(path, root)
            if not dotted:
                continue
            self.dotted_of[path] = dotted
            self.package_root_of[path] = root
            if dotted in self._primary and self._primary[dotted] != path:
                self._ambiguous.add(dotted)
            else:
                self._primary[dotted] = path
            for alias in self._namespace_aliases(path):
                self._aliases.setdefault(alias, set()).add(path)

    @staticmethod
    def _is_package_dir(directory: Path) -> bool:
        return any((directory / marker).exists() for marker in PACKAGE_MARKERS)

    def _import_root(self, path: Path) -> Path:
        directory = path.parent
        while self._is_package_dir(directory) and directory != directory.parent:
            directory = directory.parent
        return directory

    @staticmethod
    def _dotted_from_parts(parts: Sequence[str]) -> str:
        trimmed = list(parts)
        if trimmed and trimmed[-1] in ("__init__", "__main__"):
            trimmed = trimmed[:-1]
        return ".".join(trimmed)

    def _dotted(self, path: Path, root: Path) -> str:
        try:
            relative = path.relative_to(root)
        except ValueError:
            return ""
        return self._dotted_from_parts(relative.with_suffix("").parts)

    def _namespace_aliases(self, path: Path) -> List[str]:
        """Every dotted name the file would answer to if its parents were namespace
        packages: each suffix of its source-relative path."""
        try:
            relative = path.relative_to(self.source_dir)
        except ValueError:
            return []
        parts = relative.with_suffix("").parts
        names = []
        for start in range(len(parts)):
            dotted = self._dotted_from_parts(parts[start:])
            if dotted:
                names.append(dotted)
        return names

    def is_package(self, path: Path) -> bool:
        return path.name in PACKAGE_MARKERS

    def containing_package(self, path: Path) -> str:
        """The dotted name a level-1 relative import is measured from.

        For ``pkg/__init__.py`` that is ``pkg`` itself; for ``pkg/mod.py`` it is
        also ``pkg``, since the module's own name is not part of its package.
        """
        dotted = self.dotted_of.get(path, "")
        if self.is_package(path):
            return dotted
        return dotted.rsplit(".", 1)[0] if "." in dotted else ""

    def absolute_name(
        self, dotted: str, level: int, importer: Path,
    ) -> Optional[str]:
        """Turn a possibly-relative import into an absolute dotted name."""
        if level <= 0:
            return dotted or None
        base = self.containing_package(importer)
        if level > 1:
            parts = base.split(".") if base else []
            if len(parts) < level - 1:
                return None  # climbs above the import root; not decidable here
            parts = parts[: len(parts) - (level - 1)]
            base = ".".join(parts)
        if not base:
            return None
        return f"{base}.{dotted}" if dotted else base

    def resolve(self, dotted: str) -> Tuple[Optional[Path], str]:
        """(file, confidence) for a dotted module name."""
        if not dotted:
            return None, "unresolved"
        if dotted not in self._ambiguous and dotted in self._primary:
            return self._primary[dotted], "exact"
        candidates = self._aliases.get(dotted, set())
        if len(candidates) == 1:
            return next(iter(candidates)), "conservative"
        return None, "unresolved"


class FileFacts(NamedTuple):
    """What pass one learned about a file, minus its AST."""
    source: SourceFile
    path: Path
    file_id: str
    imports: List[ImportRecord]
    exported_names: Optional[List[str]]
    module_bindings: Dict[str, List[str]]


def external_module(graph: Graph, specifier: str) -> str:
    """A dotted name that resolves to nothing in the root set."""
    node_id = stable_id("external-module", specifier)
    top = specifier.split(".")[0]
    graph.node(
        node_id, "external-module", specifier,
        specifier=specifier, package_name=top,
        provenance="stdlib" if top in STDLIB_MODULES else "unresolved-dependency",
    )
    return node_id


def emit_imports(
    graph: Graph, index: ModuleIndex, facts: FileFacts,
    file_ids: Dict[Path, str], all_facts: Dict[Path, FileFacts],
) -> int:
    """Emit one `import` node per clause, plus the file-level DEPENDS_ON it implies."""
    emitted = 0
    for record in facts.imports:
        absolute = index.absolute_name(record.module, record.level, facts.path)
        target_path: Optional[Path] = None
        confidence = "unresolved"
        member = ""
        if absolute:
            # `from a.b import c` is ambiguous in the language itself: `c` may be a
            # submodule or a name inside `a.b`. The submodule reading is tried first
            # because that is what Python does. `import *` names nothing, so it can
            # only ever resolve to the module.
            if record.name and record.name != "*":
                target_path, confidence = index.resolve(f"{absolute}.{record.name}")
                if target_path is None:
                    target_path, confidence = index.resolve(absolute)
                    member = record.name if target_path is not None else ""
            else:
                target_path, confidence = index.resolve(absolute)
        specifier = ("." * record.level) + (record.module or "")
        if record.name and record.statement_form == "from-import":
            specifier = f"{specifier} :: {record.name}" if specifier else record.name

        import_id = stable_id(
            "import", facts.source.display, record.position["start_offset"],
            record.alias, record.module, record.name, record.level,
        )
        graph.node(
            import_id, "import", record.alias, **record.position,
            specifier=specifier,
            module=record.module or None,
            imported_name=record.name or None,
            alias=record.alias,
            level=record.level,
            statement_form=record.statement_form,
            absolute_module=absolute,
            # absolute_module is the module clause as resolved; resolved_path is the
            # file the clause actually landed on, which differs whenever the imported
            # name turned out to be a submodule rather than a binding.
            resolved_path=str(target_path) if target_path is not None else None,
            resolution=confidence if target_path is not None else "external",
            confidence="exact" if target_path is not None and confidence == "exact"
                else ("conservative" if target_path is not None else "unresolved"),
        )
        graph.edge("DECLARES", facts.file_id, import_id)
        emitted += 1
        # A top-level import binds a module-level name, so it joins the binding
        # table that __all__ re-exports and (from step 4) call resolution read.
        if record.module_level and record.alias != "*":
            facts.module_bindings.setdefault(record.alias, []).append(import_id)

        if target_path is not None:
            target_id = file_ids[target_path]
            graph.edge(
                "DEPENDS_ON", facts.file_id, target_id,
                specifier=specifier, line=record.position["start_line"],
                resolved_path=str(target_path), source_kind="local",
                confidence="exact" if confidence == "exact" else "conservative",
            )
            graph.edge(
                "REFERS_TO", import_id, target_id,
                confidence="exact" if confidence == "exact" else "conservative",
            )
            # When the clause names something inside the target module and that
            # name is bound there exactly once, the import points at the
            # declaration itself. More than one binding means the name is rebound
            # and no single declaration is the honest answer.
            if member:
                bindings = all_facts[target_path].module_bindings.get(member, [])
                if len(bindings) == 1:
                    graph.edge("REFERS_TO", import_id, bindings[0], member=member)
        else:
            external_id = external_module(graph, absolute or specifier or record.alias)
            graph.edge(
                "DEPENDS_ON", facts.file_id, external_id,
                specifier=specifier, line=record.position["start_line"],
                source_kind="package", confidence="conservative",
            )
            graph.edge("REFERS_TO", import_id, external_id, confidence="conservative")
    return emitted


def emit_exports(
    graph: Graph, index: ModuleIndex, facts: FileFacts,
    file_ids: Dict[Path, str],
) -> int:
    """EXPORTS from the file to each name its module surface publishes.

    With ``__all__`` the surface is exactly that list. Without one, Python's rule
    is every module-level name not starting with an underscore, which is what
    ``from module import *`` binds, so that is what is recorded.
    """
    if facts.exported_names is not None:
        names = list(facts.exported_names)
        form = "__all__"
    else:
        names = [
            name for name in facts.module_bindings if not name.startswith("_")
        ]
        form = "implicit-public"
    own_package = index.dotted_of.get(facts.path, "")
    emitted = 0
    for name in sorted(set(names)):
        targets = facts.module_bindings.get(name)
        if not targets and facts.exported_names is not None and own_package:
            # A package's __all__ commonly names its submodules rather than any
            # binding in __init__.py. Those are exports too, of the submodule file.
            submodule, _ = index.resolve(f"{own_package}.{name}")
            targets = [file_ids[submodule]] if submodule is not None else []
        for target in targets or ():
            graph.edge(
                "EXPORTS", facts.file_id, target, name=name, export_form=form,
            )
            emitted += 1
    return emitted
