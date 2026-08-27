"""Register language frontends without exposing them to the analysis core."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..core.contract import ContractError, FrontendSnapshot, FrontendSpec
from ..core.snapshot import snapshot_from_payloads


class FrontendRegistry:
    def __init__(self) -> None:
        self._frontends: Dict[str, FrontendSpec] = {}

    def register(self, frontend: FrontendSpec) -> None:
        if frontend.frontend_id in self._frontends:
            raise ContractError(f"frontend already registered: {frontend.frontend_id}")
        self._frontends[frontend.frontend_id] = frontend

    def get(self, frontend_id: str) -> FrontendSpec:
        try:
            return self._frontends[frontend_id]
        except KeyError as error:
            raise ContractError(f"unknown frontend: {frontend_id}") from error

    def select(self, path: str) -> Optional[FrontendSpec]:
        matches = [item for item in self._frontends.values() if item.supports(path)]
        return min(matches, key=lambda item: item.priority, default=None)

    def partition(self, paths: Iterable[str]) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        for path in paths:
            frontend = self.select(path)
            if frontend:
                result.setdefault(frontend.frontend_id, []).append(path)
        for grouped in result.values():
            grouped.sort()
        return result

    def partition_by_package(
        self, packages: Mapping[str, Iterable[str]],
    ) -> Dict[Tuple[str, str], List[str]]:
        """Split an already-bucketed ``{package_key: files}`` mapping by frontend.

        The unit of a parallel build is a (frontend, package) pair, because two
        frontends over one package are as independent as one frontend over two
        packages. ``partition`` is left alone: three callers depend on its shape.
        """
        result: Dict[Tuple[str, str], List[str]] = {}
        for package, paths in packages.items():
            for frontend_id, grouped in self.partition(paths).items():
                result[(frontend_id, package)] = grouped
        return dict(sorted(result.items()))

    @property
    def frontends(self) -> Tuple[FrontendSpec, ...]:
        return tuple(sorted(self._frontends.values(), key=lambda item: item.priority))


def _workspace_root(workspace_root: Optional[str]) -> Path:
    return Path(workspace_root or Path(__file__).resolve().parents[2]).resolve()


def typescript_compiler_frontend(workspace_root: Optional[str] = None) -> FrontendSpec:
    root = _workspace_root(workspace_root)
    configured_heap = os.environ.get("LACHESIS_TS_MAX_OLD_SPACE_MB", "12288")
    try:
        heap_mb = max(512, int(configured_heap))
    except ValueError:
        heap_mb = 12288
    return FrontendSpec(
        frontend_id="typescript-compiler-api",
        languages=("typescript", "javascript"),
        extensions=(".ts", ".tsx", ".mts", ".cts", ".js", ".jsx"),
        command=(
            # Node's default old-space is around 4GB, which a mid-sized application
            # tree exhausts during analysis, before serialization is even reached: the
            # node map, the edge list and the per-tier arrays are all live at once. The
            # flag is advisory, so a small build still uses only what it needs, and it
            # is spelled here rather than in NODE_OPTIONS so it shows up in `ps`.
            "node", f"--max-old-space-size={heap_mb}",
            str(root / "lachesis" / "frontends" / "typescript" / "build_graph.mjs"),
            "{source_dir}", "{output_dir}",
        ),
        working_directory=str(root),
        priority=10,
    )


def clang_c_frontend(workspace_root: Optional[str] = None) -> FrontendSpec:
    root = _workspace_root(workspace_root)
    packaged_binary = root / "lachesis" / "_native" / "lachesis-clang-frontend"
    native_binary = next(
        (
            candidate
            for candidate in (
                packaged_binary,
                root / "native" / "clang_frontend" / "target" / "release"
                / "lachesis-clang-frontend",
                root / "native" / "clang_frontend" / "target" / "debug"
                / "lachesis-clang-frontend",
            )
            if candidate.is_file()
        ),
        # Keep registry construction usable for non-C projects. If a C project
        # is selected without a native frontend, run_frontend reports the
        # missing executable instead of silently entering the legacy JSON path.
        packaged_binary,
    )
    command = (str(native_binary), "{source_dir}", "{output_dir}")
    return FrontendSpec(
        frontend_id="clang-c",
        # Clang owns both C and C++ roots. Keep one compiler-backed frontend so
        # mixed projects share the same precise symbol/edge contract while the
        # emitted binary manifest still records the concrete root languages.
        languages=("c", "cpp"),
        extensions=(".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"),
        command=command,
        working_directory=str(root),
        priority=20,
    )


def _cpython_ast_here(
    source_dir: str, roots: Optional[Sequence[str]] = None,
) -> FrontendSnapshot:
    """Analyze `source_dir` in this process and return the snapshot directly.

    Same code the subprocess runs, minus the serialisation between the two. The
    import is deferred because it pulls in the whole Python frontend package, and a
    caller that only wants the registry to partition file paths should not pay for
    that.
    """
    from .python.build_graph import analyze

    analysis = analyze(Path(source_dir).resolve(), roots)
    return snapshot_from_payloads(
        analysis.manifest, analysis.payloads,
        stdout=f"{analysis.summary} in process",
    )


def cpython_ast_frontend(workspace_root: Optional[str] = None) -> FrontendSpec:
    root = _workspace_root(workspace_root)
    return FrontendSpec(
        frontend_id="cpython-ast",
        languages=("python",),
        extensions=(".py", ".pyi"),
        # Run as a module, not as a script path: the frontend is a package of nine
        # modules and importing it by path would put the package's own directory
        # on sys.path ahead of the workspace.
        command=(
            sys.executable, "-m", "lachesis.frontends.python.build_graph",
            "{source_dir}", "{output_dir}",
        ),
        working_directory=str(root),
        priority=30,
        in_process=_cpython_ast_here,
    )


def default_registry(workspace_root: Optional[str] = None) -> FrontendRegistry:
    registry = FrontendRegistry()
    registry.register(typescript_compiler_frontend(workspace_root))
    registry.register(clang_c_frontend(workspace_root))
    registry.register(cpython_ast_frontend(workspace_root))
    return registry
