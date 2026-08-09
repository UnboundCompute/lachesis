"""Register language frontends without exposing them to the analysis core."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from ..core.contract import ContractError, FrontendSpec


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

    @property
    def frontends(self) -> Tuple[FrontendSpec, ...]:
        return tuple(sorted(self._frontends.values(), key=lambda item: item.priority))


def _workspace_root(workspace_root: Optional[str]) -> Path:
    return Path(workspace_root or Path(__file__).resolve().parents[2]).resolve()


def typescript_compiler_frontend(workspace_root: Optional[str] = None) -> FrontendSpec:
    root = _workspace_root(workspace_root)
    return FrontendSpec(
        frontend_id="typescript-compiler-api",
        languages=("typescript", "javascript"),
        extensions=(".ts", ".tsx", ".mts", ".cts", ".js", ".jsx"),
        command=(
            "node", str(root / "Arachne" / "frontends" / "typescript" / "build_graph.mjs"),
            "{source_dir}", "{output_dir}",
        ),
        working_directory=str(root),
        priority=10,
    )


def clang_c_frontend(workspace_root: Optional[str] = None) -> FrontendSpec:
    root = _workspace_root(workspace_root)
    return FrontendSpec(
        frontend_id="clang-c",
        languages=("c",),
        extensions=(".c", ".h"),
        command=(
            "python3", str(root / "Arachne" / "frontends" / "c" / "build_graph.py"),
            "{source_dir}", "{output_dir}",
        ),
        working_directory=str(root),
        priority=20,
    )


def default_registry(workspace_root: Optional[str] = None) -> FrontendRegistry:
    registry = FrontendRegistry()
    registry.register(typescript_compiler_frontend(workspace_root))
    registry.register(clang_c_frontend(workspace_root))
    return registry

