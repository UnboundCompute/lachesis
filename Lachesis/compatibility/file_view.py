"""File-oriented compatibility view projected from the canonical graph."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional

from ..types import FileInfo
from .projector import compatibility_taint_path, graph_file_infos


# Public compatibility indexes. Compiler discovery populates the complete
# project before overlays run, so HOLD_LIST no longer drives resolution.
FILE_MAP: Dict[str, FileInfo] = {}
HOLD_LIST: List[FileInfo] = []
LAST_GRAPH: dict = {"nodes": [], "edges": []}
TYPESCRIPT_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts")


def hash_path(path: str) -> str:
    absolute_path = os.path.abspath(path)
    return hashlib.sha256(absolute_path.encode("utf-8")).hexdigest()


def walk(src_dir: str) -> List[str]:
    files = []
    for root, directories, names in os.walk(src_dir):
        directories[:] = sorted(
            name for name in directories
            if name not in {".git", "node_modules", "graph_out", "dist", "build"}
        )
        for name in sorted(names):
            if name.endswith(TYPESCRIPT_EXTENSIONS):
                files.append(os.path.join(root, name))
    return sorted(files)


def _compiler_project_root(paths: List[str]) -> str:
    absolute = [os.path.abspath(path) for path in paths]
    common = Path(os.path.commonpath(absolute))
    if common.is_file() or common.suffix:
        common = common.parent
    current = common
    while True:
        if (current / "tsconfig.json").is_file():
            return str(current)
        if current.parent == current:
            return str(common)
        current = current.parent


def analyze_files(paths: List[str], workers: Optional[int] = None) -> List[FileInfo]:
    """Analyze requested TS/JS files through the official compiler frontend.

    The complete containing compiler project is analyzed so aliases, re-exports
    and interprocedural targets remain resolvable. Only requested application
    records are returned, preserving the historical API. ``workers`` remains a
    compatibility argument; the native compiler controls its own execution.
    """
    del workers
    if not paths:
        FILE_MAP.clear()
        HOLD_LIST.clear()
        return []
    unsupported = [path for path in paths if Path(path).suffix.lower() not in TYPESCRIPT_EXTENSIONS]
    if unsupported:
        raise ValueError(
            "FileInfo semantic overlays currently support TS/JS paths; use "
        "run_project() for mixed-language canonical graphs, which is how C and "
        "Python are analysed. "
            f"First unsupported path: {unsupported[0]}"
        )
    from ..pipeline import run_project

    project_root = _compiler_project_root(paths)
    graph, _snapshots = run_project(project_root)
    global LAST_GRAPH
    LAST_GRAPH = graph
    all_infos = graph_file_infos(graph)
    FILE_MAP.clear()
    HOLD_LIST.clear()
    for info in all_infos:
        FILE_MAP[info["path_hash"]] = info
    requested = {os.path.abspath(path) for path in paths}
    return [info for info in all_infos if info["path"] in requested]


def read_file(path: str) -> FileInfo:
    """Return the compiler-backed record for one file in its project context."""
    absolute = os.path.abspath(path)
    result = analyze_files([absolute])
    if not result:
        raise FileNotFoundError(absolute)
    return result[0]


def run_semantic_overlays(results: List[FileInfo]) -> List[FileInfo]:
    """Deprecated no-op: compatibility records already contain final facts."""
    return results


def taint_path(files: List[FileInfo], source_id: str, target_id: str) -> List[str]:
    return compatibility_taint_path(files, source_id, target_id)
