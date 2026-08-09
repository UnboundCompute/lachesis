"""Compiler-backed project inventory and language-neutral overlay execution."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional

from .async_analysis import analyze_async_flow
from .branch_analysis import analyze_branch_histories
from .context_analysis import analyze_call_contexts
from .control_flow import build_control_flow
from .data_flow import link_data_flow
from .dispatch_analysis import analyze_dispatch
from .dynamic_analysis import analyze_dynamic_behavior
from .effect_analysis import analyze_effects
from .exception_analysis import analyze_exceptions
from .heap_analysis import analyze_heap
from .module_init_analysis import analyze_module_init
from .receiver_analysis import resolve_receivers
from .runtime_models import analyze_runtime_models
from .taint_analysis import analyze_taint
from .type_system_analysis import analyze_type_system
from .types import FileInfo
from .wiring_analysis import analyze_wiring


# Public compatibility indexes. Compiler discovery populates the complete
# project before overlays run, so HOLD_LIST no longer drives resolution.
FILE_MAP: Dict[str, FileInfo] = {}
HOLD_LIST: List[FileInfo] = []
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
            "run_project_frontends() for mixed-language/C canonical graphs. "
            f"First unsupported path: {unsupported[0]}"
        )
    from .compiler_adapter import snapshot_file_infos
    from .frontend import default_registry, run_frontend

    project_root = _compiler_project_root(paths)
    frontend = default_registry().get("typescript-compiler-api")
    snapshot = run_frontend(frontend, project_root)
    all_infos = snapshot_file_infos(snapshot)
    FILE_MAP.clear()
    HOLD_LIST.clear()
    for info in all_infos:
        FILE_MAP[info["path_hash"]] = info
    run_semantic_overlays(all_infos)
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
    """Apply interprocedural/runtime/security layers after compiler discovery."""
    resolve_receivers(results)
    analyze_dispatch(results)
    link_data_flow(results)
    analyze_call_contexts(results)
    analyze_dispatch(results, include_callbacks=True)
    link_data_flow(results)
    analyze_call_contexts(results)
    analyze_dynamic_behavior(results)
    analyze_heap(results)
    for info in results:
        build_control_flow(info)
    analyze_branch_histories(results)
    analyze_type_system(results)
    analyze_runtime_models(results)
    analyze_effects(results)
    analyze_async_flow(results)
    analyze_exceptions(results)
    analyze_module_init(results)
    analyze_wiring(results)
    analyze_taint(results)
    return results
