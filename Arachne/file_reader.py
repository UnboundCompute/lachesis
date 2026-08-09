"""Compatibility imports for the legacy file-oriented analysis API."""

from .compatibility.legacy_file_api import (
    FILE_MAP,
    HOLD_LIST,
    LAST_GRAPH,
    TYPESCRIPT_EXTENSIONS,
    analyze_files,
    hash_path,
    read_file,
    run_semantic_overlays,
    taint_path,
    walk,
)

__all__ = [
    "FILE_MAP", "HOLD_LIST", "TYPESCRIPT_EXTENSIONS", "analyze_files",
    "LAST_GRAPH", "hash_path", "read_file", "run_semantic_overlays", "taint_path", "walk",
]
