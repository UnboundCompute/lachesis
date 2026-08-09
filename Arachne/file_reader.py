"""Compatibility imports for the legacy file-oriented analysis API."""

from .compatibility.legacy_file_api import (
    FILE_MAP,
    HOLD_LIST,
    TYPESCRIPT_EXTENSIONS,
    analyze_files,
    hash_path,
    read_file,
    run_semantic_overlays,
    walk,
)

__all__ = [
    "FILE_MAP", "HOLD_LIST", "TYPESCRIPT_EXTENSIONS", "analyze_files",
    "hash_path", "read_file", "run_semantic_overlays", "walk",
]
