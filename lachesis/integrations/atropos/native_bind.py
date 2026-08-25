"""Bridge to the Rust Atropos binder.

The JSON boundary intentionally matches ``tools/bind.py``.  Atropos's Python
module remains a model-loader and offline differential oracle; production model
matching is implemented only by Rust.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
from typing import Any


def _library_candidates() -> tuple[Path, ...]:
    configured = os.environ.get("LACHESIS_NATIVE_ATROPOS_LIB")
    if configured:
        return (Path(configured),)
    root = Path(__file__).resolve().parents[3]
    return tuple(root / "native" / "lifetime_kernel" / "target" / "release" / name
                 for name in (
                     "liblachesis_lifetime_kernel.dylib",
                     "liblachesis_lifetime_kernel.so",
                     "lachesis_lifetime_kernel.dll",
                 ))


def _load():
    for candidate in _library_candidates():
        if not candidate.is_file():
            continue
        library = ctypes.CDLL(str(candidate))
        library.lachesis_atropos_bind_json.argtypes = [ctypes.c_char_p]
        library.lachesis_atropos_bind_json.restype = ctypes.c_void_p
        library.lachesis_lifetime_free_json.argtypes = [ctypes.c_void_p]
        library.lachesis_lifetime_free_json.restype = None
        return library
    return None


def available() -> bool:
    return _load() is not None


def bind_all(models: list[dict[str, Any]], index: dict[str, Any]) -> dict[str, Any]:
    """Bind models with Rust; fail clearly if the native kernel is not installed."""
    library = _load()
    if library is None:
        candidates = ", ".join(str(path) for path in _library_candidates())
        raise RuntimeError(
            "Rust Atropos binder is unavailable; build native/lifetime_kernel "
            f"or set LACHESIS_NATIVE_ATROPOS_LIB (checked: {candidates})"
        )
    payload = json.dumps({"models": models, "index": index}, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    pointer = library.lachesis_atropos_bind_json(payload)
    if not pointer:
        raise RuntimeError("native Atropos binder returned a null pointer")
    try:
        result = json.loads(ctypes.string_at(pointer).decode("utf-8"))
    finally:
        library.lachesis_lifetime_free_json(pointer)
    if "error" in result:
        raise RuntimeError(f"native Atropos binder failed: {result['error']}")
    return result
