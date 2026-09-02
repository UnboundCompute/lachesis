"""Path-only protobuf bridge to the Rust Pass-1/Pass-2/Pass-3 engine.

Python passes filenames and scalar metadata across this boundary. Rust opens the
binary sidecars, performs the work, and publishes protobuf results. There is no
Python graph/object solver or JSON transport here.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

from lachesis.core import graph_pb2, lifetime_pb2


def _library_candidates() -> tuple[Path, ...]:
    configured = os.environ.get("LACHESIS_NATIVE_LIFETIME_LIB")
    if configured:
        return (Path(configured),)
    names = (
                     "liblachesis_lifetime_kernel.dylib",
                     "liblachesis_lifetime_kernel.so",
                     "lachesis_lifetime_kernel.dll",
                 )
    package_native = Path(__file__).resolve().parents[1] / "_native"
    root = Path(__file__).resolve().parents[2]
    return tuple(package_native / name for name in names) + tuple(
        root / "native" / "lifetime_kernel" / "target" / "release" / name
        for name in names
    )


def _load():
    for candidate in _library_candidates():
        if candidate.is_file():
            library = ctypes.CDLL(str(candidate))
            library.lachesis_lifetime_free_bytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            library.lachesis_lifetime_free_bytes.restype = None
            return library
    return None


def available() -> bool:
    return _load() is not None


def kernel_version() -> str | None:
    """Return the native build stamp when the loaded kernel publishes one."""
    library = _load()
    if library is None:
        return None
    try:
        function = library.lachesis_lifetime_kernel_version
    except AttributeError:
        return None
    function.argtypes = []
    function.restype = ctypes.c_char_p
    value = function()
    return os.fsdecode(value) if value else None


def _require_library():
    library = _load()
    if library is None:
        candidates = ", ".join(str(path) for path in _library_candidates())
        raise RuntimeError(
            "Native analysis kernel not found. Install a prebuilt wheel with "
            "`python -m pip install --upgrade lachesis-cpg`, or build it from a "
            "source checkout with `cargo build --release --manifest-path "
            "native/lifetime_kernel/Cargo.toml`. Checked: " + candidates)
    return library


# -- native-pass process isolation ---------------------------------------------
#
# A whole-graph native pass (Pass-2 enrich, the Pass-3 semantic sidecar) allocates
# a large transient inside the Rust arena and, on return, the system allocator keeps
# those freed pages resident rather than returning them to the OS. Two such passes
# run back to back during `enrich`, so the second transient lands on top of the
# first's retained arena and the peak is the *sum*, not the max -- measured ~2.1 GB
# on a store where each pass alone needs ~1.3 GB.
#
# Both passes speak to Rust purely through file paths (input/catalog in, sidecar
# out), so running one in a short-lived child process is transparent: the child
# writes the identical sidecar and exits, and the OS reclaims its entire heap. The
# transients then never coexist and the peak is bounded by the single largest pass,
# which is what lets `enrich` scale to a Linux-sized graph. Opt-in via
# ``LACHESIS_ISOLATE_NATIVE`` so small-graph and interactive callers keep the
# in-process path and its ~1s-per-pass spawn cost.
_ISOLATE_ENV = "LACHESIS_ISOLATE_NATIVE"


def _isolation_requested() -> bool:
    return os.environ.get(_ISOLATE_ENV, "") not in ("", "0")


def _run_isolated(op: str, input_path, output_path, catalog_path) -> bool:
    """Run native pass ``op`` in a child process when isolation is requested.

    Returns True when the pass was handled in a child (the caller must not also run
    it in-process); False when the caller should fall through to the in-process FFI.
    Raises the same ``RuntimeError`` the in-process path raises on a non-zero status.
    """
    if not _isolation_requested():
        return False
    child_env = dict(os.environ)
    # The child re-enters this module; clear the flag so it runs the pass in-process
    # instead of spawning a grandchild forever.
    child_env.pop(_ISOLATE_ENV, None)
    # Guarantee the child can import `lachesis` however the parent was launched
    # (editable install, PYTHONPATH, or a source checkout): prepend the repo root.
    repo_root = str(Path(__file__).resolve().parents[2])
    existing = child_env.get("PYTHONPATH", "")
    if repo_root not in existing.split(os.pathsep):
        child_env["PYTHONPATH"] = repo_root + (os.pathsep + existing if existing else "")
    argv = [sys.executable, "-m", "lachesis.flow.native_worker", op,
            os.fspath(input_path), os.fspath(output_path),
            os.fspath(catalog_path) if catalog_path is not None else ""]
    completed = subprocess.run(argv, env=child_env)
    if completed.returncode != 0:
        raise RuntimeError(
            f"native pass {op!r} (isolated) failed with exit code {completed.returncode}")
    return True


def _call_path(symbol: str, input_path: str | os.PathLike[str], response_type,
               operation: str):
    library = _require_library()
    function = getattr(library, symbol)
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)]
    function.restype = ctypes.c_void_p
    output_length = ctypes.c_size_t()
    pointer = function(os.fsencode(os.fspath(input_path)), ctypes.byref(output_length))
    if not pointer or not output_length.value:
        raise RuntimeError(f"{operation} returned no result")
    try:
        result = response_type()
        result.ParseFromString(ctypes.string_at(pointer, output_length.value))
        return result
    finally:
        library.lachesis_lifetime_free_bytes(pointer, output_length.value)


def write_translation_facts_path(sidecar_path: str | os.PathLike[str],
                                 output_path: str | os.PathLike[str]) -> None:
    library = _require_library()
    function = library.lachesis_lifetime_translate_graph_write_path
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    function.restype = ctypes.c_int
    status = function(os.fsencode(os.fspath(sidecar_path)),
                      os.fsencode(os.fspath(output_path)))
    if status != 0:
        raise RuntimeError("native translation facts failed")


def run_pass2_path(input_path: str | os.PathLike[str],
                   output_path: str | os.PathLike[str],
                   catalog_path: str | os.PathLike[str] | None = None) -> None:
    if _run_isolated("pass2", input_path, output_path, catalog_path):
        return
    library = _require_library()
    function = library.lachesis_pass2_run_path
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    function.restype = ctypes.c_int
    status = function(os.fsencode(os.fspath(input_path)),
                      os.fsencode(os.fspath(catalog_path)) if catalog_path is not None else None,
                      os.fsencode(os.fspath(output_path)))
    if status != 0:
        raise RuntimeError(f"native Pass-2 runner failed with status {status}")


def _encoded(value: Any) -> bytes:
    return os.fsencode(str(value or ""))


def project_pass1_shard(nodes_path, edges_path, pass2_output, pass3_output,
                        manifest: dict[str, Any], *, prune: bool = False) -> None:
    library = _require_library()
    function = library.lachesis_pass1_project_shard
    function.argtypes = [ctypes.c_char_p] * 8 + [ctypes.c_int]
    function.restype = ctypes.c_int
    status = function(
        _encoded(nodes_path), _encoded(edges_path), _encoded(pass2_output),
        _encoded(pass3_output), _encoded(manifest.get("version")),
        _encoded(manifest.get("core_content_hash")),
        _encoded(manifest.get("source_content_hash")),
        _encoded(manifest.get("build_fingerprint")), int(bool(prune)),
    )
    if status != 0:
        raise RuntimeError(f"native Pass-1 shard projector failed with status {status}")


def project_pass1_shards(shard_paths, pass2_output, pass3_output,
                         manifest: dict[str, Any], *, prune: bool = False) -> None:
    library = _require_library()
    request = graph_pb2.NativeShardSet(format_version=1)
    for frontend_id, nodes_path, edges_path in shard_paths:
        request.shards.add(frontend_id=str(frontend_id),
                           nodes_path=os.fspath(nodes_path),
                           edges_path=os.fspath(edges_path))
    if not request.shards:
        raise ValueError("native Pass-1 shard set is empty")
    with tempfile.NamedTemporaryFile(prefix="lachesis-shards-", suffix=".pb") as handle:
        handle.write(request.SerializeToString())
        handle.flush()
        function = library.lachesis_pass1_project_shards
        function.argtypes = [ctypes.c_char_p] * 7 + [ctypes.c_int]
        function.restype = ctypes.c_int
        status = function(
            _encoded(handle.name), _encoded(pass2_output), _encoded(pass3_output),
            _encoded(manifest.get("version")),
            _encoded(manifest.get("core_content_hash")),
            _encoded(manifest.get("source_content_hash")),
            _encoded(manifest.get("build_fingerprint")), int(bool(prune)),
        )
    if status != 0:
        raise RuntimeError(f"native Pass-1 shard-set projector failed with status {status}")


def plan_path(facts_path, catalog_path, output_path):
    library = _require_library()
    function = library.lachesis_lifetime_plan_path
    function.argtypes = [ctypes.c_char_p] * 3
    function.restype = ctypes.c_int
    status = function(_encoded(facts_path), _encoded(catalog_path), _encoded(output_path))
    if status != 0:
        raise RuntimeError(f"native binary planner failed with status {status}")
    result = lifetime_pb2.NativePlanResult()
    result.ParseFromString(Path(output_path).read_bytes())
    return result


def summaries_path(facts_path, catalog_path, output_path):
    library = _require_library()
    function = library.lachesis_lifetime_summaries_path
    function.argtypes = [ctypes.c_char_p] * 3
    function.restype = ctypes.c_int
    status = function(_encoded(facts_path), _encoded(catalog_path), _encoded(output_path))
    if status != 0:
        raise RuntimeError(f"native binary summaries failed with status {status}")
    result = lifetime_pb2.NativeSummaryResult()
    result.ParseFromString(Path(output_path).read_bytes())
    return result


def write_semantic_path(input_path, output_path, catalog_path=None) -> None:
    """Publish the Rust semantic sidecars without decoding them in Python."""
    if _run_isolated("semantic", input_path, output_path, catalog_path):
        return
    library = _require_library()
    function = library.lachesis_lifetime_semantic_path
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    function.restype = ctypes.c_int
    status = function(_encoded(input_path),
                      _encoded(catalog_path) if catalog_path is not None else None,
                      _encoded(output_path))
    if status != 0:
        raise RuntimeError(f"native semantic graph failed with status {status}")


def match_semantic_path(input_path: str | os.PathLike[str],
                        output_path: str | os.PathLike[str],
                        catalog_path: str | os.PathLike[str] | None = None) -> None:
    """Run the native Pass-3 matcher over a semantic protobuf sidecar.

    Only filenames cross this boundary.  Rust maps the input and writes a
    ``NativeTemporalResult`` protobuf; Python callers can decode that result
    without reconstructing the semantic graph or invoking the legacy matcher.
    """
    library = _require_library()
    function = library.lachesis_lifetime_match_semantic_path
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    function.restype = ctypes.c_int
    status = function(_encoded(input_path), _encoded(output_path),
                      _encoded(catalog_path) if catalog_path is not None else None)
    if status != 0:
        raise RuntimeError(f"native semantic matching failed with status {status}")
