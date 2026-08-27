"""Binary protobuf bridge to the Rust Atropos binder."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Any

from lachesis.core import atropos_pb2


def _library_candidates() -> tuple[Path, ...]:
    configured = os.environ.get("LACHESIS_NATIVE_ATROPOS_LIB")
    if configured:
        return (Path(configured),)
    names = (
                     "liblachesis_lifetime_kernel.dylib",
                     "liblachesis_lifetime_kernel.so",
                     "lachesis_lifetime_kernel.dll",
                 )
    package_native = Path(__file__).resolve().parents[1].parent / "_native"
    root = Path(__file__).resolve().parents[3]
    return tuple(package_native / name for name in names) + tuple(
        root / "native" / "lifetime_kernel" / "target" / "release" / name
        for name in names
    )


def _load():
    for candidate in _library_candidates():
        if not candidate.is_file():
            continue
        library = ctypes.CDLL(str(candidate))
        library.lachesis_atropos_bind_pb.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        library.lachesis_atropos_bind_pb.restype = ctypes.c_void_p
        library.lachesis_lifetime_free_bytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        library.lachesis_lifetime_free_bytes.restype = None
        return library
    return None


def available() -> bool:
    return _load() is not None


def compile_catalog(root: str | os.PathLike[str], output_path: str | os.PathLike[str]) -> None:
    """Compile the authored Atropos JSON catalog to the runtime protobuf sidecar.

    This is a setup/build operation. The Pass-2 native runtime consumes only the
    resulting protobuf and never parses JSON.
    """
    from .models import load_models
    request = atropos_pb2.Request()
    for model in load_models(Path(root)):
        encoded = request.models.add(
            id=model.get("id") or "", language=model.get("language") or "",
            method=model.get("method") or "", package=model.get("package") or "",
            receiver_type=model.get("type") or "",
            access_path=model.get("access_path") or "", role=model.get("role") or "",
        )
        if model.get("arity") is not None:
            encoded.arity = int(model["arity"])
            encoded.has_arity = True
    target = os.fspath(output_path)
    temporary = target + f".tmp.{os.getpid()}"
    with open(temporary, "wb") as stream:
        stream.write(request.SerializeToString())
    os.replace(temporary, target)


def bind_path(input_path: str | os.PathLike[str], catalog_path: str | os.PathLike[str],
              output_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Bind a framed Pass-1 substrate without constructing a Python callsite index.

    This is the path-only boundary used by the native Pass-2 engine. Rust scans the
    substrate and catalog and writes the protobuf report directly to ``output_path``.
    """
    library = _load()
    if library is None:
        raise RuntimeError("native Atropos binder is unavailable")
    function = library.lachesis_atropos_bind_path
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    function.restype = ctypes.c_int
    status = function(os.fsencode(os.fspath(input_path)),
                      os.fsencode(os.fspath(catalog_path)),
                      os.fsencode(os.fspath(output_path)))
    if status != 0:
        raise RuntimeError(f"native Atropos path bind failed with status {status}")
    report = atropos_pb2.Report()
    report.ParseFromString(Path(output_path).read_bytes())
    return _report_dict(report)


def _report_dict(report) -> dict[str, Any]:
    """Project a decoded native report without reconstructing its input index."""
    summary = report.summary
    result = {
        "format": report.format, "version": report.version,
        "index": report.index or None,
        "summary": {
            "bound": summary.bound,
            "symbol-not-found": summary.symbol_not_found,
            "ambiguous": summary.ambiguous,
            "arity-mismatch": summary.arity_mismatch,
            "unsupported-path": summary.unsupported_path,
            "attempted": summary.attempted,
        },
        "results": [],
    }
    for row in report.results:
        converted = {
            "model_id": row.model_id or None, "method": row.method or None,
            "access_path": row.access_path or None, "role": row.role or None,
            "status": row.status,
        }
        if row.candidates:
            converted["candidates"] = [{
                "module": candidate.module or None,
                "receiver_type": candidate.receiver_type or None,
                "arity": candidate.arity if candidate.has_arity else None,
            } for candidate in row.candidates]
        if row.attachments:
            attachments = []
            for attachment in row.attachments:
                item = {"callsite": attachment.callsite}
                target = attachment.WhichOneof("target")
                if target == "node":
                    item.update({"node": attachment.node.node,
                                 "kind": attachment.node.kind,
                                 "index": (attachment.node.index
                                           if attachment.node.has_index else None)})
                elif target == "edge":
                    item["edge"] = {"from": getattr(attachment.edge, "from"),
                                     "to": attachment.edge.to}
                    if attachment.from_kind:
                        item["from_kind"] = attachment.from_kind
                    if attachment.to_kind:
                        item["to_kind"] = attachment.to_kind
                attachments.append(item)
            converted["attachments"] = attachments
        if row.skipped:
            converted["skipped"] = [{"callsite": item.callsite, "detail": item.detail}
                                     for item in row.skipped]
        if row.detail:
            converted["detail"] = row.detail
        result["results"].append(converted)
    return result


def bind_all(models: list[dict[str, Any]], index: dict[str, Any]) -> dict[str, Any]:
    """Bind models with Rust over typed protobuf; no JSON crosses the ABI."""
    library = _load()
    if library is None:
        candidates = ", ".join(str(path) for path in _library_candidates())
        raise RuntimeError(
            "Rust Atropos binder is unavailable; build native/lifetime_kernel "
            f"or set LACHESIS_NATIVE_ATROPOS_LIB (checked: {candidates})"
        )
    request = atropos_pb2.Request()
    for model in models:
        encoded = request.models.add()
        encoded.id = model.get("id") or ""
        encoded.language = model.get("language") or ""
        encoded.method = model.get("method") or ""
        encoded.package = model.get("package") or ""
        encoded.receiver_type = model.get("type") or ""
        if model.get("arity") is not None:
            encoded.arity = int(model["arity"])
            encoded.has_arity = True
        encoded.access_path = model.get("access_path") or ""
        encoded.role = model.get("role") or ""
    request.index.language = index.get("language") or ""
    request.index.source = index.get("source") or ""
    for callsite in index.get("callsites", ()):
        encoded = request.index.callsites.add(id=callsite.get("id") or "")
        callee = callsite.get("callee") or {}
        encoded.callee.name = callee.get("name") or ""
        encoded.callee.module = callee.get("module") or ""
        encoded.callee.receiver_type = callee.get("receiver_type") or ""
        if callee.get("arity") is not None:
            encoded.callee.arity = int(callee["arity"])
            encoded.callee.has_arity = True
        encoded.call_value_id = callsite.get("call_value_id") or ""
        encoded.receiver_value_id = callsite.get("receiver_value_id") or ""
        encoded.arg_value_ids.extend(callsite.get("arg_value_ids") or ())
    payload = request.SerializeToString()
    request_buffer = ctypes.create_string_buffer(payload)
    output_length = ctypes.c_size_t()
    pointer = library.lachesis_atropos_bind_pb(
        ctypes.cast(request_buffer, ctypes.c_void_p), len(payload),
        ctypes.byref(output_length))
    if not pointer or not output_length.value:
        raise RuntimeError("native Atropos binder returned a null pointer")
    try:
        report = atropos_pb2.Report()
        report.ParseFromString(ctypes.string_at(pointer, output_length.value))
    finally:
        library.lachesis_lifetime_free_bytes(pointer, output_length.value)
    return _report_dict(report)
