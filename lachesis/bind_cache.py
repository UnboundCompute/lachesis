"""Persist the catalog bind beside the graph, so census stops paying for it every run.

Candidate enumeration begins by binding the sink catalog against *this* graph's call sites
(``atropos_enrich``) and merging the semantic skeleton into the stamped graph. That bind is a
pure function of the graph's content -- the same store binds to the same result every time --
but it is expensive (>120s on a real tree) and, with no disk cache, was recomputed on every
fresh ``candidates``/``census`` call. This module caches the *result* of that bind as a
``<graph>.bind.pb`` sidecar, keyed by the store's content hash and the output-bearing build
options, exactly like the ``.dataflow.pb`` tier cache beside it.

What is persisted is the post-merge ``(stamped, summary)`` pair, not the registry object: the
registry rebuilds from that pair in milliseconds (``default_candidate_registry``), and a plain
dict pair is what the document codec can round-trip. A hit therefore skips *both* the enrich
and the semantic-merge flow pass -- a fresh process answers ``census`` almost immediately.

The cache is safe by construction: any header mismatch (version, content hash, build options)
is a miss that recomputes, never a wrong answer served from a stale file. A size ceiling and
the ``LACHESIS_BIND_SIDECAR=0`` opt-out keep it from ever costing more than it saves -- the
same footgun the disk snapshot cache once was, where loading a multi-gigabyte blob was slower
than recomputing from scratch.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from contextlib import contextmanager

from lachesis.core import graph_pb2
from lachesis.core.graph_wire import (
    decode_document, decode_edge, decode_node, encode_document, _edge_message,
    _node_message,
)

# Bump when the persisted shape changes in a way an old file would misdescribe. The header
# match turns a bump into a clean miss (recompute) rather than a decode against stale layout.
BIND_VERSION = 3

# Never let the sidecar dominate the time it saves: above this, the bind is used but not
# written, because decoding a multi-gigabyte blob can rival recomputing the bind outright.
_DEFAULT_MAX_BYTES = 512 * 1024 * 1024


def _enabled() -> bool:
    return os.environ.get("LACHESIS_BIND_SIDECAR", "1") != "0"


def _max_bytes() -> int:
    raw = os.environ.get("LACHESIS_BIND_SIDECAR_MAX_MB")
    if raw:
        try:
            return int(float(raw) * 1024 * 1024)
        except ValueError:
            pass
    return _DEFAULT_MAX_BYTES


def sidecar_path(graph_path: str) -> str:
    """``<graph>.bind.pb`` -- beside the store, next to ``.dataflow.pb``/``.enriched``."""
    return str(graph_path).rstrip("/") + ".bind.pb"


def _core_hash(graph_path: str) -> str:
    """The store's content hash -- the key that decides whether a bind still describes it.

    An unkeyable store (older, or core-only without the stamp) returns "" so the caller
    declines the sidecar entirely rather than trust a file it cannot invalidate.
    """
    from lachesis.kuzu_store import read_store_manifest

    try:
        return read_store_manifest(graph_path).get("core_content_hash") or ""
    except (OSError, ValueError):
        return ""


def _stat_files(fingerprint, paths) -> None:
    """Fold each existing file's identity + mtime + size into ``fingerprint``.

    Mirrors ``native_bind.compiled_catalog`` exactly (path, ``st_mtime_ns``, ``st_size``) so
    the two agree on what "the catalog changed" means. Missing files are skipped, not errors:
    a component's absence is itself a stable input, so its later appearance is a clean miss.
    """
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        fingerprint.update(str(path).encode())
        fingerprint.update(str(stat.st_mtime_ns).encode())
        fingerprint.update(str(stat.st_size).encode())


def _binder_fingerprint() -> str:
    """Fingerprint the two bind inputs the graph content does NOT capture: the native binder
    shared library and the Atropos catalog it consults.

    The bind result is a pure function of (graph, binder code, catalog data). The core content
    hash covers the graph; ``build_options_fingerprint`` covers the environment; neither sees a
    rebuilt binder ``.dylib`` or an edited model/detection file. Without this, a binder or
    catalog change replayed a stale bind (the alias-fix regression: bound:1 served after the
    fix produced bound:10) until the sidecar was hand-deleted. Both inputs are resolved from the
    filesystem alone -- no dependence on the summary -- so ``load`` and ``store`` derive the
    identical key. Any resolution failure degrades to a stable empty component, never a throw.
    """
    fingerprint = hashlib.sha256()
    try:
        from lachesis.integrations.atropos.native_bind import _library_candidates

        for candidate in _library_candidates():
            if candidate.is_file():
                _stat_files(fingerprint, (candidate,))
                break
    except Exception:  # pragma: no cover - resolver unavailable
        pass
    try:
        from pathlib import Path

        from lachesis.integrations.atropos.enrich import locate_atropos

        root = locate_atropos()
        if root is not None:
            root = Path(root)
            models = sorted((root / "models").rglob("*.json"))
            detection = [root / "detection" / name for name in (
                "lifecycle-roles.json", "flow-patterns.json", "evaluators.json")]
            _stat_files(fingerprint, models)
            _stat_files(fingerprint, detection)
    except Exception:  # pragma: no cover - atropos layout unavailable
        pass
    return fingerprint.hexdigest()


def _header(graph_path: str) -> dict:
    from lachesis.cache import build_options_fingerprint

    return {
        "version": BIND_VERSION,
        "core_content_hash": _core_hash(graph_path),
        "options": build_options_fingerprint(),
        "binder": _binder_fingerprint(),
    }


def _header_matches(document: dict, header: dict) -> bool:
    return (document.get("version") == header["version"]
            and document.get("core_content_hash") == header["core_content_hash"]
            and document.get("options") == header["options"]
            and document.get("binder") == header["binder"])


def _document_message(value: dict) -> graph_pb2.Document:
    message = graph_pb2.Document()
    message.ParseFromString(encode_document(value))
    return message


def _document_value(message: graph_pb2.Document) -> dict:
    return decode_document(message.SerializeToString())


def _encode_typed(payload: dict) -> bytes:
    stamped = payload["stamped"]
    message = graph_pb2.BindCache(
        format_version=1,
        header=_document_message({key: payload[key]
                                  for key in ("version", "core_content_hash", "options",
                                              "binder")}),
        stamped_meta=_document_message({key: value for key, value in stamped.items()
                                        if key not in {"nodes", "edges",
                                                       "_typed_bind_cache_path"}}),
        summary=_document_message(payload["summary"]),
    )
    property_cache = {}
    for node in stamped.get("nodes", ()):
        message.nodes.add().CopyFrom(
            _node_message(node, _property_cache=property_cache))
    for edge in stamped.get("edges", ()):
        message.edges.add().CopyFrom(
            _edge_message(edge, _property_cache=property_cache))
    return message.SerializeToString()


def _decode_typed(blob: bytes) -> dict:
    message = graph_pb2.BindCache()
    message.ParseFromString(blob)
    if message.format_version != 1:
        raise ValueError("unsupported typed bind cache format")
    header = _document_value(message.header)
    stamped = _document_value(message.stamped_meta)
    stamped["nodes"] = [decode_node(node.SerializeToString())
                        for node in message.nodes]
    stamped["edges"] = [decode_edge(edge.SerializeToString())
                        for edge in message.edges]
    return {**header, "stamped": stamped,
            "summary": _document_value(message.summary)}


def _varint(blob: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(blob):
        byte = blob[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("invalid bind cache varint")
    raise ValueError("truncated bind cache varint")


def _decode_typed_metadata(blob: bytes) -> dict:
    """Decode only cache metadata while skipping repeated graph records."""
    fields = {}
    offset = 0
    while offset < len(blob):
        key, offset = _varint(blob, offset)
        number, wire = key >> 3, key & 7
        if wire == 2:
            length, offset = _varint(blob, offset)
            end = offset + length
            if end > len(blob):
                raise ValueError("truncated bind cache field")
            if number in {2, 3, 6}:
                fields[number] = blob[offset:end]
            offset = end
        elif wire == 0:
            _, offset = _varint(blob, offset)
        elif wire == 1:
            offset += 8
        elif wire == 5:
            offset += 4
        else:
            raise ValueError("unsupported bind cache wire type")
    if set(fields) != {2, 3, 6}:
        raise ValueError("incomplete typed bind cache")
    header = _document_value(graph_pb2.Document.FromString(fields[2]))
    stamped = _document_value(graph_pb2.Document.FromString(fields[3]))
    summary = _document_value(graph_pb2.Document.FromString(fields[6]))
    return {**header, "stamped": stamped, "summary": summary}


def _load_typed_graph(path: str) -> dict:
    with open(path, "rb") as stream:
        return _decode_typed(stream.read())


def _graph_path(store) -> str | None:
    path = getattr(store, "graph_path", None)
    return path or None


def load(store) -> tuple[dict, dict] | None:
    """Return the cached ``(stamped, summary)`` for this store, or ``None`` on any miss.

    Miss covers every reason not to trust a file: the opt-out, a store with no on-disk path,
    an unkeyable store, an absent/unreadable/undecodable sidecar, or a header that does not
    match this store's content and build options. Every one recomputes -- miss beats wrong.
    """
    if not _enabled():
        return None
    graph_path = _graph_path(store)
    if not graph_path:
        return None
    header = _header(graph_path)
    if not header["core_content_hash"]:
        return None
    try:
        with open(sidecar_path(graph_path), "rb") as stream:
            blob = stream.read()
    except OSError:
        return None
    typed = False
    try:
        document = _decode_typed_metadata(blob)
        typed = True
    except (ValueError, TypeError):
        try:
            document = decode_document(blob)
        except (ValueError, TypeError):
            return None
    if not _header_matches(document, header):
        return None
    stamped, summary = document.get("stamped"), document.get("summary")
    if not isinstance(stamped, dict) or not isinstance(summary, dict):
        return None
    if typed:
        # Keep repeated graph records on disk until a candidate constructor
        # actually needs them. This makes cached enrich metadata-only.
        stamped["_typed_bind_cache_path"] = sidecar_path(graph_path)
        stamped["nodes"] = []
        stamped["edges"] = []
    return stamped, summary


def store(store, stamped: dict, summary: dict) -> None:
    """Persist ``(stamped, summary)`` for this store's content, atomically and under a lock.

    Silently declines whenever it cannot help safely: the opt-out, a store with no path or no
    content hash, a payload the codec cannot represent, or a blob past the size ceiling. The
    write is a tmp-file ``os.replace`` under a per-graph lock, so a concurrent reader never
    sees a half-written file and two binders do not race the same path.
    """
    if not _enabled():
        return
    graph_path = _graph_path(store)
    if not graph_path:
        return
    header = _header(graph_path)
    if not header["core_content_hash"]:
        return
    payload = dict(header)
    payload["stamped"] = stamped
    payload["summary"] = summary
    try:
        blob = _encode_typed(payload)
    except (TypeError, ValueError):
        return
    if len(blob) > _max_bytes():
        return
    path = sidecar_path(graph_path)
    with _lock(path):
        _atomic_write(path, blob)


def _atomic_write(path: str, blob: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    handle, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(blob)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextmanager
def _lock(path: str):
    """Serialize binders writing the same sidecar across processes.

    Keyed to the graph path and placed in the system temp dir (never beside the store, whose
    directory a failed build may remove). A no-op on a platform without ``fcntl`` -- the same
    platforms that have no supported embedded-store runtime, so nothing is lost.
    """
    try:
        import fcntl
    except ImportError:  # pragma: no cover - unsupported runtime platform
        yield
        return
    key = hashlib.sha256(path.encode("utf-8")).hexdigest()[:32]
    lock_path = os.path.join(tempfile.gettempdir(), f"lachesis-bind-{key}.lock")
    with open(lock_path, "a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
