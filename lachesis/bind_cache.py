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

from lachesis.core.graph_wire import decode_document, encode_document

# Bump when the persisted shape changes in a way an old file would misdescribe. The header
# match turns a bump into a clean miss (recompute) rather than a decode against stale layout.
BIND_VERSION = 1

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


def _header(graph_path: str) -> dict:
    from lachesis.cache import build_options_fingerprint

    return {
        "version": BIND_VERSION,
        "core_content_hash": _core_hash(graph_path),
        "options": build_options_fingerprint(),
    }


def _header_matches(document: dict, header: dict) -> bool:
    return (document.get("version") == header["version"]
            and document.get("core_content_hash") == header["core_content_hash"]
            and document.get("options") == header["options"])


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
    try:
        document = decode_document(blob)
    except (ValueError, TypeError):
        return None
    if not _header_matches(document, header):
        return None
    stamped, summary = document.get("stamped"), document.get("summary")
    if not isinstance(stamped, dict) or not isinstance(summary, dict):
        return None
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
        blob = encode_document(payload)
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
