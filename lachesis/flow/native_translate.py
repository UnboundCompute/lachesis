"""Binary boundary for the native Pass-2/Pass-3 engine.

Rust owns preparation, catalog planning, summaries, temporal analysis, and semantic
graph construction. Python only supplies paths and decodes compact protobuf results
needed by the public SDK.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .native_lifetime import match_semantic_path, semantic_path
from lachesis.core import lifetime_pb2
from lachesis.nav.dataflow.substrate import (
    pass2_input_cache_path,
    translation_facts_path,
)


def _compiled_catalog(root, base):
    """Return the versioned binary Atropos catalog for the native planner."""
    models_root = Path(root) / "models"
    model_files = sorted(models_root.rglob("*.json"))
    fingerprint = hashlib.sha256()
    for path in model_files:
        try:
            stat = path.stat()
        except OSError:
            continue
        fingerprint.update(str(path).encode())
        fingerprint.update(str(stat.st_mtime_ns).encode())
        fingerprint.update(str(stat.st_size).encode())
    target = Path(f"{base}.atropos.{fingerprint.hexdigest()[:16]}.catalog.pb")
    if not target.is_file():
        from lachesis.integrations.atropos.native_bind import compile_catalog
        compile_catalog(models_root, target)
    return target


def _base(store):
    index = getattr(store, "index", None)
    return (getattr(index, "_pass3_cache_base", None)
            or getattr(index, "_db_dir", None))


def native_semantic_capable(store, languages=None) -> bool:
    """Return whether the store has the complete binary Pass-2 substrate."""
    base = _base(store)
    return bool(base and translation_facts_path(base).is_file()
                and pass2_input_cache_path(base).is_file())


def native_semantic_sidecar_path(store) -> Path:
    """Return the Rust semantic sidecar location for ``store``."""
    base = _base(store)
    if not base:
        raise RuntimeError("native Pass-3 requires a store-backed binary substrate")
    return Path(f"{base}.pass3.semantic.pb")


def native_match_sidecar_path(semantic_path: str | os.PathLike[str]) -> Path:
    """Return the binary cache for final Pass-3 matcher findings."""
    return Path(f"{semantic_path}.match.pb")


def _sidecar_stale(output: Path, *inputs: Path) -> bool:
    """Return whether a derived binary sidecar must be regenerated."""
    if not output.is_file():
        return True
    try:
        output_mtime = output.stat().st_mtime_ns
        return any(path.stat().st_mtime_ns > output_mtime for path in inputs)
    except OSError:
        return True


def build_native_match_result(semantic_path: str | os.PathLike[str]):
    """Build or load the Rust-owned final matcher result."""
    source = Path(semantic_path)
    event_source = native_semantic_events_path(source)
    if event_source.is_file():
        source = event_source
    output = native_match_sidecar_path(source)
    if _sidecar_stale(output, source):
        match_semantic_path(source, output)
    try:
        result = lifetime_pb2.NativeTemporalResult()
        result.ParseFromString(output.read_bytes())
    except (OSError, ValueError) as error:
        raise RuntimeError("native Pass-3 matcher sidecar is invalid") from error
    return result


def native_match_leads(result) -> list[dict[str, Any]]:
    """Project compact native findings into the public lead record shape."""
    pattern_ids = {
        "pointer-arithmetic-before-validation": "mem.pointer-arithmetic.before-validation",
        "leak": "mem.lifetime.leak",
        "uninitialized-use": "mem.lifetime.uninitialized-use",
        "double-free": "mem.lifetime.double-free",
        "uaf.deref": "mem.lifetime.use-after-free",
        "use.dangling": "mem.lifetime.use-after-free",
        "null-deref": "mem.lifetime.null-deref",
        "use-after-return": "mem.lifetime.use-after-return",
        "realloc-failure-leak": "mem.lifetime.realloc-failure-leak",
        "aggregate-copy-alias": "aggregate-copy-alias",
    }
    leads = []
    for function in result.functions:
        for finding in function.findings:
            path = finding.path
            rendered = path.root if path is not None else "unknown"
            if path is not None and path.selectors:
                rendered += "".join(path.selectors)
            leads.append({
                "pattern": finding.pattern,
                "object": rendered,
                "node": finding.node,
                "entry": finding.function,
                "line": finding.line if finding.has_line else None,
                "is_source": True,
                "guarded": False,
                "value": rendered,
                "var": rendered,
                "at": finding.node,
                "pattern_id": pattern_ids.get(finding.pattern, finding.pattern),
                "evaluator": "typestate",
                "source_reachable": True,
                "source_influenced": True,
                "witness": [finding.node],
                "witness_complete": True,
                "source_context": finding.function,
                "source_function": finding.function,
                "source_entry": finding.function,
                "source_line": finding.line if finding.has_line else None,
                "tier": 1,
            })
    return leads


def _semantic_function_language(function, fallback: str) -> str:
    """Read the optional native language tag across old/new protobuf bindings."""
    explicit = getattr(function, "language", "")
    if explicit:
        return explicit
    identifier = getattr(function, "id", "")
    if ":cpython-ast:" in identifier or ":python:" in identifier:
        return "python"
    if ":typescript-compiler-api:" in identifier or ":typescript:" in identifier:
        return "typescript"
    if ":javascript:" in identifier:
        return "javascript"
    if ":clang-c:" in identifier or ":clang-cpp:" in identifier:
        return "c"
    return fallback


def _decode_native_semantic_result(result, lang="mixed"):
    from .semantic_graph import Event, EventKind, ObjRef, SkeletonGraph

    graph = SkeletonGraph(language=lang)
    for function in result.functions:
        if not function.nodes:
            continue
        node_ids = {node.id for node in function.nodes}
        for node in function.nodes:
            event = None
            if node.event_kind:
                kind = getattr(EventKind, node.event_kind, node.event_kind)
                obj = (ObjRef(node.object_root, tuple(node.object_selectors),
                              node.generation or "g0")
                       if node.object_root else None)
                event = Event(kind, obj=obj, base=obj,
                              path="*" if obj is not None else None,
                              line=node.line if node.has_line else None)
            function_language = _semantic_function_language(function, lang)
            graph.add_node(node.id, event, fragment=function.id,
                           owner_function_id=function.id, native_anchor=node.anchor,
                           language=function_language)
        for edge in function.edges:
            if edge.source in node_ids and edge.target in node_ids:
                graph.add_edge(edge.source, edge.target, kind=edge.kind or "normal")
        exits = [node for node in function.exits if node in node_ids]
        graph.add_fragment(
            function.id,
            function.entry if function.entry in node_ids else function.nodes[0].id,
            exits=exits or [function.nodes[-1].id],
        )
    if not result.complete:
        graph.coverage["converged"] = False
    return graph


def build_native_semantic_graph(store, lang="mixed"):
    """Build or load the Rust semantic graph from the binary Pass-2 substrate."""
    base = _base(store)
    if not base:
        raise RuntimeError("native Pass-3 requires a store-backed binary substrate")
    input_path = pass2_input_cache_path(base)
    if not input_path.is_file():
        raise RuntimeError("native Pass-3 substrate sidecar is missing")
    output_path = native_semantic_sidecar_path(store)
    if _sidecar_stale(output_path, input_path):
        semantic_path(input_path, output_path)
    try:
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(output_path.read_bytes())
    except (OSError, ValueError) as error:
        raise RuntimeError("native Pass-3 semantic sidecar is invalid") from error
    return _decode_native_semantic_result(result, lang)


def ensure_native_semantic_sidecar(store):
    """Publish the Rust semantic sidecar without materializing the graph in Python."""
    base = _base(store)
    if not base or not pass2_input_cache_path(base).is_file():
        raise RuntimeError("native Pass-3 substrate sidecar is missing")
    output_path = native_semantic_sidecar_path(store)
    input_path = pass2_input_cache_path(base)
    if _sidecar_stale(output_path, input_path):
        semantic_path(input_path, output_path)
    events_path = Path(f"{output_path}.events.pb")
    if _sidecar_stale(events_path, input_path, output_path):
        # Regenerate through Rust so the event-only sibling is published atomically.
        temporary = Path(f"{output_path}.events-migrate.{os.getpid()}.pb")
        try:
            semantic_path(input_path, temporary)
            generated = Path(f"{temporary}.events.pb")
            os.replace(generated, events_path)
        finally:
            temporary.unlink(missing_ok=True)
    return output_path


def load_native_semantic_graph_sidecar(path, lang="mixed"):
    """Decode a native semantic sidecar for a scoped SDK/query response."""
    try:
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(Path(path).read_bytes())
    except (OSError, ValueError) as error:
        raise RuntimeError("native Pass-3 semantic sidecar is invalid") from error
    return _decode_native_semantic_result(result, lang)


def native_semantic_events_path(path) -> Path:
    return Path(f"{path}.events.pb")


def load_native_semantic_events_sidecar(path, lang="mixed"):
    """Decode only event nodes from the compact Rust sidecar."""
    from .semantic_graph import Event, EventKind, ObjRef, SkeletonGraph

    try:
        result = lifetime_pb2.NativeSemanticResult()
        result.ParseFromString(native_semantic_events_path(path).read_bytes())
    except (OSError, ValueError) as error:
        raise RuntimeError("native Pass-3 event sidecar is invalid") from error
    graph = SkeletonGraph(language=lang)
    for function in result.functions:
        for node in function.nodes:
            if not node.event_kind:
                continue
            kind = getattr(EventKind, node.event_kind, node.event_kind)
            obj = (ObjRef(node.object_root, tuple(node.object_selectors),
                          node.generation or "g0")
                   if node.object_root else None)
            graph.add_node(
                node.id,
                Event(kind, obj=obj, base=obj, path="*" if obj else None,
                      line=node.line if node.has_line else None),
                fragment=function.id,
                owner_function_id=function.id,
                native_anchor=node.anchor,
            )
    if not result.complete:
        graph.coverage["converged"] = False
    return graph
