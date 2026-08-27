"""Binary boundary for the native Pass-2/Pass-3 engine.

Rust owns preparation, catalog planning, summaries, temporal analysis, and semantic
graph construction. Python only supplies paths and decodes compact protobuf results
needed by the public SDK.
"""
from __future__ import annotations

import os
from pathlib import Path

from .atropos import flow_pattern_id
from .native_lifetime import match_semantic_path, write_semantic_path
from lachesis.core import lifetime_pb2
from lachesis.nav.dataflow.substrate import (
    pass2_input_cache_path,
    translation_facts_path,
)


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
    leads = []
    for function in result.functions:
        for finding in function.findings:
            path = finding.path
            rendered = path.root if path is not None else "unknown"
            if path is not None and path.selectors:
                rendered += "".join(path.selectors)
            witness = (list(finding.source_witness_nodes)
                       if finding.source_witness_nodes
                       else list(finding.witness_nodes))
            lead = {
                "pattern": finding.pattern,
                "object": rendered,
                "node": finding.node,
                "entry": finding.function,
                "line": finding.line if finding.has_line else None,
                "value": rendered,
                "var": rendered,
                "at": finding.node,
                "witness": witness,
                "witness_complete": finding.witness_complete and bool(witness),
            }
            if finding.source_witness_nodes:
                lead["source_witness"] = list(finding.source_witness_nodes)
            if finding.HasField("source_reachable"):
                lead["source_reachable"] = finding.source_reachable
            pattern_id = flow_pattern_id(finding.pattern)
            if pattern_id:
                lead["pattern_id"] = pattern_id
            leads.append(lead)
    return leads


def ensure_native_semantic_sidecar(store, catalog_path=None):
    """Publish the Rust semantic sidecar without materializing the graph in Python."""
    base = _base(store)
    if not base or not pass2_input_cache_path(base).is_file():
        raise RuntimeError("native Pass-3 substrate sidecar is missing")
    output_path = native_semantic_sidecar_path(store)
    input_path = pass2_input_cache_path(base)
    if _sidecar_stale(output_path, input_path):
        # The Rust path publishes both the full semantic sidecar and its
        # compact event sibling in one invocation.  Do not immediately invoke
        # it a second time below on a cold cache.
        write_semantic_path(input_path, output_path, catalog_path)
    else:
        events_path = Path(f"{output_path}.events.pb")
        if not _sidecar_stale(events_path, input_path, output_path):
            return output_path
        # Regenerate through Rust so the event-only sibling is published atomically.
        temporary = Path(f"{output_path}.events-migrate.{os.getpid()}.pb")
        try:
            write_semantic_path(input_path, temporary, catalog_path)
            generated = Path(f"{temporary}.events.pb")
            os.replace(generated, events_path)
        finally:
            temporary.unlink(missing_ok=True)
    return output_path


def native_semantic_events_path(path) -> Path:
    return Path(f"{path}.events.pb")
