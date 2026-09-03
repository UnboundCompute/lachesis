"""Binary boundary for the native Pass-2/Pass-3 engine.

Rust owns preparation, catalog planning, summaries, temporal analysis, and semantic
graph construction. Python only supplies paths and decodes compact protobuf results
needed by the public SDK.
"""
from __future__ import annotations

import mmap
import os
from pathlib import Path

from .native_lifetime import match_semantic_path, write_semantic_path
from lachesis.core import lifetime_pb2
from lachesis.nav.dataflow.substrate import (
    pass2_input_cache_path,
    substrate_cache_path,
    translation_facts_path,
)


def _base(store):
    index = getattr(store, "index", None)
    return (getattr(index, "_pass3_cache_base", None)
            or getattr(index, "_db_dir", None))


def native_semantic_capable(store, languages=None) -> bool:
    """Return whether the store has the complete binary Pass-2 substrate.

    The translation facts (`.pass2.facts.pb`) are *not* required here: a
    large-graph build defers them to keep the projection off the build peak, and
    the semantic pass recomputes them from the substrate when absent (see
    ``lachesis_lifetime_semantic_path``).  Capability therefore turns on the two
    sidecars the pass actually consumes -- the Pass-2 input and the substrate the
    recompute reads -- not on the derived facts file.
    """
    base = _base(store)
    return bool(base and pass2_input_cache_path(base).is_file()
                and substrate_cache_path(base).is_file())


def native_semantic_sidecar_path(store) -> Path:
    """Return the Rust semantic sidecar location for ``store``."""
    base = _base(store)
    if not base:
        raise RuntimeError("native Pass-3 requires a store-backed binary substrate")
    return Path(f"{base}.pass3.semantic.pb")


def native_catalog_path(store) -> Path | None:
    """Return the compiled Atropos catalog for a store, when available.

    Catalog authoring is allowed to use its source files during setup, but the
    native analysis boundary receives only the fingerprinted protobuf artifact.
    Keeping this lookup here makes every Rust entrypoint use the same catalog
    contract without opening graph data in Python.
    """
    base = _base(store)
    if not base:
        return None
    try:
        from lachesis.integrations.atropos.enrich import locate_atropos
        from lachesis.integrations.atropos.native_bind import compiled_catalog
        root = locate_atropos()
        return compiled_catalog(root, base) if root is not None else None
    except (OSError, ValueError):
        return None


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


def ensure_native_match_sidecar(
        semantic_path: str | os.PathLike[str],
        catalog_path: str | os.PathLike[str] | None = None) -> Path:
    """Publish the final Pass-3 matcher sidecar and return its path.

    Resolves the compact event sibling as the matcher input when present, then
    runs the Rust matcher only when the sidecar is stale.  This is the shared
    first half of ``build_native_match_result``; callers that need only a
    summary of the result (see ``native_match_any_capped``) use this without
    parsing the whole findings protobuf into Python.
    """
    source = Path(semantic_path)
    event_source = native_semantic_events_path(source)
    if event_source.is_file():
        source = event_source
    output = native_match_sidecar_path(source)
    if _sidecar_stale(output, source):
        match_semantic_path(source, output, catalog_path)
    return output


def build_native_match_result(semantic_path: str | os.PathLike[str],
                              catalog_path: str | os.PathLike[str] | None = None):
    """Build or load the Rust-owned final matcher result."""
    output = ensure_native_match_sidecar(semantic_path, catalog_path)
    try:
        result = lifetime_pb2.NativeTemporalResult()
        result.ParseFromString(output.read_bytes())
    except (OSError, ValueError) as error:
        raise RuntimeError("native Pass-3 matcher sidecar is invalid") from error
    return result


def _read_varint(buf, pos: int) -> tuple[int, int]:
    """Decode one base-128 varint from ``buf`` at ``pos``; return (value, next)."""
    result = shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def _skip_field(buf, pos: int, wire_type: int) -> int:
    """Advance ``pos`` past one field payload of the given wire type."""
    if wire_type == 0:            # varint
        _, pos = _read_varint(buf, pos)
        return pos
    if wire_type == 2:            # length-delimited
        length, pos = _read_varint(buf, pos)
        return pos + length
    if wire_type == 1:            # 64-bit
        return pos + 8
    if wire_type == 5:            # 32-bit
        return pos + 4
    raise ValueError(f"unsupported protobuf wire type {wire_type}")


def native_match_any_capped(match_path: str | os.PathLike[str]) -> bool:
    """Return whether any function in the match sidecar was capped.

    The bind's convergence check needs only this one bit, but the sidecar is
    dominated by per-finding witnesses (~160 MB on suricata) that a full
    ``NativeTemporalResult`` parse would materialize into ~350 MB of Python
    objects.  Scan the protobuf wire form over a read-only mmap instead: walk
    the top-level ``functions`` (field 1) and, inside each, read only ``capped``
    (field 5, a varint), skipping the ``findings`` bytes without decoding them.
    Nothing but the file-backed mapping is held resident, and the answer is
    byte-identical to ``any(f.capped for f in result.functions)``.
    """
    with open(match_path, "rb") as handle:
        # An empty sidecar carries no functions, so nothing is capped; mmap also
        # rejects a zero-length mapping, so short-circuit before mapping.
        if os.fstat(handle.fileno()).st_size == 0:
            return False
        mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        buf = memoryview(mapped)
        pos, end = 0, len(buf)
        while pos < end:
            tag, pos = _read_varint(buf, pos)
            field, wire_type = tag >> 3, tag & 7
            if field == 1 and wire_type == 2:
                length, pos = _read_varint(buf, pos)
                fn_end = pos + length
                while pos < fn_end:
                    inner_tag, pos = _read_varint(buf, pos)
                    inner_field, inner_wire = inner_tag >> 3, inner_tag & 7
                    if inner_field == 5 and inner_wire == 0:
                        value, pos = _read_varint(buf, pos)
                        if value:
                            return True
                    else:
                        pos = _skip_field(buf, pos, inner_wire)
                pos = fn_end
            else:
                pos = _skip_field(buf, pos, wire_type)
        return False
    finally:
        buf.release()
        mapped.close()


def _read_path_message(buf, pos: int, end: int) -> str:
    """Render a ``Path`` (field 1 root, field 2 repeated selectors) as root+selectors."""
    root, selectors = "", []
    while pos < end:
        tag, pos = _read_varint(buf, pos)
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2:            # root
            length, pos = _read_varint(buf, pos)
            root = bytes(buf[pos:pos + length]).decode("utf-8", "replace")
            pos += length
        elif field == 2 and wire == 2:          # selectors
            length, pos = _read_varint(buf, pos)
            selectors.append(bytes(buf[pos:pos + length]).decode("utf-8", "replace"))
            pos += length
        else:
            pos = _skip_field(buf, pos, wire)
    return (root + "".join(selectors)) if root else ""


def _read_temporal_finding(buf, pos: int, end: int) -> dict[str, Any]:
    """Read one ``NativeTemporalFinding``, keeping only the census-relevant fields.

    The matcher's per-finding CFG witnesses (fields 7+) dominate the sidecar and
    are never consulted by the candidate census, so they are skipped: only
    ``pattern`` (2), ``path`` (3), ``line`` (4, a zig-zag ``sint64`` gated by
    ``has_line`` field 5) and ``node`` (6) are decoded.
    """
    pattern = node = ""
    rendered_path = ""
    line_raw = None
    has_line = False
    while pos < end:
        tag, pos = _read_varint(buf, pos)
        field, wire = tag >> 3, tag & 7
        if field == 2 and wire == 2:            # pattern
            length, pos = _read_varint(buf, pos)
            pattern = bytes(buf[pos:pos + length]).decode("utf-8", "replace")
            pos += length
        elif field == 3 and wire == 2:          # path
            length, pos = _read_varint(buf, pos)
            rendered_path = _read_path_message(buf, pos, pos + length)
            pos += length
        elif field == 4 and wire == 0:          # line (sint64, zig-zag)
            raw, pos = _read_varint(buf, pos)
            line_raw = (raw >> 1) ^ -(raw & 1)
        elif field == 5 and wire == 0:          # has_line
            value, pos = _read_varint(buf, pos)
            has_line = bool(value)
        elif field == 6 and wire == 2:          # node
            length, pos = _read_varint(buf, pos)
            node = bytes(buf[pos:pos + length]).decode("utf-8", "replace")
            pos += length
        else:
            pos = _skip_field(buf, pos, wire)
    return {"pattern": pattern, "node": node, "path": rendered_path,
            "line": line_raw if has_line else None}


def load_native_temporal(match_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Project the Rust matcher's correlated findings into the census bind shape.

    The candidate census only needs each temporal finding's pattern, node, line
    and object path to route it to a family and render a confirmed candidate; the
    per-finding witnesses (~160 MB on suricata) that dominate the match sidecar
    are never read here.  Scan the ``NativeTemporalResult`` wire form over a
    read-only mmap -- mirroring :func:`native_match_any_capped` -- walking
    ``functions`` (field 1) and, inside each, ``id`` (field 1) and ``findings``
    (field 2).  The returned ``{"functions": [{"id", "findings": [...]}]}`` is
    exactly what :class:`~lachesis.planner.temporal_obligation.TemporalLifecycle`
    consumes, so the matcher's confirmed temporal relation replaces the vacuous
    per-dereference inventory in the census.
    """
    functions: list[dict[str, Any]] = []
    result = {"functions": functions}
    path = Path(match_path)
    try:
        if path.stat().st_size == 0:
            return result
    except OSError:
        return result
    with open(path, "rb") as handle:
        mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        buf = memoryview(mapped)
        pos, end = 0, len(buf)
        while pos < end:
            tag, pos = _read_varint(buf, pos)
            field, wire = tag >> 3, tag & 7
            if field == 1 and wire == 2:                # NativeTemporalFunction
                length, pos = _read_varint(buf, pos)
                fn_end = pos + length
                fn_id, findings = "", []
                while pos < fn_end:
                    inner_tag, pos = _read_varint(buf, pos)
                    inner_field, inner_wire = inner_tag >> 3, inner_tag & 7
                    if inner_field == 1 and inner_wire == 2:      # function id
                        n, pos = _read_varint(buf, pos)
                        fn_id = bytes(buf[pos:pos + n]).decode("utf-8", "replace")
                        pos += n
                    elif inner_field == 2 and inner_wire == 2:    # findings
                        n, pos = _read_varint(buf, pos)
                        findings.append(_read_temporal_finding(buf, pos, pos + n))
                        pos += n
                    else:
                        pos = _skip_field(buf, pos, inner_wire)
                pos = fn_end
                functions.append({"id": fn_id, "findings": findings})
            else:
                pos = _skip_field(buf, pos, wire)
    finally:
        buf.release()
        mapped.close()
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
            witness = list(finding.witness_nodes)
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
                "analysis_complete": not function.capped,
                "truncated": function.capped,
                "guarded": finding.guarded,
                "guards": [{"kind": guard.kind, "value": guard.value}
                           for guard in finding.guards],
            }
            if finding.source_witness_nodes:
                lead["source_witness"] = list(finding.source_witness_nodes)
            if finding.HasField("source_reachable"):
                lead["source_reachable"] = finding.source_reachable
            if finding.HasField("source_influenced"):
                lead["source_influenced"] = finding.source_influenced
            if finding.family:
                lead["family"] = finding.family
            if finding.pattern_id:
                lead["pattern_id"] = finding.pattern_id
            if finding.evaluator:
                lead["evaluator"] = finding.evaluator
            if finding.tier:
                lead["tier"] = finding.tier
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
