"""Protobuf wire helpers for the language-neutral graph stream.

The graph contract is deliberately made of ordinary Python dictionaries at the
frontend boundary. This module is the only conversion seam: on disk, records are
typed protobuf messages with a stable length frame, so a non-Python frontend can
produce/consume the same shards.
"""
from __future__ import annotations

import gzip
import struct
import sys
from pathlib import Path
from typing import Any, Iterator, Mapping

from . import graph_pb2


FRAME = struct.Struct("!I")
WIRE_FORMAT_VERSION = 2
# Additive dataflow sidecars can be written while overlays run.  The legacy
# DataflowOverlay protobuf remains readable; this framed variant avoids retaining
# every derived record in a second protobuf message before writing it.
DATAFLOW_STREAM_MAGIC = b"LACHESIS-DATAFLOW-STREAM\x00"


def _varint(value: int) -> bytes:
    out = bytearray()
    value = int(value)
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _field_bytes(number: int, payload: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(payload)) + payload


def _value(value: Any) -> graph_pb2.Value:
    result = graph_pb2.Value()
    if value is None:
        result.null_value.SetInParent()
    elif isinstance(value, bool):
        result.boolean = value
    elif isinstance(value, int):
        result.integer = value
    elif isinstance(value, float):
        result.real = value
    elif isinstance(value, bytes):
        result.binary = value
    elif isinstance(value, str):
        result.text = value
    elif isinstance(value, (list, tuple)):
        result.list.values.extend((_value(item) for item in value))
        result.list.SetInParent()
    elif isinstance(value, Mapping):
        for key in sorted(value, key=str):
            field = result.object.fields.add(key=str(key))
            field.value.CopyFrom(_value(value[key]))
        result.object.SetInParent()
    else:
        raise TypeError(f"unsupported graph property value: {type(value).__name__}")
    return result


_CACHE_SKIP_KEYS = frozenset({
    "file", "absolute_file", "content_hash", "compiler_node_id",
    "start_offset", "end_offset", "start_line", "end_line",
})
_CACHEABLE_KEYS = frozenset({
    "confidence", "fact_origin", "evidence_ids", "via", "resolution",
    "reason", "target_tier", "semantic_kind",
})


def _property_cache_key(values: Mapping[str, Any]) -> tuple | None:
    """Fast key for the small, repeated metadata maps used by graph edges."""
    if any(key not in _CACHEABLE_KEYS for key in values):
        return None
    parts = []
    for key, value in values.items():
        if isinstance(value, (list, tuple)):
            if not all(isinstance(item, (str, bytes, int, float, bool, type(None)))
                       for item in value):
                return None
            value = tuple((type(item).__name__, item) for item in value)
        elif not isinstance(value, (str, bytes, int, float, bool, type(None))):
            return None
        parts.append((str(key), type(value).__name__, value))
    return tuple(sorted(parts))


def _properties(
    values: Mapping[str, Any] | None,
    cache: dict | None = None,
) -> list[graph_pb2.Field]:
    cache_key = None
    properties = values or {}
    cache_key = None
    cacheable = (cache is not None and len(properties) <= 8
                 and not _CACHE_SKIP_KEYS.intersection(properties))
    if cacheable:
        cache_key = _property_cache_key(properties)
        cacheable = cache_key is not None
        if cacheable:
            cached = cache.get(cache_key)
            if cached is not None:
                return list(cached)
    fields = []
    for key in sorted(values or {}, key=str):
        field = graph_pb2.Field(key=str(key))
        field.value.CopyFrom(_value(values[key]))
        fields.append(field)
    if cacheable and len(cache) < 1024:
        cache[cache_key] = tuple(fields)
    return fields


def _from_value(value: graph_pb2.Value) -> Any:
    kind = value.WhichOneof("kind")
    if kind == "null_value":
        return None
    if kind == "text":
        return value.text
    if kind == "integer":
        return value.integer
    if kind == "real":
        return value.real
    if kind == "boolean":
        return value.boolean
    if kind == "binary":
        return bytes(value.binary)
    if kind == "list":
        return [_from_value(item) for item in value.list.values]
    if kind == "object":
        # Intern the property key: a graph holds the same few dozen field names
        # (``file``, ``start_line``, ``event_kind`` ...) once per node, so without
        # interning the same key string is reallocated hundreds of thousands of times
        # and every copy is retained inside the property dicts. Interning collapses
        # them to one object per name; a dict is unchanged by whether its keys are
        # interned, so lookups, iteration order, equality, JSON and digests all match.
        return {sys.intern(field.key): _from_value(field.value)
                for field in value.object.fields}
    raise ValueError("protobuf graph value has no kind")


def _read_properties(fields, wanted: set[str] | None = None) -> dict[str, Any]:
    if wanted is None:
        return {sys.intern(field.key): _from_value(field.value) for field in fields}
    return {sys.intern(field.key): _from_value(field.value)
            for field in fields if field.key in wanted}


def _node_message(record: Mapping[str, Any], *, _property_cache: dict | None = None):
    message = graph_pb2.NodeRecord(
        id=str(record.get("id", "")), kind=str(record.get("kind", "")),
        label=str(record.get("label", "")), tier=str(record.get("tier", "")),
    )
    message.properties.extend(_properties(record.get("properties"), _property_cache))
    return message


def encode_node(record: Mapping[str, Any], *, _property_cache: dict | None = None) -> bytes:
    message = _node_message(record, _property_cache=_property_cache)
    return message.SerializeToString()


def decode_node(payload: bytes, *, properties: bool = True) -> dict[str, Any]:
    message = graph_pb2.NodeRecord()
    message.ParseFromString(payload)
    record = {"id": message.id}
    if message.kind:
        record["kind"] = message.kind
    if message.label:
        record["label"] = message.label
    if message.properties:
        record["properties"] = _read_properties(
            message.properties,
            None if properties else {"file", "compiler_node_id"},
        )
    if message.tier:
        record["tier"] = message.tier
    return record


def _edge_message(record: Mapping[str, Any], *, _property_cache: dict | None = None):
    message = graph_pb2.EdgeRecord(
        kind=str(record.get("kind", "")), source=str(record.get("source", "")),
        target=str(record.get("target", "")),
        source_tier=str(record.get("source_tier", "")),
        relationship_class=str(record.get("relationship_class", "")),
    )
    message.properties.extend(_properties(record.get("properties"), _property_cache))
    return message


def encode_edge(record: Mapping[str, Any], *, _property_cache: dict | None = None) -> bytes:
    message = _edge_message(record, _property_cache=_property_cache)
    return message.SerializeToString()


def decode_edge(payload: bytes, *, properties: bool = True) -> dict[str, Any]:
    message = graph_pb2.EdgeRecord()
    message.ParseFromString(payload)
    record = {"source": message.source, "target": message.target}
    if message.kind:
        record["kind"] = message.kind
    if properties and message.properties:
        record["properties"] = _read_properties(message.properties)
    if message.source_tier:
        record["source_tier"] = message.source_tier
    if message.relationship_class:
        record["relationship_class"] = message.relationship_class
    return record


def encode_overlay(payload: Mapping[str, Any]) -> bytes:
    message = graph_pb2.DataflowOverlay(
        overlay_id=str(payload.get("overlay_id", "dataflow")),
        source=str(payload.get("source", "")), version=int(payload.get("version", 1)),
        core_content_hash=str(payload.get("core_content_hash", "")),
    )
    # Build child messages directly.  The old implementation serialized every
    # record and parsed it back into the repeated field, doing two protobuf
    # traversals and allocating a temporary bytes object per record.
    property_cache = {}
    for node in payload.get("derived_nodes", []):
        message.derived_nodes.add().CopyFrom(
            _node_message(node, _property_cache=property_cache)
        )
    for edge in payload.get("derived_edges", []):
        message.derived_edges.add().CopyFrom(
            _edge_message(edge, _property_cache=property_cache)
        )
    return message.SerializeToString()


def decode_overlay(payload: bytes) -> dict[str, Any]:
    message = graph_pb2.DataflowOverlay()
    message.ParseFromString(payload)
    return {
        "overlay_id": message.overlay_id, "source": message.source,
        "version": message.version, "core_content_hash": message.core_content_hash,
        "derived_nodes": [decode_node(item.SerializeToString()) for item in message.derived_nodes],
        "derived_edges": [decode_edge(item.SerializeToString()) for item in message.derived_edges],
    }


def _overlay_header(payload: Mapping[str, Any]) -> bytes:
    return graph_pb2.DataflowOverlay(
        overlay_id=str(payload.get("overlay_id", "dataflow")),
        source=str(payload.get("source", "")), version=int(payload.get("version", 1)),
        core_content_hash=str(payload.get("core_content_hash", "")),
    ).SerializeToString()


def write_dataflow_stream_header(handle, payload: Mapping[str, Any]) -> None:
    """Start a streaming additive dataflow sidecar."""
    handle.write(DATAFLOW_STREAM_MAGIC)
    write_frame(handle, _overlay_header(payload))


def write_dataflow_stream_node(handle, node: Mapping[str, Any]) -> None:
    write_frame(handle, b"N" + encode_node(node))


def write_dataflow_stream_edge(handle, edge: Mapping[str, Any]) -> None:
    write_frame(handle, b"E" + encode_edge(edge))


def is_dataflow_stream(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(DATAFLOW_STREAM_MAGIC)) == DATAFLOW_STREAM_MAGIC
    except OSError:
        return False


def read_dataflow_stream_header(path: Path) -> dict[str, Any]:
    """Read only stream metadata for cheap cache validation."""
    with path.open("rb") as handle:
        if handle.read(len(DATAFLOW_STREAM_MAGIC)) != DATAFLOW_STREAM_MAGIC:
            raise ValueError(f"not a dataflow stream: {path}")
        header = handle.read(FRAME.size)
        if len(header) != FRAME.size:
            raise ValueError(f"truncated dataflow stream header: {path}")
        (size,) = FRAME.unpack(header)
        payload = handle.read(size)
        if len(payload) != size:
            raise ValueError(f"truncated dataflow stream header: {path}")
        message = graph_pb2.DataflowOverlay()
        message.ParseFromString(payload)
        return {
            "overlay_id": message.overlay_id, "source": message.source,
            "version": message.version, "core_content_hash": message.core_content_hash,
        }


def read_dataflow_stream(path: Path) -> dict[str, Any]:
    """Read a framed dataflow sidecar without requiring one giant input bytestring."""
    with path.open("rb") as handle:
        if handle.read(len(DATAFLOW_STREAM_MAGIC)) != DATAFLOW_STREAM_MAGIC:
            raise ValueError(f"not a dataflow stream: {path}")
        header = handle.read(FRAME.size)
        if len(header) != FRAME.size:
            raise ValueError(f"truncated dataflow stream header: {path}")
        (size,) = FRAME.unpack(header)
        payload = handle.read(size)
        if len(payload) != size:
            raise ValueError(f"truncated dataflow stream header: {path}")
        message = graph_pb2.DataflowOverlay()
        message.ParseFromString(payload)
        result = {
            "overlay_id": message.overlay_id, "source": message.source,
            "version": message.version, "core_content_hash": message.core_content_hash,
            "node_props": {}, "edge_props": {},
            "derived_nodes": [], "derived_edges": [],
        }
        while True:
            header = handle.read(FRAME.size)
            if not header:
                break
            if len(header) != FRAME.size:
                raise ValueError(f"truncated dataflow stream frame header: {path}")
            (size,) = FRAME.unpack(header)
            frame = handle.read(size)
            if len(frame) != size or not frame:
                raise ValueError(f"truncated dataflow stream frame: {path}")
            kind, record = frame[:1], frame[1:]
            if kind == b"N":
                result["derived_nodes"].append(decode_node(record))
            elif kind == b"E":
                result["derived_edges"].append(decode_edge(record))
            else:
                raise ValueError(f"unknown dataflow stream record {kind!r}")
    # The stream is written in deterministic overlay order.  Restore the same
    # canonical view ordering used by the legacy monolithic sidecar on load.
    result["derived_nodes"].sort(key=lambda node: node["id"])
    result["derived_edges"].sort(key=lambda edge: (
        edge.get("kind") or "", edge.get("source") or "", edge.get("target") or "",
    ))
    return result


def encode_tier(payload: Mapping[str, Any]) -> bytes:
    """Encode a frontend tier with typed node/edge records."""
    message = graph_pb2.TierPayload(
        tier=str(payload.get("tier") or ""), name=str(payload.get("name") or "")
    )
    for node in payload.get("nodes", ()):
        message.nodes.add().ParseFromString(encode_node(node))
    for field in ("edges", "expands_to", "links"):
        for edge in payload.get(field, ()):
            message.__getattribute__(field).add().ParseFromString(encode_edge(edge))
    return message.SerializeToString()


def decode_tier(payload: bytes) -> dict[str, Any]:
    message = graph_pb2.TierPayload()
    message.ParseFromString(payload)
    return {
        "tier": message.tier,
        "name": message.name,
        "nodes": [decode_node(item.SerializeToString()) for item in message.nodes],
        "edges": [decode_edge(item.SerializeToString()) for item in message.edges],
        "expands_to": [decode_edge(item.SerializeToString()) for item in message.expands_to],
        "links": [decode_edge(item.SerializeToString()) for item in message.links],
    }


def write_tier(path: str | Path, payload: Mapping[str, Any]) -> None:
    """Write a typed tier incrementally without materializing its outer message."""
    property_cache: dict = {}
    with open(path, "wb") as handle:
        handle.write(_field_bytes(1, str(payload.get("tier") or "").encode()))
        handle.write(_field_bytes(2, str(payload.get("name") or "").encode()))
        for node in payload.get("nodes", ()):
            handle.write(_field_bytes(3, encode_node(node, _property_cache=property_cache)))
        for field, tag in (("edges", 4), ("expands_to", 5), ("links", 6)):
            for edge in payload.get(field, ()):
                handle.write(_field_bytes(
                    tag, encode_edge(edge, _property_cache=property_cache)))


def _take_varint(buffer: bytearray):
    value = 0
    shift = 0
    for index, byte in enumerate(buffer):
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index + 1
        shift += 7
        if shift > 63:
            raise ValueError("protobuf varint is too long")
    return None


def iter_tier_records(path: str | Path, *, raw: bool = False):
    """Yield typed tier records while reading a tier file in bounded chunks."""
    buffer = bytearray()
    with open(path, "rb") as handle:
        eof = False
        while True:
            if not eof:
                chunk = handle.read(1024 * 1024)
                if chunk:
                    buffer.extend(chunk)
                else:
                    eof = True
            while buffer:
                key = _take_varint(buffer)
                if key is None:
                    break
                wire_key, key_size = key
                number = wire_key >> 3
                length = _take_varint(buffer[key_size:])
                if length is None:
                    break
                size, length_size = length
                start = key_size + length_size
                end = start + size
                if len(buffer) < end:
                    break
                payload = bytes(buffer[start:end])
                del buffer[:end]
                if number == 3:
                    yield "nodes", payload if raw else decode_node(payload)
                elif number in (4, 5, 6):
                    collection = {4: "edges", 5: "expands_to", 6: "links"}[number]
                    yield collection, payload if raw else decode_edge(payload)
            if eof:
                if buffer:
                    raise ValueError(f"truncated protobuf tier: {path}")
                return


def encode_document(payload: Mapping[str, Any], *, version: int = 1) -> bytes:
    message = graph_pb2.Document(format_version=version)
    value = _value(dict(payload))
    message.fields.CopyFrom(value.object)
    return message.SerializeToString()


def decode_document(payload: bytes) -> dict[str, Any]:
    message = graph_pb2.Document()
    message.ParseFromString(payload)
    if message.format_version != 1:
        raise ValueError("unsupported protobuf document format")
    value = graph_pb2.Value()
    value.object.CopyFrom(message.fields)
    return _from_value(value)


def write_frame(handle, payload: bytes) -> None:
    if len(payload) >= 2**32:
        raise ValueError("graph protobuf record exceeds 4 GiB frame limit")
    # Keep the length prefix and payload in one buffered write.  Large Pass-1
    # builds emit millions of frames; two Python file-method calls per frame
    # add measurable interpreter overhead while producing identical bytes.
    handle.write(FRAME.pack(len(payload)) + payload)


_FRAME_GZIP_MAGIC = b"\x1f\x8b"


def read_frames(path: Path) -> Iterator[bytes]:
    # The sidecar may be gzip-framed (the native writer compresses it); the gzip
    # magic cannot collide with a raw frame's 4-byte big-endian length prefix,
    # whose leading byte is 0x00 for any frame under 16 MiB.  gzip.open streams
    # the decode, so a compressed sidecar is read with the same bounded memory as
    # the raw one.
    with path.open("rb") as probe:
        compressed = probe.read(2) == _FRAME_GZIP_MAGIC
    opener = gzip.open if compressed else (lambda p, mode: Path(p).open(mode))
    with opener(path, "rb") as handle:
        while True:
            header = handle.read(FRAME.size)
            if not header:
                return
            if len(header) != FRAME.size:
                raise ValueError(f"truncated protobuf frame header: {path}")
            (size,) = FRAME.unpack(header)
            payload = handle.read(size)
            if len(payload) != size:
                raise ValueError(f"truncated protobuf frame: {path}")
            yield payload
