"""Protobuf wire helpers for the language-neutral graph stream.

The graph contract is deliberately made of ordinary Python dictionaries at the
frontend boundary. This module is the only conversion seam: on disk, records are
typed protobuf messages with a stable length frame, so a non-Python frontend can
produce/consume the same shards.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Iterator, Mapping

from . import graph_pb2


FRAME = struct.Struct("!I")
WIRE_FORMAT_VERSION = 2


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


def _properties(values: Mapping[str, Any] | None) -> list[graph_pb2.Field]:
    fields = []
    for key in sorted(values or {}, key=str):
        field = graph_pb2.Field(key=str(key))
        field.value.CopyFrom(_value(values[key]))
        fields.append(field)
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
        return {field.key: _from_value(field.value) for field in value.object.fields}
    raise ValueError("protobuf graph value has no kind")


def _read_properties(fields) -> dict[str, Any]:
    return {field.key: _from_value(field.value) for field in fields}


def encode_node(record: Mapping[str, Any]) -> bytes:
    message = graph_pb2.NodeRecord(
        id=str(record.get("id", "")), kind=str(record.get("kind", "")),
        label=str(record.get("label", "")), tier=str(record.get("tier", "")),
    )
    message.properties.extend(_properties(record.get("properties")))
    return message.SerializeToString()


def decode_node(payload: bytes) -> dict[str, Any]:
    message = graph_pb2.NodeRecord()
    message.ParseFromString(payload)
    record = {"id": message.id}
    if message.kind:
        record["kind"] = message.kind
    if message.label:
        record["label"] = message.label
    if message.properties:
        record["properties"] = _read_properties(message.properties)
    if message.tier:
        record["tier"] = message.tier
    return record


def encode_edge(record: Mapping[str, Any]) -> bytes:
    message = graph_pb2.EdgeRecord(
        kind=str(record.get("kind", "")), source=str(record.get("source", "")),
        target=str(record.get("target", "")),
        source_tier=str(record.get("source_tier", "")),
        relationship_class=str(record.get("relationship_class", "")),
    )
    message.properties.extend(_properties(record.get("properties")))
    return message.SerializeToString()


def decode_edge(payload: bytes) -> dict[str, Any]:
    message = graph_pb2.EdgeRecord()
    message.ParseFromString(payload)
    record = {"source": message.source, "target": message.target}
    if message.kind:
        record["kind"] = message.kind
    if message.properties:
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
    for node in payload.get("derived_nodes", []):
        message.derived_nodes.add().ParseFromString(encode_node(node))
    for edge in payload.get("derived_edges", []):
        message.derived_edges.add().ParseFromString(encode_edge(edge))
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
    handle.write(FRAME.pack(len(payload)))
    handle.write(payload)


def read_frames(path: Path) -> Iterator[bytes]:
    with path.open("rb") as handle:
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
