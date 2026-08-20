"""Language-neutral, bounded-memory graph shard storage.

Frontends may emit immutable shards instead of one giant in-memory payload.  Records
are length-framed marshal values: writing and reading are incremental, while the
record shape remains the same JSON-shaped node/edge contract used by snapshots.
"""
from __future__ import annotations

import json
import marshal
import struct
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional, Tuple


SHARD_FORMAT_VERSION = 1
_FRAME = struct.Struct("!I")


def _write_record(handle, record: dict) -> None:
    payload = marshal.dumps(record)
    if len(payload) >= 2 ** 32:
        raise ValueError("graph shard record exceeds 4 GiB frame limit")
    handle.write(_FRAME.pack(len(payload)))
    handle.write(payload)


def _read_records(path: Path) -> Iterator[dict]:
    with path.open("rb") as handle:
        while True:
            header = handle.read(_FRAME.size)
            if not header:
                return
            if len(header) != _FRAME.size:
                raise ValueError(f"truncated shard frame header: {path}")
            (size,) = _FRAME.unpack(header)
            payload = handle.read(size)
            if len(payload) != size:
                raise ValueError(f"truncated shard frame: {path}")
            record = marshal.loads(payload)
            if not isinstance(record, dict):
                raise ValueError(f"shard record is not an object: {path}")
            yield record


class ShardWriter:
    """Append graph records to a shard directory with bounded live memory."""

    def __init__(self, directory: str | Path, *, frontend_id: str, shard_id: str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.frontend_id = frontend_id
        self.shard_id = shard_id
        self._nodes = (self.directory / "nodes.bin").open("wb")
        self._edges = (self.directory / "edges.bin").open("wb")
        self.node_count = 0
        self.edge_count = 0

    def add_node(self, node: dict) -> None:
        _write_record(self._nodes, node)
        self.node_count += 1

    def add_edge(self, edge: dict) -> None:
        _write_record(self._edges, edge)
        self.edge_count += 1

    def close(self) -> None:
        if self._nodes.closed and self._edges.closed:
            return
        self._nodes.close()
        self._edges.close()
        manifest = {
            "shard_format_version": SHARD_FORMAT_VERSION,
            "frontend_id": self.frontend_id,
            "shard_id": self.shard_id,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes_file": "nodes.bin",
            "edges_file": "edges.bin",
        }
        (self.directory / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
        )

    def __enter__(self) -> "ShardWriter":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


class ShardReader:
    """Stream records from one completed shard."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.manifest: Dict[str, object] = json.loads(
            (self.directory / "manifest.json").read_text(encoding="utf-8"),
        )
        if self.manifest.get("shard_format_version") != SHARD_FORMAT_VERSION:
            raise ValueError("unsupported graph shard format")

    def nodes(self) -> Iterator[dict]:
        yield from _read_records(self.directory / str(self.manifest["nodes_file"]))

    def edges(self) -> Iterator[dict]:
        yield from _read_records(self.directory / str(self.manifest["edges_file"]))


def write_snapshot_shard(
    directory: str | Path, *, frontend_id: str, shard_id: str,
    nodes: Iterable[dict], edges: Iterable[dict],
) -> Dict[str, int]:
    """Bridge an existing iterable snapshot into the streaming shard format."""
    with ShardWriter(directory, frontend_id=frontend_id, shard_id=shard_id) as writer:
        for node in nodes:
            writer.add_node(node)
        for edge in edges:
            writer.add_edge(edge)
        return {"nodes": writer.node_count, "edges": writer.edge_count}
