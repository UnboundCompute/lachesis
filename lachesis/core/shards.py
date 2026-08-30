"""Language-neutral, bounded-memory graph shard storage.

Frontends may emit immutable shards instead of one giant in-memory payload.  Records
are length-framed protobuf values: writing and reading are incremental, while the
record shape remains the same language-neutral node/edge contract used by snapshots.
"""
from __future__ import annotations

from itertools import chain
from pathlib import Path
import shutil
from typing import Dict, Iterable, Iterator, Optional, Tuple

from . import graph_pb2
from .graph_wire import (
    WIRE_FORMAT_VERSION, decode_edge, decode_node, encode_edge, encode_node,
    read_frames, write_frame,
)


SHARD_FORMAT_VERSION = WIRE_FORMAT_VERSION


class ShardWriter:
    """Append graph records to a shard directory with bounded live memory."""

    def __init__(self, directory: str | Path, *, frontend_id: str, shard_id: str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.frontend_id = frontend_id
        self.shard_id = shard_id
        self._nodes = (self.directory / "nodes.pb").open("wb")
        self._edges = (self.directory / "edges.pb").open("wb")
        self.node_count = 0
        self.edge_count = 0

    def add_node(self, node: dict) -> None:
        write_frame(self._nodes, encode_node(node))
        self.node_count += 1

    def add_node_payload(self, payload: bytes) -> None:
        write_frame(self._nodes, payload)
        self.node_count += 1

    def add_edge(self, edge: dict) -> None:
        write_frame(self._edges, encode_edge(edge))
        self.edge_count += 1

    def add_edge_payload(self, payload: bytes) -> None:
        write_frame(self._edges, payload)
        self.edge_count += 1

    def close(self) -> None:
        if self._nodes.closed and self._edges.closed:
            return
        self._nodes.close()
        self._edges.close()
        manifest = graph_pb2.ShardManifest(
            format_version=SHARD_FORMAT_VERSION,
            frontend_id=self.frontend_id, shard_id=self.shard_id,
            node_count=self.node_count, edge_count=self.edge_count,
            nodes_file="nodes.pb", edges_file="edges.pb",
        )
        (self.directory / "manifest.pb").write_bytes(manifest.SerializeToString())

    def __enter__(self) -> "ShardWriter":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


class ShardReader:
    """Stream records from one completed shard."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        manifest_path = self.directory / "manifest.pb"
        if manifest_path.is_file():
            message = graph_pb2.ShardManifest()
            message.ParseFromString(manifest_path.read_bytes())
            if message.format_version != SHARD_FORMAT_VERSION:
                raise ValueError("unsupported graph protobuf shard format")
            self.manifest = {
                "shard_format_version": message.format_version,
                "frontend_id": message.frontend_id, "shard_id": message.shard_id,
                "node_count": message.node_count, "edge_count": message.edge_count,
                "nodes_file": message.nodes_file, "edges_file": message.edges_file,
            }
        else:
            raise ValueError("missing protobuf shard manifest; rebuild shards")

    def nodes(self, *, headers_only: bool = False) -> Iterator[dict]:
        path = self.directory / str(self.manifest["nodes_file"])
        yield from (decode_node(payload, properties=not headers_only)
                    for payload in read_frames(path))

    def raw_nodes(self) -> Iterator[bytes]:
        """Yield the original protobuf node payloads without a dict round-trip."""
        path = self.directory / str(self.manifest["nodes_file"])
        yield from read_frames(path)

    def edges(self, *, headers_only: bool = False) -> Iterator[dict]:
        path = self.directory / str(self.manifest["edges_file"])
        yield from (decode_edge(payload, properties=not headers_only)
                    for payload in read_frames(path))

    def raw_edges(self) -> Iterator[bytes]:
        """Yield the original protobuf edge payloads without a dict round-trip."""
        path = self.directory / str(self.manifest["edges_file"])
        yield from read_frames(path)

    def raw_shard_paths(self):
        """Return the immutable framed files for native path-based consumers."""
        return ((self.manifest["frontend_id"],
                 self.directory / str(self.manifest["nodes_file"]),
                 self.directory / str(self.manifest["edges_file"])),)


class ShardSetReader:
    """Read a completed shard-set manifest in deterministic shard order."""

    def __init__(self, manifest_path: str | Path) -> None:
        self.manifest_path = Path(manifest_path)
        if self.manifest_path.suffix == ".pb":
            message = graph_pb2.ShardSetManifest()
            message.ParseFromString(self.manifest_path.read_bytes())
            if message.format_version != SHARD_FORMAT_VERSION:
                raise ValueError("unsupported graph protobuf shard-set format")
            self.manifest = {
                "shard_format_version": message.format_version,
                "frontend_id": message.frontend_id,
                "shards": [
                    {"shard_id": item.shard_id, "directory": item.directory,
                     "status": item.status, "node_count": item.node_count,
                     "edge_count": item.edge_count}
                    for item in message.shards
                ],
            }
        else:
            raise ValueError("JSON shard-set manifests are no longer supported; rebuild shards")
        self._root = self.manifest_path.parent

    def _shards(self) -> Iterator[ShardReader]:
        entries = self.manifest.get("shards", [])
        if not isinstance(entries, list):
            raise ValueError("shard-set manifest has invalid `shards`")
        for entry in sorted(entries, key=lambda item: str(item.get("shard_id", ""))):
            if entry.get("status") != "complete":
                continue
            directory = self._root / str(entry["directory"])
            yield ShardReader(directory)

    def nodes(self, *, headers_only: bool = False) -> Iterator[dict]:
        for shard in self._shards():
            yield from shard.nodes(headers_only=headers_only)

    def raw_nodes(self) -> Iterator[bytes]:
        for shard in self._shards():
            yield from shard.raw_nodes()

    def edges(self, *, headers_only: bool = False) -> Iterator[dict]:
        for shard in self._shards():
            yield from shard.edges(headers_only=headers_only)

    def raw_edges(self) -> Iterator[bytes]:
        for shard in self._shards():
            yield from shard.raw_edges()

    def raw_shard_paths(self):
        paths = []
        for shard in self._shards():
            paths.extend(shard.raw_shard_paths())
        return tuple(paths)


class CompositeShardReader:
    """Stream several frontend shard sets as one canonical source."""

    def __init__(self, readers) -> None:
        self.readers = tuple(readers)

    def nodes(self, *, headers_only: bool = False) -> Iterator[dict]:
        yield from chain.from_iterable(
            reader.nodes(headers_only=headers_only) for reader in self.readers
        )

    def raw_nodes(self) -> Iterator[bytes]:
        yield from chain.from_iterable(reader.raw_nodes() for reader in self.readers)

    def edges(self, *, headers_only: bool = False) -> Iterator[dict]:
        yield from chain.from_iterable(
            reader.edges(headers_only=headers_only) for reader in self.readers
        )

    def raw_edges(self) -> Iterator[bytes]:
        yield from chain.from_iterable(reader.raw_edges() for reader in self.readers)

    def raw_shard_paths(self):
        paths = []
        for reader in self.readers:
            paths.extend(reader.raw_shard_paths())
        return tuple(paths)


class ShardSetWriter:
    """Track shard completion atomically so interrupted builds are resumable."""

    def __init__(self, directory: str | Path, *, frontend_id: str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.frontend_id = frontend_id
        self.path = self.directory / "shards.pb"
        if self.path.is_file():
            message = graph_pb2.ShardSetManifest()
            message.ParseFromString(self.path.read_bytes())
            if message.format_version != SHARD_FORMAT_VERSION:
                raise ValueError("unsupported graph protobuf shard-set format")
            self.manifest = {
                "shard_format_version": message.format_version,
                "frontend_id": message.frontend_id,
                "shards": [
                    {"shard_id": item.shard_id, "directory": item.directory,
                     "status": item.status, "node_count": item.node_count,
                     "edge_count": item.edge_count}
                    for item in message.shards
                ],
            }
        else:
            self.manifest = {
                "shard_format_version": SHARD_FORMAT_VERSION,
                "frontend_id": frontend_id,
                "shards": [],
            }
            self._save()

    def _save(self) -> None:
        message = graph_pb2.ShardSetManifest(
            format_version=SHARD_FORMAT_VERSION,
            frontend_id=str(self.manifest.get("frontend_id", self.frontend_id)),
        )
        for item in self.manifest.get("shards", []):
            entry = message.shards.add(
                shard_id=str(item.get("shard_id", "")),
                directory=str(item.get("directory", "")),
                status=str(item.get("status", "")),
            )
            if item.get("node_count") is not None:
                entry.node_count = int(item["node_count"])
            if item.get("edge_count") is not None:
                entry.edge_count = int(item["edge_count"])
        temporary = self.path.with_suffix(".pb.tmp")
        temporary.write_bytes(message.SerializeToString())
        temporary.replace(self.path)

    def start(self, shard_id: str) -> ShardWriter:
        relative = f"shard-{shard_id}"
        entries = [entry for entry in self.manifest["shards"] if entry["shard_id"] != shard_id]
        entries.append({"shard_id": shard_id, "directory": relative, "status": "running"})
        self.manifest["shards"] = entries
        self._save()
        return ShardWriter(
            self.directory / relative, frontend_id=self.frontend_id, shard_id=shard_id,
        )

    def complete(self, shard_id: str, writer: ShardWriter) -> None:
        writer.close()
        for entry in self.manifest["shards"]:
            if entry["shard_id"] == shard_id:
                entry.update({
                    "status": "complete", "node_count": writer.node_count,
                    "edge_count": writer.edge_count,
                })
                break
        self._save()

    def complete_payloads(
        self, shard_id: str, nodes_path: str | Path, edges_path: str | Path,
        node_count: int, edge_count: int,
    ) -> None:
        """Publish already-framed protobuf payload files without decoding records.

        Native frontends can emit the exact shard wire format themselves. Copying
        those files directly avoids a Python protobuf decode/re-encode pass while
        preserving the same atomic manifest protocol as ``complete``.
        """
        relative = f"shard-{shard_id}"
        entries = [entry for entry in self.manifest["shards"] if entry["shard_id"] != shard_id]
        entries.append({"shard_id": shard_id, "directory": relative, "status": "running"})
        self.manifest["shards"] = entries
        self._save()
        target = self.directory / relative
        target.mkdir(parents=True, exist_ok=True)
        # Move rather than copy: the raw frontend bundle (shard-0) is a disposable
        # handoff consumed only here, so renaming its payloads into the published
        # shard-set avoids a transient second copy of the whole bundle on disk --
        # the dominant transient-disk term at large graph scale. shutil.move falls
        # back to copy+unlink when source and destination are on different volumes.
        shutil.move(str(nodes_path), str(target / "nodes.pb"))
        shutil.move(str(edges_path), str(target / "edges.pb"))
        shard_manifest = graph_pb2.ShardManifest(
            format_version=SHARD_FORMAT_VERSION,
            frontend_id=self.frontend_id, shard_id=str(shard_id),
            node_count=int(node_count), edge_count=int(edge_count),
            nodes_file="nodes.pb", edges_file="edges.pb",
        )
        (target / "manifest.pb").write_bytes(shard_manifest.SerializeToString())
        for entry in self.manifest["shards"]:
            if entry["shard_id"] == shard_id:
                entry.update({
                    "status": "complete", "node_count": int(node_count),
                    "edge_count": int(edge_count),
                })
                break
        self._save()


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
