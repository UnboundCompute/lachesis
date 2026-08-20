"""Common graph-output sinks used by all language frontends.

The sink API is deliberately tiny: frontends publish canonical node/edge records and
close the stream.  The default memory sink preserves today's behavior; the shard sink
provides bounded-memory output for large projects.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Protocol

from .shards import ShardWriter


class GraphSink(Protocol):
    def node(self, record: dict) -> None: ...
    def edge(self, record: dict) -> None: ...
    def close(self) -> None: ...


class MemoryGraphSink:
    """Compatibility sink collecting the canonical graph in memory."""

    def __init__(self) -> None:
        self.nodes: List[dict] = []
        self.edges: List[dict] = []

    def node(self, record: dict) -> None:
        self.nodes.append(record)

    def edge(self, record: dict) -> None:
        self.edges.append(record)

    def close(self) -> None:
        return None


class ShardGraphSink:
    """Bounded-memory sink writing immutable node/edge records to one shard."""

    def __init__(self, directory: str, *, frontend_id: str, shard_id: str) -> None:
        self._writer = ShardWriter(
            directory, frontend_id=frontend_id, shard_id=shard_id,
        )

    def node(self, record: dict) -> None:
        self._writer.add_node(record)

    def edge(self, record: dict) -> None:
        self._writer.add_edge(record)

    def close(self) -> None:
        self._writer.close()


def sink_from_environment(
    *, frontend_id: str, shard_id: str = "0", memory: Optional[MemoryGraphSink] = None,
) -> GraphSink:
    """Select a sink without making language frontends know about CLI plumbing.

    ``LACHESIS_SHARD_DIR`` is intentionally opt-in until every frontend has adopted
    streaming emission and the common merger is enabled by default.
    """
    import os

    directory = os.environ.get("LACHESIS_SHARD_DIR")
    if directory:
        return ShardGraphSink(
            directory, frontend_id=frontend_id,
            shard_id=os.environ.get("LACHESIS_SHARD_ID", shard_id),
        )
    return memory or MemoryGraphSink()
