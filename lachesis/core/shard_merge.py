"""Bounded-memory merge of language-neutral graph shards."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterator

from .graph_wire import decode_document, encode_document

from .shards import ShardSetReader


class ShardMerger:
    """Deduplicate shard records on disk and expose streaming graph iterators."""

    def __init__(self, database: str | Path) -> None:
        self.database = str(database)
        self.connection = sqlite3.connect(self.database)
        self.connection.execute("PRAGMA journal_mode=OFF")
        self.connection.execute("PRAGMA synchronous=OFF")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL,
                properties BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS edges (
                kind TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL,
                properties BLOB NOT NULL,
                PRIMARY KEY (kind, source, target, properties)
            );
            """,
        )

    def ingest(self, shards: ShardSetReader) -> None:
        self.connection.execute("BEGIN")
        try:
            for node in shards.nodes():
                self.connection.execute(
                    "INSERT OR IGNORE INTO nodes VALUES (?, ?, ?, ?)",
                    (
                        node["id"], node.get("kind", ""), node.get("label", node["id"]),
                        encode_document(node.get("properties", {})),
                    ),
                )
            for edge in shards.edges():
                self.connection.execute(
                    "INSERT OR IGNORE INTO edges VALUES (?, ?, ?, ?)",
                    (
                        edge["kind"], edge["source"], edge["target"],
                        encode_document(edge.get("properties", {})),
                    ),
                )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def iter_nodes(self) -> Iterator[dict]:
        for node_id, kind, label, properties in self.connection.execute(
            "SELECT id, kind, label, properties FROM nodes ORDER BY id",
        ):
            yield {
                "id": node_id, "kind": kind, "label": label,
                "properties": decode_document(properties),
            }

    def iter_edges(self) -> Iterator[dict]:
        for kind, source, target, properties in self.connection.execute(
            "SELECT kind, source, target, properties FROM edges "
            "ORDER BY kind, source, target",
        ):
            yield {
                "kind": kind, "source": source, "target": target,
                "properties": decode_document(properties),
            }

    def counts(self) -> tuple[int, int]:
        nodes = self.connection.execute("SELECT count(*) FROM nodes").fetchone()[0]
        edges = self.connection.execute("SELECT count(*) FROM edges").fetchone()[0]
        return nodes, edges

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "ShardMerger":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()
