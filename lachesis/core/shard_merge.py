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

    # Node kinds whose cross-TU instances share a canonical identity (clang USR).
    _CANONICAL_KINDS = ("function", "value", "variable")

    def canonicalize(self, *, reconstruct_binding: bool = True) -> dict:
        """Collapse cross-TU duplicate declarations onto one canonical id and rewrite
        every edge endpoint onto it, so the merged graph is independent of how the TUs
        were sharded.

        A call whose callee has a header prototype and a definition resolves to the
        prototype in one build and the definition in another; the derived call-context id
        is ``stable_id(call, target)``, so the two disagree. Picking one canonical instance
        per ``(kind, USR)`` -- the definition (``declaration_only`` not true), smallest id
        as tiebreak, else the smallest declaration -- and rewriting all edge endpoints onto
        it makes the choice order-independent and shard-count-invariant.

        With ``reconstruct_binding`` the frontend's traversal-order-dependent
        function-pointer dispatch edges are dropped and rebuilt from the global
        registration slot map (a function-pointer call targets every function globally
        registered to its slot), which converges across shardings the same way.

        Bounded memory: the canonical map and slot map are small (a few thousand entries);
        the millions of structural edges are rewritten by an on-disk SQL join, and only the
        few thousand ``MAY_INVOKE`` edges are handled in Python. Returns a stats dict."""
        remap, fnptr_calls = self._canonical_remap(reconstruct_binding)
        return self._rewrite_edges(remap, fnptr_calls, reconstruct_binding)

    def _canonical_remap(self, want_fnptr: bool) -> tuple[dict, dict]:
        defs: dict[tuple, list] = {}
        decls: dict[tuple, list] = {}
        fnptr_calls: dict[str, str] = {}
        for node_id, kind, properties in self.connection.execute(
            "SELECT id, kind, properties FROM nodes",
        ):
            props = decode_document(properties) if properties else {}
            if want_fnptr and props.get("resolution") == "function-pointer":
                callee = props.get("callee")
                if callee:
                    fnptr_calls[node_id] = callee
            if kind not in self._CANONICAL_KINDS:
                continue
            usr = props.get("usr")
            if not usr:
                continue
            key = (kind, usr)
            (decls if props.get("declaration_only") is True else defs).setdefault(
                key, []).append(node_id)
        remap: dict[str, str] = {}
        for key in set(defs) | set(decls):
            bucket = defs.get(key)
            canonical = min(bucket) if bucket else min(decls[key])
            for node_id in defs.get(key, ()):
                if node_id != canonical:
                    remap[node_id] = canonical
            for node_id in decls.get(key, ()):
                if node_id != canonical:
                    remap[node_id] = canonical
        return remap, fnptr_calls

    def _rewrite_edges(self, remap: dict, fnptr_calls: dict, reconstruct: bool) -> dict:
        conn = self.connection
        # MAY_INVOKE edges are few (thousands); handle them wholly in Python so we can
        # read the encoded resolution/slot. Everything else is rewritten by SQL join.
        slot_map: dict[str, set] = {}
        bind_blob = None
        may_invoke: list[tuple] = []
        for kind, source, target, properties in conn.execute(
            "SELECT kind, source, target, properties FROM edges WHERE kind = 'MAY_INVOKE'",
        ):
            doc = decode_document(properties) if properties else {}
            res = doc.get("resolution")
            if res == "binding":
                if bind_blob is None:
                    bind_blob = properties
            elif res == "registration":
                slot = doc.get("slot")
                if slot:
                    slot_map.setdefault(slot, set()).add(remap.get(target, target))
            may_invoke.append((kind, source, target, properties, res))

        conn.execute("DROP TABLE IF EXISTS _remap")
        conn.execute("CREATE TABLE _remap (old TEXT PRIMARY KEY, new TEXT NOT NULL)")
        conn.executemany("INSERT INTO _remap VALUES (?, ?)", remap.items())
        conn.execute("DROP TABLE IF EXISTS _edges_new")
        conn.execute(
            """
            CREATE TABLE _edges_new (
                kind TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL,
                properties BLOB NOT NULL,
                PRIMARY KEY (kind, source, target, properties)
            )
            """,
        )
        # Structural edges: rewrite both endpoints via the map, drop self-loops, dedup
        # on the primary key -- all on disk, no Python-side edge buffer.
        conn.execute(
            """
            INSERT OR IGNORE INTO _edges_new (kind, source, target, properties)
            SELECT e.kind,
                   COALESCE(rs.new, e.source),
                   COALESCE(rt.new, e.target),
                   e.properties
            FROM edges e
            LEFT JOIN _remap rs ON rs.old = e.source
            LEFT JOIN _remap rt ON rt.old = e.target
            WHERE e.kind <> 'MAY_INVOKE'
              AND COALESCE(rs.new, e.source) <> COALESCE(rt.new, e.target)
            """,
        )

        rewritten = dropped = added = 0
        for kind, source, target, properties, res in may_invoke:
            if reconstruct and res == "binding":
                continue  # regenerated below from the global slot map
            ns, nt = remap.get(source, source), remap.get(target, target)
            if ns != source or nt != target:
                rewritten += 1
            if ns == nt:
                dropped += 1
                continue
            conn.execute(
                "INSERT OR IGNORE INTO _edges_new VALUES (?, ?, ?, ?)",
                (kind, ns, nt, properties),
            )
        if reconstruct:
            for call_id, slot in fnptr_calls.items():
                for fn in slot_map.get(slot, ()):
                    conn.execute(
                        "INSERT OR IGNORE INTO _edges_new VALUES (?, ?, ?, ?)",
                        ("MAY_INVOKE", call_id, fn, bind_blob or encode_document({})),
                    )
                    added += 1
        conn.execute("DROP TABLE edges")
        conn.execute("ALTER TABLE _edges_new RENAME TO edges")
        conn.execute("DROP TABLE _remap")
        conn.commit()
        return {"remapped": len(remap), "may_invoke_rewritten": rewritten,
                "self_loops_dropped": dropped, "binding_reconstructed": added}

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
