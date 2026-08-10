"""Kùzu writer for a composed Arachne graph — the disk-backed alternative to the
one-big-JSON store written by ``pipeline.write_project_graph``.

Why (see ``KUZU_STORE_SPEC.md``): the JSON store repeats every ~50-byte content-hash
id on both endpoints of ~1M edges and stamps constant ``fact_origin``/``confidence``/
``evidence_ids`` on nearly every node and edge; loading it parses the whole thing into
RAM. Kùzu dictionary-encodes the string PK (the id is stored once), low-cardinality
columns compress away, and columnar+mmap removes the RAM ceiling that blocks whole-repo
graphs. This module is the *ingest* half; ``nav/kuzu_index.py`` is the read half that
satisfies the existing ``GraphIndex`` accessor surface so no nav tool changes.

Two shrink levers, both flag-gated so a parity harness can disable them and get an
exact reconstruction of the canonical node/edge dicts:

  * **prune** (Lever A) — drop pure-lexical ``token``/``source-span`` nodes and any edge
    with a dropped endpoint. ``read_body`` reads the *source file by offset*, not these
    nodes, so this is lossless for navigation.
  * **elide_constants** (Lever B, partial) — drop the three constant keys from the stored
    ``props`` blob. The read side restores them via ``setdefault`` (they are genuinely
    constant), so reconstruction is exact.

Storage contract (kept deliberately simple for v1 correctness + parity):
  * one generic ``Node`` table; the columns nav actually filters on are promoted, and the
    **full** original ``properties`` dict (minus elided constants) rides in a ``props``
    JSON string — reconstruction reads ``props`` only, so promoted columns are never a
    second source of truth.
  * one typed rel table per *hot* edge kind (the traversal moat), each just
    ``(FROM Node TO Node, props STRING)`` — the kind is the table name. Per-property typed
    columns (the spec's ``context_id`` etc.) are a future query optimization; carrying the
    whole ``props`` blob is sufficient for the current accessors, which return whole edge
    dicts and read properties in Python.
  * one catch-all ``EDGE(kind, semantic_kind, props)`` for the cold long tail. ``kind`` is
    the raw kind (e.g. ``EXPANDS_TO``); ``semantic_kind`` is the unwrapped relationship
    (``properties.via`` for ``EXPANDS_TO``, else ``kind``) so the read side can match on
    the semantic kind without parsing JSON in Cypher.

``import kuzu`` is deferred so this module imports under the repo's Python 3.9 (Kùzu needs
3.10+); the writer raises a clear error if kuzu is missing.
"""
from __future__ import annotations

import json
import os
import shutil
from typing import Iterable, Optional, Sequence

try:  # optional dependency; only needed to actually write a DB (3.10+ venv)
    import kuzu  # type: ignore
except Exception:  # pragma: no cover - absent under 3.9
    kuzu = None


# -- schema shared with the read side (single source of truth) ----------------

# node property -> promoted column. `props` always carries the full properties dict
# (minus elided constants); these columns are duplicates used only for WHERE/index.
PROMOTED_NODE_PROPS = (
    "symbol_name", "file", "absolute_file", "start_line", "end_line",
    "start_offset", "end_offset", "owner_function_id", "function_id",
    "type", "package_name", "content_hash", "unit",
)
_INT_COLUMNS = frozenset({
    "start_line", "end_line", "start_offset", "end_offset",
})

# the traversal-critical kinds get their own typed rel table (columnar, no kind filter
# on the hot path); everything else lands in the catch-all EDGE table.
HOT_REL_KINDS = (
    "VALUE_FLOWS_TO", "POINTS_TO", "TAINT_FLOWS_TO", "ALIASES", "ALIASES_VALUE",
    "CALLS", "MAY_INVOKE", "INVOKES", "READS_FROM", "WRITES_TO", "DEFINES", "REFERS_TO",
)
_HOT_SET = frozenset(HOT_REL_KINDS)

# pure-lexical node kinds dropped by the prune lever (nav reads source by offset).
PRUNE_NODE_KINDS = frozenset({"token", "source-span"})

# constant, low-cardinality props dropped from `props` when eliding; the read side
# restores them by setdefault. A fresh object per node/edge on the read side.
CONSTANT_PROP_DEFAULTS = {
    "fact_origin": "compiler",
    "confidence": "exact",
    "evidence_ids": [],
}


def is_kuzu_dir(path: str) -> bool:
    """A Kùzu store is a directory; the JSON store is a file. Used by the loader to
    branch without a magic byte."""
    return bool(path) and os.path.isdir(path)


def _semantic_kind(edge: dict) -> str:
    kind = edge.get("kind")
    if kind == "EXPANDS_TO":
        return (edge.get("properties") or {}).get("via") or "EXPANDS_TO"
    return kind


def _stored_props(properties: dict, elide: bool) -> str:
    if elide and properties:
        properties = {k: v for k, v in properties.items()
                      if k not in CONSTANT_PROP_DEFAULTS}
    return json.dumps(properties or {})


def _is_test_file(path: Optional[str]) -> bool:
    if not path:
        return False
    from nav.symbol_index import is_test_path  # single source of truth
    return is_test_path(path)


def _kept_nodes(nodes: Iterable[dict], *, prune: bool,
                drop_diagnostics: bool, drop_tests: bool) -> list[dict]:
    out = []
    for node in nodes:
        kind = node.get("kind")
        if prune and kind in PRUNE_NODE_KINDS:
            continue
        if drop_diagnostics and kind == "diagnostic":
            continue
        if drop_tests and _is_test_file((node.get("properties") or {}).get("file")):
            continue
        out.append(node)
    return out


# -- DDL ----------------------------------------------------------------------

def _node_ddl() -> str:
    cols = ["id STRING", "kind STRING", "label STRING"]
    for prop in PROMOTED_NODE_PROPS:
        cols.append(f"{prop} {'INT64' if prop in _INT_COLUMNS else 'STRING'}")
    cols.append("props STRING")
    cols.append("PRIMARY KEY (id)")
    return "CREATE NODE TABLE Node(" + ", ".join(cols) + ")"


def _rel_ddl() -> list[str]:
    stmts = [f"CREATE REL TABLE {kind}(FROM Node TO Node, props STRING)"
             for kind in HOT_REL_KINDS]
    stmts.append("CREATE REL TABLE EDGE(FROM Node TO Node, "
                 "kind STRING, semantic_kind STRING, props STRING)")
    return stmts


# -- writer -------------------------------------------------------------------

def write_kuzu_graph(
    graph: dict,
    snapshots: Optional[Sequence[object]] = None,
    db_dir: str = "graph_out/kuzu",
    *,
    prune: bool = True,
    elide_constants: bool = True,
    drop_diagnostics: bool = False,
    drop_tests: bool = False,
    overwrite: bool = True,
) -> str:
    """Write the composed ``graph`` dict (post-enrich, same shape
    ``write_project_graph`` receives) into a Kùzu DB directory. Returns the path.

    ``snapshots`` is accepted for call-site symmetry with ``write_project_graph`` but
    unused (the manifest is not needed by the store). Set ``prune=False,
    elide_constants=False`` for an exact-reconstruction parity build.
    """
    if kuzu is None:
        raise RuntimeError(
            "kuzu is not installed; the Kùzu writer needs Python 3.10+ with `kuzu`. "
            "Create a venv (e.g. `python3.11 -m venv .venv-kuzu && "
            ".venv-kuzu/bin/pip install kuzu`) and run there."
        )
    db_dir = os.path.abspath(db_dir)
    if os.path.exists(db_dir):
        if not overwrite:
            raise FileExistsError(db_dir)
        shutil.rmtree(db_dir) if os.path.isdir(db_dir) else os.remove(db_dir)

    nodes = _kept_nodes(graph.get("nodes", []), prune=prune,
                        drop_diagnostics=drop_diagnostics, drop_tests=drop_tests)
    kept_ids = {n["id"] for n in nodes}
    edges = [e for e in graph.get("edges", [])
             if e.get("source") in kept_ids and e.get("target") in kept_ids]

    db = kuzu.Database(db_dir)
    conn = kuzu.Connection(db)
    conn.execute(_node_ddl())
    for stmt in _rel_ddl():
        conn.execute(stmt)

    _load_nodes(conn, nodes, elide=elide_constants)
    _load_edges(conn, edges, elide=elide_constants)
    return db_dir


def _load_nodes(conn, nodes: list[dict], *, elide: bool) -> None:
    columns = ["id", "kind", "label", *PROMOTED_NODE_PROPS, "props"]
    placeholders = ", ".join(f"{c}: ${c}" for c in columns)
    stmt = f"CREATE (n:Node {{{placeholders}}})"
    conn.execute("BEGIN TRANSACTION")
    try:
        for node in nodes:
            props = node.get("properties") or {}
            params = {"id": node["id"], "kind": node.get("kind"),
                      "label": node.get("label")}
            for prop in PROMOTED_NODE_PROPS:
                params[prop] = props.get(prop)
            params["props"] = _stored_props(props, elide)
            conn.execute(stmt, params)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _load_edges(conn, edges: list[dict], *, elide: bool) -> None:
    hot_stmt = {
        kind: (f"MATCH (a:Node), (b:Node) WHERE a.id = $s AND b.id = $t "
               f"CREATE (a)-[:{kind} {{props: $props}}]->(b)")
        for kind in HOT_REL_KINDS
    }
    edge_stmt = ("MATCH (a:Node), (b:Node) WHERE a.id = $s AND b.id = $t "
                 "CREATE (a)-[:EDGE {kind: $kind, semantic_kind: $sem, props: $props}]->(b)")
    conn.execute("BEGIN TRANSACTION")
    try:
        for edge in edges:
            kind = edge.get("kind")
            props = _stored_props(edge.get("properties") or {}, elide)
            base = {"s": edge["source"], "t": edge["target"], "props": props}
            if kind in _HOT_SET:
                conn.execute(hot_stmt[kind], base)
            else:
                base["kind"] = kind
                base["sem"] = _semantic_kind(edge)
                conn.execute(edge_stmt, base)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
