"""Kùzu writer for a composed Lachesis graph — the graph store.

Why (see ``KUZU_STORE_SPEC.md``): the one-big-JSON store this replaced repeats every
~50-byte content-hash id on both endpoints of ~1M edges and stamps constant
``fact_origin``/``confidence``/``evidence_ids`` on nearly every node and edge; loading
it parses the whole thing into RAM. Kùzu dictionary-encodes the string PK (the id is
stored once), low-cardinality columns compress away, and columnar+mmap removes the RAM
ceiling that blocks whole-repo graphs. This module is the *ingest* half; ``nav/kuzu_index.py`` is the read half that
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

``import kuzu`` is deferred so the module still imports if the dependency is somehow
absent; the writer then raises a clear error.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from typing import Iterable, Optional, Sequence

try:  # optional dependency; only needed to actually write a DB (3.10+ venv)
    import kuzu  # type: ignore
except Exception:  # pragma: no cover - a broken install, not a supported mode
    kuzu = None

try:  # optional; enables the fast bulk `COPY FROM` staged-Parquet load path
    import pyarrow as pa  # type: ignore
    import pyarrow.parquet as pq  # type: ignore
except Exception:  # pragma: no cover - falls back to per-row inserts if absent
    pa = None
    pq = None


# -- schema shared with the read side (single source of truth) ----------------

# node property -> promoted column. `props` carries the *tail*: every property not
# already stored in one of these typed columns (and minus the elided constants). The
# read side unions the columns back in, so nothing is lost and nothing is stored twice.
PROMOTED_NODE_PROPS = (
    "symbol_name", "file", "absolute_file", "start_line", "end_line",
    "start_offset", "end_offset", "owner_function_id", "function_id",
    "type", "package_name", "content_hash", "unit",
)
_INT_COLUMNS = frozenset({
    "start_line", "end_line", "start_offset", "end_offset",
})
# The keys a node's `props` blob may omit. `unit` is not among them: it is *derived*
# (from `file`, see `_promoted_value`) rather than a property key of its own, so there
# is nothing to omit and a reader that merged it back would invent a key.
_COLUMN_KEYS = frozenset(PROMOTED_NODE_PROPS) - {"unit"}

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


# the Kùzu store is a *directory* holding this DB file plus the store manifest. The
# marker file lets the loader branch without a magic byte and is robust to Kùzu using a
# single-file DB.
KUZU_DB_FILENAME = "graph.kuzu"

# Deliberately NOT `manifest.json`: that name is already taken by the per-frontend
# bundle manifest under --frontend-out (see pipeline.run_project_incremental), and the
# two would collide the moment anyone points one at the other.
STORE_MANIFEST_FILENAME = "lachesis-manifest.json"

# On-disk format of the store, stamped into the manifest.
#   2 — `props` carries the whole properties dict; promoted columns are duplicates.
#   3 — `props` carries only the tail; the reader unions the promoted columns back in.
# A v3 reader reads a v2 store correctly (the tail is a superset and wins on merge);
# a v2 reader silently loses the promoted keys from a v3 store, which is what this
# stamp exists to let a reader detect.
STORE_FORMAT_VERSION = 3


def db_file(db_dir: str) -> str:
    return os.path.join(db_dir, KUZU_DB_FILENAME)


def store_manifest_file(db_dir: str) -> str:
    return os.path.join(db_dir, STORE_MANIFEST_FILENAME)


def is_kuzu_dir(path: str) -> bool:
    """True when ``path`` is a Kùzu store directory (contains the DB file)."""
    return bool(path) and os.path.isdir(path) and os.path.exists(db_file(path))


def manifest_payload(graph: dict, snapshots: Optional[Sequence[object]]) -> dict:
    """The frontend/capability inventory that travels with a store.

    Every field here was previously carried by the JSON graph's ``manifest`` block.
    ``capabilities`` and ``languages`` in particular are load-bearing: they are the
    only two inputs overlay enrichment needs beyond the graph itself, so a store that
    dropped them could not have its dataflow tier recomputed.
    """
    return {
        "version": STORE_FORMAT_VERSION,
        "frontends": [{
            "frontend_id": item.frontend_id,
            "languages": list(item.languages),
            "capabilities": item.capabilities,
            "node_count": len(item.nodes),
            "edge_count": len(item.edges),
            "diagnostic_count": item.manifest.get("diagnostic_count", 0),
        } for item in (snapshots or [])],
        "node_count": len(graph.get("nodes", [])),
        "edge_count": len(graph.get("edges", [])),
    }


def read_store_manifest(db_dir: str) -> dict:
    """The store's manifest, or an empty inventory when it predates one."""
    path = store_manifest_file(db_dir)
    if not os.path.isfile(path):
        return {"version": STORE_FORMAT_VERSION, "frontends": [],
                "node_count": 0, "edge_count": 0}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def manifest_languages(manifest: dict) -> set:
    """Every language any frontend in the store reported."""
    return {language
            for item in manifest.get("frontends", [])
            for language in item.get("languages", [])}


def manifest_capabilities(manifest: dict) -> dict:
    """The store-wide capability levels: the strongest claim any frontend made.

    Same max-by-rank rule as ``pipeline._combined_capabilities``, recomputed from the
    manifest because the per-frontend levels are what gets persisted.
    """
    rank = {"none": 0, "partial": 1, "complete": 2}
    combined: dict = {}
    for item in manifest.get("frontends", []):
        for name, level in (item.get("capabilities") or {}).items():
            if rank.get(level, 0) >= rank.get(combined.get(name, "none"), 0):
                combined[name] = level
    return combined


def graph_content_hash(nodes: Sequence[dict], edges: Sequence[dict]) -> str:
    """A stable digest of a graph's identity: node ids plus edge triples.

    This is the cache key that ties a derived overlay store back to the core store it
    was computed from. Properties are deliberately excluded — they are large, and the
    node/edge identity set is what enrichment is a function of. A rebuild always
    rewrites store and manifest together, so the key cannot go stale silently.
    """
    digest = hashlib.sha256()
    for node_id in sorted(node["id"] for node in nodes):
        digest.update(node_id.encode("utf-8"))
        digest.update(b"\0")
    digest.update(b"\1")
    for triple in sorted((e.get("kind") or "", e.get("source") or "", e.get("target") or "")
                         for e in edges):
        digest.update("\0".join(triple).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _semantic_kind(edge: dict) -> str:
    kind = edge.get("kind")
    if kind == "EXPANDS_TO":
        return (edge.get("properties") or {}).get("via") or "EXPANDS_TO"
    return kind


def _column_faithful(key: str, value) -> bool:
    """True when the typed column stores ``value`` back exactly as it came in.

    Decided per *value*, not per key, and that distinction is the whole trick. On the
    reference store `owner_function_id` is a string on 179k nodes and a real ``null``
    on 31k of them; `file` is a path on 205,091 nodes and ``null`` on exactly one. The
    faithful ones drop out of the blob because the column carries them; the rest stay,
    because an absent key and a key holding ``null`` both reach the column as SQL NULL
    and are indistinguishable on the way back.

    The type check is exact rather than ``isinstance``: `_cell` coerces anything else
    with ``str()``/``int()``, which is only harmless while the blob is still the
    authority.
    """
    if key in _INT_COLUMNS:
        return type(value) is int and -(2 ** 63) <= value < 2 ** 63
    return type(value) is str


def _stored_props(properties: dict, elide: bool,
                  drop: frozenset = frozenset()) -> str:
    """The `props` blob: the properties a typed column is not already carrying."""
    properties = properties or {}
    if properties and (elide or drop):
        properties = {
            k: v for k, v in properties.items()
            if not (elide and k in CONSTANT_PROP_DEFAULTS)
            and not (k in drop and _column_faithful(k, v))
        }
    return json.dumps(properties)


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
    # `unit` (= emitting source file) is the §5 incremental key, carried on every
    # edge as well as every node. Column order is the rel-COPY contract: the two
    # endpoint PKs come first, then the properties in this definition order.
    stmts = [f"CREATE REL TABLE {kind}(FROM Node TO Node, unit STRING, props STRING)"
             for kind in HOT_REL_KINDS]
    stmts.append("CREATE REL TABLE EDGE(FROM Node TO Node, "
                 "kind STRING, semantic_kind STRING, unit STRING, props STRING)")
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
    enriched: bool = True,
    core_content_hash: Optional[str] = None,
) -> str:
    """Write the composed ``graph`` dict into a Kùzu DB directory. Returns the path.

    ``snapshots`` supplies the store manifest (``lachesis-manifest.json`` beside the DB
    file): the frontend inventory, and with it the capabilities and languages that
    overlay enrichment needs. Set ``prune=False, elide_constants=False`` for an
    exact-reconstruction parity build.

    ``enriched`` records whether the graph carries the overlay dataflow tier. A
    core-only store also gets its own ``core_content_hash`` stamped, which is the key a
    derived ``<store>.enriched`` cache validates itself against; pass that same hash
    explicitly when writing the derived store so the two manifests agree.
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
    os.makedirs(db_dir, exist_ok=True)

    nodes = _kept_nodes(graph.get("nodes", []), prune=prune,
                        drop_diagnostics=drop_diagnostics, drop_tests=drop_tests)
    kept_ids = {n["id"] for n in nodes}
    edges = [e for e in graph.get("edges", [])
             if e.get("source") in kept_ids and e.get("target") in kept_ids]
    # id -> owning file, so an edge (which carries no `file` of its own) can inherit
    # its source node's unit as the §5 incremental key.
    node_units = {n["id"]: _node_unit(n.get("properties") or {}) for n in nodes}

    db = kuzu.Database(db_file(db_dir))
    conn = kuzu.Connection(db)
    conn.execute(_node_ddl())
    for stmt in _rel_ddl():
        conn.execute(stmt)

    # Bulk `COPY FROM` staged Parquet is the fast path (per-row inserts measured
    # ~9.4 min/package — too slow for whole-repo). When pyarrow is absent we fall
    # back to per-row inserts so the module still works everywhere.
    if pa is not None and pq is not None:
        with tempfile.TemporaryDirectory(prefix="kuzu_stage_") as stage_dir:
            _load_nodes_bulk(conn, nodes, elide=elide_constants, stage_dir=stage_dir)
            _load_edges_bulk(conn, edges, elide=elide_constants, stage_dir=stage_dir,
                             node_units=node_units)
    else:  # pragma: no cover - exercised only without pyarrow
        _load_nodes_rowwise(conn, nodes, elide=elide_constants)
        _load_edges_rowwise(conn, edges, elide=elide_constants, node_units=node_units)
    # counts describe what the store actually holds, which is the pruned set, not the
    # composed input — a reader comparing them against a scan should find them equal.
    payload = manifest_payload(graph, snapshots)
    payload["node_count"] = len(nodes)
    payload["edge_count"] = len(edges)
    payload["enriched"] = bool(enriched)
    # The hash describes what was *stored*, so pruning is inside the key: a pruned core
    # and a lossless one are different cores and must not share a derived cache.
    payload["core_content_hash"] = (
        core_content_hash if core_content_hash is not None
        else (None if enriched else graph_content_hash(nodes, edges))
    )
    with open(store_manifest_file(db_dir), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return db_dir


# -- node/edge unit key (§5 incremental) --------------------------------------

def _node_unit(props: dict) -> Optional[str]:
    """The incremental key: the source file that emitted this node/edge."""
    return props.get("file")


def _promoted_value(props: dict, prop: str):
    return _node_unit(props) if prop == "unit" else props.get(prop)


def _edge_unit(edge: dict, node_units: dict) -> Optional[str]:
    """The edge's incremental key. Edges carry no ``file`` of their own
    (``Graph.edge`` stamps none), so attribute an edge to the source node's owning
    file — mirroring ``owner_file(source)`` — giving the ``unit`` column a usable,
    non-NULL value. A rare edge that does carry ``file`` keeps it."""
    props = edge.get("properties") or {}
    return _node_unit(props) or node_units.get(edge.get("source"))


# -- bulk load: stage one Parquet per table, then `COPY FROM` -------------------

def _arrow_type(column: str):
    return pa.int64() if column in _INT_COLUMNS else pa.string()


def _cell(column: str, value):
    """Coerce a promoted-column value to its Parquet type.

    A value this has to coerce is one `_column_faithful` refused, so it is still in
    the ``props`` tail and the tail wins on read: the coercion stays invisible in
    reconstructed dicts. That is now a two-sided invariant — loosen the check there
    and this silently starts rewriting properties."""
    if value is None:
        return None
    if column in _INT_COLUMNS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, str) else str(value)


def _str_col(values: list) -> "pa.Array":
    return pa.array([None if v is None else str(v) for v in values], pa.string())


def _load_nodes_bulk(conn, nodes: list[dict], *, elide: bool, stage_dir: str) -> None:
    if not nodes:
        return
    columns = ["id", "kind", "label", *PROMOTED_NODE_PROPS, "props"]
    data: dict[str, list] = {c: [] for c in columns}
    for node in nodes:
        props = node.get("properties") or {}
        data["id"].append(node["id"])
        data["kind"].append(node.get("kind"))
        data["label"].append(node.get("label"))
        for prop in PROMOTED_NODE_PROPS:
            data[prop].append(_promoted_value(props, prop))
        data["props"].append(_stored_props(props, elide, _COLUMN_KEYS))
    table = pa.table({c: pa.array([_cell(c, v) for v in data[c]], type=_arrow_type(c))
                      for c in columns})
    path = os.path.join(stage_dir, "node.parquet")
    pq.write_table(table, path)
    conn.execute(f"COPY Node FROM '{path}'")


def _load_edges_bulk(conn, edges: list[dict], *, elide: bool, stage_dir: str,
                     node_units: dict) -> None:
    # group edges by destination table; column order is the rel-COPY contract
    # (endpoint PKs first, then properties in table-definition order).
    hot: dict[str, dict[str, list]] = {
        kind: {"src": [], "tgt": [], "unit": [], "props": []}
        for kind in HOT_REL_KINDS
    }
    cold: dict[str, list] = {"src": [], "tgt": [], "kind": [], "sem": [],
                             "unit": [], "props": []}
    for edge in edges:
        kind = edge.get("kind")
        props = edge.get("properties") or {}
        unit = _edge_unit(edge, node_units)
        stored = _stored_props(props, elide)
        if kind in _HOT_SET:
            bucket = hot[kind]
            bucket["src"].append(edge["source"])
            bucket["tgt"].append(edge["target"])
            bucket["unit"].append(unit)
            bucket["props"].append(stored)
        else:
            cold["src"].append(edge["source"])
            cold["tgt"].append(edge["target"])
            cold["kind"].append(kind)
            cold["sem"].append(_semantic_kind(edge))
            cold["unit"].append(unit)
            cold["props"].append(stored)

    for kind, bucket in hot.items():
        if not bucket["src"]:
            continue
        table = pa.table({
            "src": _str_col(bucket["src"]), "tgt": _str_col(bucket["tgt"]),
            "unit": _str_col(bucket["unit"]),
            "props": pa.array(bucket["props"], pa.string()),
        })
        path = os.path.join(stage_dir, f"rel_{kind}.parquet")
        pq.write_table(table, path)
        conn.execute(f"COPY {kind} FROM '{path}'")

    if cold["src"]:
        table = pa.table({
            "src": _str_col(cold["src"]), "tgt": _str_col(cold["tgt"]),
            "kind": _str_col(cold["kind"]), "sem": _str_col(cold["sem"]),
            "unit": _str_col(cold["unit"]),
            "props": pa.array(cold["props"], pa.string()),
        })
        path = os.path.join(stage_dir, "rel_EDGE.parquet")
        pq.write_table(table, path)
        conn.execute(f"COPY EDGE FROM '{path}'")


# -- per-row fallback (no pyarrow): same output, one CREATE per row ------------

def _load_nodes_rowwise(conn, nodes: list[dict], *, elide: bool) -> None:
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
                params[prop] = _promoted_value(props, prop)
            params["props"] = _stored_props(props, elide, _COLUMN_KEYS)
            conn.execute(stmt, params)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _load_edges_rowwise(conn, edges: list[dict], *, elide: bool, node_units: dict) -> None:
    hot_stmt = {
        kind: (f"MATCH (a:Node), (b:Node) WHERE a.id = $s AND b.id = $t "
               f"CREATE (a)-[:{kind} {{unit: $unit, props: $props}}]->(b)")
        for kind in HOT_REL_KINDS
    }
    edge_stmt = ("MATCH (a:Node), (b:Node) WHERE a.id = $s AND b.id = $t "
                 "CREATE (a)-[:EDGE {kind: $kind, semantic_kind: $sem, "
                 "unit: $unit, props: $props}]->(b)")
    conn.execute("BEGIN TRANSACTION")
    try:
        for edge in edges:
            kind = edge.get("kind")
            props = edge.get("properties") or {}
            base = {"s": edge["source"], "t": edge["target"],
                    "unit": _edge_unit(edge, node_units),
                    "props": _stored_props(props, elide)}
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
