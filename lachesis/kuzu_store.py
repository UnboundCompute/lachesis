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

Storage contract:
  * one generic ``Node`` table; the columns nav filters on are promoted to typed columns,
    and ``props`` carries the *tail*, the properties no column holds. Reconstruction
    unions the two, so nothing is stored twice and nothing is lost.
  * ``props`` is deflated UTF-8 JSON in a ``BLOB``, not a ``STRING``. That costs
    readability in a raw Cypher dump and buys the last easy allocation boundary; see
    ``STORE_COMPRESSION_SPEC.md`` 0.2 for why boundaries are the unit of account here.
    The deflate runs against a preset dictionary built from this store's own most
    frequent tails and kept in the manifest, so each blob stays independently
    addressable while still paying only a reference for what every row repeats.
  * one typed rel table per *hot* edge kind (the traversal moat), each just
    ``(FROM Node TO Node, unit STRING, props BLOB)`` — the kind is the table name.
    Per-property typed columns (the spec's ``context_id`` etc.) are a future query
    optimization; carrying the whole ``props`` blob is sufficient for the current
    accessors, which return whole edge dicts and read properties in Python.
  * one catch-all ``EDGE(kind, semantic_kind, unit, props)`` for the cold long tail.
    ``kind`` is the raw kind (e.g. ``EXPANDS_TO``); ``semantic_kind`` is the unwrapped
    relationship (``properties.via`` for ``EXPANDS_TO``, else ``kind``) so the read side
    can match on the semantic kind without inflating a blob in Cypher.

``import kuzu`` is deferred so the module still imports if the dependency is somehow
absent; the writer then raises a clear error.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import itertools
import json
import os
import re
import shutil
import tempfile
import zlib
from typing import Iterable, Optional, Sequence

from lachesis.indices import (
    CALLSITE_KINDS, INDEXED_KINDS, build_callsite_index, build_decl_index,
    exported_ids, index_rows,
)

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
#
# Which keys belong here is a *disk* question with a sharp answer, not a matter of taste.
# Kùzu allocates each column's data chunk a power-of-two number of 4 KB pages, per
# 131,072-row node group, and writes that allocation into the file. So bytes are free
# until they cross a boundary, and then a whole bucket is free at once. Promoting a key
# moves its name out of ~200k JSON blobs and into one dictionary-encoded column, which
# is what walks `props` down toward the next boundary. See STORE_COMPRESSION_SPEC.md 0.2;
# the six keys after `unit` below are the ones that measurement picked.
PROMOTED_NODE_PROPS = (
    "symbol_name", "file", "absolute_file", "start_line", "end_line",
    "start_offset", "end_offset", "owner_function_id", "function_id",
    "type", "package_name", "content_hash", "unit",
    "frontend_id", "frontend_tier", "language", "compiler_node_id",
    "start_column", "end_column",
)
_INT_COLUMNS = frozenset({
    "start_line", "end_line", "start_offset", "end_offset",
    "start_column", "end_column",
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


def _kuzu_buffer_pool_size(default: int = 0) -> int:
    """Return an optional bounded Kùzu buffer pool size in bytes.

    Kùzu's ``0`` default auto-sizes from host memory, which is unsafe for CI
    runners when a large graph is being materialized.  Keep the historical
    default unless the caller opts in, while allowing the low-memory and streamed
    paths to set a hard ceiling without changing the graph format.
    """
    raw = os.environ.get("LACHESIS_KUZU_BUFFER_POOL_SIZE", "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("LACHESIS_KUZU_BUFFER_POOL_SIZE must be an integer byte count") from exc
    if value < 0:
        raise ValueError("LACHESIS_KUZU_BUFFER_POOL_SIZE must be non-negative")
    return value


def _kuzu_checkpoint_threshold(default: int = -1) -> int:
    """Return the Kùzu WAL checkpoint threshold in bytes.

    A bounded threshold prevents a streamed build from retaining a very large
    copy-on-write shadow file until the final checkpoint.  ``-1`` preserves Kùzu's
    automatic default for the non-streamed writer.
    """
    raw = os.environ.get("LACHESIS_KUZU_CHECKPOINT_THRESHOLD", "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            "LACHESIS_KUZU_CHECKPOINT_THRESHOLD must be an integer byte count"
        ) from exc
    if value < 0:
        raise ValueError("LACHESIS_KUZU_CHECKPOINT_THRESHOLD must be non-negative")
    return value

# Deliberately NOT `manifest.json`: that name is already taken by the per-frontend
# bundle manifest under --frontend-out (see pipeline.run_project_incremental), and the
# two would collide the moment anyone points one at the other.
STORE_MANIFEST_FILENAME = "lachesis-manifest.json"

# On-disk format of the store, stamped into the manifest.
#   2 — `props` carries the whole properties dict; promoted columns are duplicates.
#   3 — `props` carries only the tail; the reader unions the promoted columns back in.
#   4 — six more keys promoted to columns; `props` uses compact JSON separators.
#   5 — `props` is a deflated BLOB rather than a JSON STRING.
#   6 — the deflate uses a preset dictionary shared by every row, kept in the manifest.
#   7 — `compiler_node_id` is coded against a prefix table in the manifest.
#   8 — the `id` primary key is coded against that same table.
#   9 — four resolution tables: DeclIndex, CallsiteIndex, ResolveMemo, ConeMemo.
# v9 adds tables and writes two of them; a v8 reader handed a v9 store would simply not
# see them, and a v9 reader handed a v8 store would fail on a table that is not there.
# The memo tables ship empty on purpose — see `_index_ddl` for why they are declared now.
# v8 is a separate version from v7 and not a refinement of it: a v7 store carries the
# prefix table but an *uncoded* `id`, so a v8 reader handed one would decode a value
# that was never encoded. The stamp is what turns that into a sentence rather than a
# base64 error from somewhere deep in the read path.
# v4 is the first version that is not backward compatible, and the tail-wins rule is why
# the earlier ones were. Up to v3 the column set was fixed, so a newer reader could read
# an older store: the older store's `props` was a superset and won on merge. v4 *adds*
# columns, so its reader selects names a v2 or v3 schema does not have and the query
# fails. Both directions are now hard failures, and the load path checks this stamp so
# they arrive as a sentence telling you to rebuild rather than as a Cypher error. A store
# is a rebuildable artifact (KUZU_STORE_SPEC.md): a format bump is a rebuild, not a
# migration.
STORE_FORMAT_VERSION = 9


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
            "node_count": item.payload_node_count,
            "edge_count": item.payload_edge_count,
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


def manifest_props_dictionary(manifest: dict) -> bytes:
    """The shared deflate dictionary this store's `props` blobs were written against.

    Empty for a store whose tails held nothing worth sharing (a tiny fixture), which is
    also the plain-deflate path in ``PropsCodec``, so the empty case needs no branch of
    its own on either side.
    """
    return base64.b64decode(manifest.get(PROPS_DICT_KEY) or "")


def manifest_id_prefixes(manifest: dict) -> list:
    """The prefix table this store's coded id columns were written against.

    Empty for a store whose id columns held nothing prefix-shaped, which is the
    identity path on both sides — same arrangement as the deflate dictionary above,
    so neither end needs a branch for the trivial case.
    """
    return list(manifest.get(ID_PREFIX_KEY) or ())


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


# deflate level for the `props` blob. Measured across levels 1 to 9 on the reference
# store the ratio moves 0.631 to 0.624 and the whole-build cost 4.5s to 4.9s, so the
# level is very nearly irrelevant here and this is the stdlib default rather than a
# tuned value. Kùzu's own page compression does not reach inside a BLOB, which is why
# this is the one place where general-purpose compression is not already spent.
_PROPS_ZLIB_LEVEL = 6

# Size of the preset deflate dictionary shared by every `props` blob in the store.
# 32 KB is deflate's whole window, so a larger one cannot be referenced anyway.
PROPS_DICT_SIZE = 32 * 1024

# Manifest key holding that dictionary, base64 of the raw bytes.
PROPS_DICT_KEY = "props_dict"

# Manifest key holding the prefix table the coded id columns are written against.
ID_PREFIX_KEY = "id_prefixes"

# The columns coded against it: the primary key, and node ids held as an ordinary
# property. They are the one shape in this store that every other lever misses. Kùzu
# dictionary-encodes a STRING column by storing each *distinct* value once, which is
# free and total for a column like `language`; it does nothing at all for a column
# whose values are all distinct, and on the reference store `id` has 244,954 values and
# `compiler_node_id` 203,367, every one of them distinct. What repeats there is not the
# value but its *prefix* — 49 and 24 respectively — and a prefix is not something a
# per-value dictionary can factor out.
CODED_ID_COLUMNS = ("id", "compiler_node_id")

# Just the promoted-property ones. `id` is a leading column of its own rather than a
# props key, so it is coded at the column and never appears in a properties dict.
CODED_PROP_COLUMNS = tuple(c for c in CODED_ID_COLUMNS if c != "id")
_CODED_SET = frozenset(CODED_PROP_COLUMNS)

# A node id: a hierarchical prefix, a colon, then 20 hex characters of content hash.
# The prefix group is greedy, so the hash is the *last* 20 hex characters and a prefix
# that itself ends in something hex-shaped is not misread as part of it.
_ID_SHAPE = re.compile(r"\A(.*):([0-9a-f]{20})\Z", re.DOTALL)

# The two forms a coded value can take, told apart by the first character. Neither is a
# legal start for a raw id, but the codec does not depend on that: every value goes
# through one branch or the other, so `decode_id` is total and exactly inverse even for
# a value that starts with one of these itself.
_ID_CODED = "~"    # `~<code>:<base64url of the 10 hash bytes>`
_ID_ESCAPE = "="   # `=<the value verbatim>`, for anything not id-shaped

_CODE_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def _prefix_code(index: int) -> str:
    """A prefix's index as base36 — 1 character for the first 36, 2 for the next 1296."""
    code = ""
    while True:
        code = _CODE_DIGITS[index % 36] + code
        index //= 36
        if not index:
            return code


def build_id_prefixes(values: Iterable[object]) -> list:
    """The distinct id prefixes in this store, as the manifest's code table.

    Sorted so that rebuilding the same graph assigns the same code to the same prefix,
    byte for byte: a store is a rebuildable artifact and two builds of one graph should
    differ in no byte at all.
    """
    return sorted({match.group(1) for value in values
                   if type(value) is str
                   for match in [_ID_SHAPE.match(value)] if match})


def encode_id(value: Optional[str], codes: dict) -> Optional[str]:
    """A node id as it is stored: prefix replaced by its code, hash by raw base64.

    Two independent cuts, both on a value that averages 62 characters. The prefix —
    `v2:frontend:typescript-compiler-api:<kind>` and 48 others — becomes one or two
    characters. The 20 hex characters are 10 bytes of content hash spelled at half a
    byte per character, and base64url spells the same 10 bytes in 14. Together that is
    62 characters down to about 17.

    Worth doing here and nowhere else because of what the id costs. A column value is
    charged twice: once in `<col>_data`, which is quantized to a power of two pages and
    so only pays at a boundary, and again in the primary-key index, which holds the key
    string itself and — measured, see ``STORE_COMPRESSION_SPEC.md`` — grows at roughly
    0.31 MB per character of key across a store this size, *linearly*, with no boundary
    to reach. That second charge is why shortening an id is the only lever here that
    pays continuously rather than all at once.
    """
    if value is None or not codes:
        return value
    match = _ID_SHAPE.match(value)
    code = codes.get(match.group(1)) if match else None
    if code is None:
        return _ID_ESCAPE + value
    packed = base64.urlsafe_b64encode(bytes.fromhex(match.group(2)))
    # rstrip the padding: 10 bytes is 14 base64 characters plus two `=` that carry no
    # information, and `decode_id` puts them back.
    return _ID_CODED + code + ":" + packed.decode("ascii").rstrip("=")


def decode_id(value: Optional[str], prefixes: Sequence[str]) -> Optional[str]:
    """Undo ``encode_id``. Exactly inverse, including for values it did not code."""
    if value is None or not prefixes:
        return value
    if value.startswith(_ID_ESCAPE):
        return value[1:]
    code, _, packed = value[1:].partition(":")
    suffix = base64.urlsafe_b64decode(packed + "==").hex()
    return f"{prefixes[int(code, 36)]}:{suffix}"


def _coded_cell(column: str, value, codes: dict):
    """A promoted column's value on the way to disk, coded if the column is an id one.

    Coerces to ``str`` first so the coding is total over the column: a non-string here
    is one ``_column_faithful`` refused, so the real value is still in the ``props``
    tail and wins on read — but the column still has to hold something ``decode_id``
    can invert, or reading the column becomes conditional on data it cannot see.
    """
    if column not in _CODED_SET or value is None:
        return value
    return encode_id(value if type(value) is str else str(value), codes)


def _props_text(properties: dict, elide: bool,
                drop: frozenset = frozenset()) -> bytes:
    """The properties a typed column is not already carrying, as UTF-8 JSON."""
    properties = properties or {}
    if properties and (elide or drop):
        properties = {
            k: v for k, v in properties.items()
            if not (elide and k in CONSTANT_PROP_DEFAULTS)
            and not (k in drop and _column_faithful(k, v))
        }
    # Compact separators: `json.dumps` defaults to ", " and ": ", which is two bytes of
    # whitespace per key on every row and nothing else. `json.loads` cannot tell the
    # difference, so this is invisible above the column.
    return json.dumps(properties, separators=(",", ":")).encode("utf-8")


class PropsCodec:
    """Deflates one `props` tail per row, against the store's shared dictionary.

    Every row is its own compressed unit, because `props` is a BLOB column read back
    one row at a time: a shared stream would make row N depend on row N-1 and there
    would be no random access left. That is not the part worth amortising.

    The part worth amortising is the priming. The dictionary is 32 KB, and a fresh
    `zlib.compressobj` has to allocate deflate state and run that whole window through
    it before it can code the ~130-byte tail that follows, so the setup dominates the
    work by a wide margin. zlib compressors can be cloned, so one prototype is primed
    when the dictionary is known and each row gets a `.copy()` of it. A clone starts
    from the same state a fresh compressor would, so the bytes it emits are the same
    bytes, which is a guarantee `lachesis.checks` pins rather than assumes.

    Not shared across builds and not cached at module level: a prototype belongs to the
    dictionary it was primed with, and one process may well write two stores. It is also
    not safe to clone from concurrently, so a parallel writer needs one prototype each.

    `texts` is the second amortisation: the tails the dictionary pre-pass already built,
    kept rather than discarded, so no row's properties are serialised to JSON twice. It
    is positional against the collection it was built from, which is what makes a codec
    belong to exactly one of `nodes` / `edges` / `deferred` — the three are serialised
    with different arguments and a codec handed the wrong list would write the wrong
    rows. Without it the codec builds each tail on demand, which is the path a caller
    outside the writer gets.
    """

    __slots__ = ("_prototype", "_texts")

    def __init__(self, zdict: bytes = b"",
                 texts: Optional[Sequence[bytes]] = None) -> None:
        # No dictionary is the honest empty case, not a degenerate one: `zlib.compress`
        # is what a reader without a dictionary inflates against.
        self._prototype = zlib.compressobj(
            _PROPS_ZLIB_LEVEL, zlib.DEFLATED, zlib.MAX_WBITS,
            zlib.DEF_MEM_LEVEL, 0, zdict) if zdict else None
        self._texts = texts

    def blob(self, index: int, properties: dict, elide: bool,
             drop: frozenset = frozenset()) -> bytes:
        """The `props` blob for row `index`: its tail, as deflated UTF-8 JSON."""
        text = (self._texts[index] if self._texts is not None
                else _props_text(properties, elide, drop))
        if self._prototype is None:
            return zlib.compress(text, _PROPS_ZLIB_LEVEL)
        obj = self._prototype.copy()
        return obj.compress(text) + obj.flush()


def build_props_dictionary(texts: Iterable[bytes]) -> bytes:
    """A preset deflate dictionary for this store's `props` tails.

    Deflate can only match against the 32 KB behind the byte it is coding, so a blob
    of a few hundred bytes compresses almost entirely on its own contents and pays for
    the same key names and the same repeated values on every row. Seeding the window
    with material shared across rows is what buys cross-row dedup without giving up
    per-row addressability, which a single concatenated stream would.

    Filled with the most *frequent* whole tails rather than the most frequent tokens:
    both were measured, and whole values won by a wide margin (the compressed tail
    lands at 19% of raw against 32%), because a repeated tail then costs a reference
    rather than a re-encoding. Ordered by frequency and then by value so a rebuild of
    the same graph produces the same dictionary, byte for byte, and put in *reverse*
    order because deflate's window looks backwards: the most useful material has to
    sit at the end, nearest the data.
    """
    counts = collections.Counter(texts)
    parts, total = [], 0
    for value, _n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        if total + len(value) > PROPS_DICT_SIZE:
            continue  # skip, don't stop: a later, smaller value may still fit
        parts.append(value)
        total += len(value)
        if total >= PROPS_DICT_SIZE:
            break
    return b"".join(reversed(parts))[-PROPS_DICT_SIZE:]


def _is_test_file(path: Optional[str]) -> bool:
    if not path:
        return False
    from lachesis.nav.symbol_index import is_test_path  # single source of truth
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
    cols.append("props BLOB")
    cols.append("PRIMARY KEY (id)")
    return "CREATE NODE TABLE Node(" + ", ".join(cols) + ")"


def _rel_ddl() -> list[str]:
    # `unit` (= emitting source file) is the §5 incremental key, carried on every
    # edge as well as every node. Column order is the rel-COPY contract: the two
    # endpoint PKs come first, then the properties in this definition order.
    stmts = [f"CREATE REL TABLE {kind}(FROM Node TO Node, unit STRING, props BLOB)"
             for kind in HOT_REL_KINDS]
    stmts.append("CREATE REL TABLE EDGE(FROM Node TO Node, "
                 "kind STRING, semantic_kind STRING, unit STRING, props BLOB)")
    return stmts


def _deferred_ddl() -> str:
    """The table for edges whose endpoints this store does not hold.

    A rel table cannot express them: both ends are foreign keys into ``Node``, and the
    whole point of a spine-and-semantic store is that one end is a body node it dropped
    on purpose, to be recompiled at load. So the endpoints are carried as coded strings
    in a node table that is never traversed, only read out whole and rejoined once the
    bodies are back. ``seq`` is a primary key because Kùzu needs one, and nothing means
    anything by it beyond insertion order.
    """
    return ("CREATE NODE TABLE DeferredEdge(seq INT64, kind STRING, src STRING, "
            "tgt STRING, unit STRING, props BLOB, PRIMARY KEY (seq))")


def _index_ddl() -> list:
    """The four resolution tables: two name indices, two memo tables.

    All four are declared together, and all four are declared *unconditionally*. An
    empty table is a fact — "this store holds no call sites" — whereas an absent one is
    a question, and a reader cannot tell a store built before the table existed from a
    store whose index legitimately came out empty. Declaring the memo tables here even
    though nothing writes them yet is the same trade in time rather than in content: a
    format bump is a rebuild for every user (KUZU_STORE_SPEC.md), so the version that
    adds the indices pays for the memos too rather than charging twice.

    ``seq`` is a primary key because Kùzu needs one and means nothing beyond insertion
    order — the same shape as ``DeferredEdge``, and for the same reason: these are rows
    read out whole and grouped by name, never traversed.

    Every field is a typed column and there is no ``props`` blob, deliberately. The
    point of an index is to be queryable without decompressing anything, in Cypher, by
    somebody who is not this module.

    ``graph_hash`` is a **column** on both memo tables, not an assumption. The base
    store and its ``.enriched`` sidecar are two databases over two hashes, and a memo
    that crossed between them would answer a question about a graph it never saw.
    """
    return [
        ("CREATE NODE TABLE DeclIndex(seq INT64, name STRING, node_id STRING, "
         "kind STRING, granularity STRING, file STRING, line INT64, "
         "signature STRING, unit STRING, exported BOOLEAN, "
         "declaration_only BOOLEAN, PRIMARY KEY (seq))"),
        ("CREATE NODE TABLE CallsiteIndex(seq INT64, callee_name STRING, "
         "node_id STRING, owner_id STRING, file STRING, line INT64, unit STRING, "
         "form STRING, receiver STRING, PRIMARY KEY (seq))"),
        # Phase 2 writes these; v9 only promises they exist.
        #
        # `truncated` is on ResolveMemo and not only on ConeMemo because measurement
        # said so. On Suricata's `src/`, `SBB_RB_FIND` and eight siblings resolve to
        # **473** declarations each — the red-black-tree macros, expanded `static` into
        # every translation unit that includes the header — and `TCPSACK_RB_*` to 183.
        # A conservative candidate list has to be capped somewhere around there, and a
        # cap that cannot say it capped is a wrong answer rather than a partial one.
        # It is a thin tail (50 of 22,233 call sites, 0.2%) and that is the argument for
        # the flag rather than against it: the case is rare enough to go unnoticed and
        # large enough to matter when it does not.
        ("CREATE NODE TABLE ResolveMemo(seq INT64, graph_hash STRING, "
         "node_id STRING, target STRING, candidates STRING, confidence STRING, "
         "truncated BOOLEAN, PRIMARY KEY (seq))"),
        ("CREATE NODE TABLE ConeMemo(seq INT64, graph_hash STRING, node_id STRING, "
         "budget INT64, members STRING, truncated BOOLEAN, PRIMARY KEY (seq))"),
    ]


# Column order is the COPY contract for each index table: it must match `_index_ddl`.
_DECL_INDEX_COLUMNS = ("name", "node_id", "kind", "granularity", "file", "line",
                       "signature", "unit", "exported", "declaration_only")
_CALLSITE_INDEX_COLUMNS = ("callee_name", "node_id", "owner_id", "file", "line",
                           "unit", "form", "receiver")
# Which of those columns hold a node id, and are therefore written coded.
_INDEX_ID_COLUMNS = ("node_id", "owner_id")
_INDEX_INT_COLUMNS = frozenset({"line"})
_INDEX_BOOL_COLUMNS = frozenset({"exported", "declaration_only"})


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
    carry_unresolved_edges: bool = False,
    source_dir: Optional[str] = None,
    source_content_hash: Optional[str] = None,
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

    ``carry_unresolved_edges`` keeps the edges whose endpoints are not both resident,
    in a table of their own, instead of dropping them. That is what a spine-and-semantic
    store needs: a semantic fact about a value inside a function is an edge into a body
    node the store deliberately does not hold, and it becomes attachable again the moment
    the bodies are recompiled. Off by default, because for an ordinary whole-graph store
    an edge with a missing endpoint is a bug and silence about it would hide one.

    ``source_dir`` and ``source_content_hash`` say which source tree this store was built
    from and what it hashed to. A reduced store cannot be read without them: getting the
    bodies back means compiling that tree again, and the hash is what says whether an
    already-joined cache still describes it.
    """
    if kuzu is None:
        raise RuntimeError(
            "kuzu is not installed; the Kùzu writer needs Python 3.10+ with `kuzu`. "
            "Create a venv (e.g. `python3.11 -m venv .venv-kuzu && "
            ".venv-kuzu/bin/pip install kuzu`) and run there."
        )
    target_db_dir = os.path.abspath(db_dir)
    if os.path.exists(target_db_dir) and not overwrite:
        raise FileExistsError(target_db_dir)
    # Publish only after every table and the manifest are complete. A killed large
    # build must never leave a path that looks like a valid but partial store.
    db_dir = tempfile.mkdtemp(prefix=".lachesis-stream-", dir=os.path.dirname(target_db_dir))

    nodes = _kept_nodes(graph.get("nodes", []), prune=prune,
                        drop_diagnostics=drop_diagnostics, drop_tests=drop_tests)
    kept_ids = {n["id"] for n in nodes}
    # An edge whose endpoints are not both resident cannot be stored: `Node` is the only
    # node table and both ends are foreign keys into it. Dropping such an edge is right,
    # but dropping it *quietly* is not — the counts below describe what was stored, so a
    # caller comparing them against its input graph learns that something went missing
    # without learning how much. Every partial store (pruned, test-filtered, or holding
    # only part of a layered graph) crosses this line, so the number is worth naming.
    edges, unresolved = [], []
    for edge in graph.get("edges", []):
        resident = edge.get("source") in kept_ids and edge.get("target") in kept_ids
        (edges if resident else unresolved).append(edge)
    unresolved_edge_count = len(unresolved)
    dropped_node_count = len(graph.get("nodes", [])) - len(nodes)
    deferred = unresolved if carry_unresolved_edges else []
    # id -> owning file, so an edge (which carries no `file` of its own) can inherit
    # its source node's unit as the §5 incremental key.
    node_units = {n["id"]: _node_unit(n.get("properties") or {}) for n in nodes}

    db = kuzu.Database(db_file(db_dir), buffer_pool_size=_kuzu_buffer_pool_size(),
                        checkpoint_threshold=_kuzu_checkpoint_threshold())
    conn = kuzu.Connection(db)
    conn.execute(_node_ddl())
    for stmt in _rel_ddl():
        conn.execute(stmt)
    if deferred:
        conn.execute(_deferred_ddl())
    for stmt in _index_ddl():
        conn.execute(stmt)

    # The name indices, over what the store actually holds. Built here rather than in
    # `enrich_graph` because a store need not be enriched — `cli/indexer.py` writes one
    # with `enrich=False` — and this is the single choke point every store passes
    # through. They are a function of the *kept* nodes, so the index describes the store
    # and not the graph it was projected from.
    decl_index = build_decl_index(nodes, exported_ids(edges))
    callsite_index = build_callsite_index(nodes)
    decl_rows = index_rows(decl_index)
    callsite_rows = index_rows(callsite_index)

    # Bulk `COPY FROM` staged Parquet is the fast path (per-row inserts measured
    # ~9.4 min/package — too slow for whole-repo). When pyarrow is absent we fall
    # back to per-row inserts so the module still works everywhere.
    # One pre-pass over both sides to build the shared deflate dictionary. It has to
    # come first, and it has to see nodes *and* edges: the dictionary is a property of
    # the store, not of a table, and the two sides repeat different material (nodes
    # repeat `frontend_id`/`language`, edges repeat `relationship_class`/`source_tier`),
    # so a dictionary built from either alone serves the other poorly.
    #
    # The two passes are inherent and stay: picking the most frequent tails needs counts
    # over the whole corpus, so the first row cannot be compressed until the last has
    # been seen. What does not have to stay is *rebuilding* the tails for the second
    # pass, so they are kept here and handed to the loaders. On a graph of this repo that
    # is ~740k tails and about 90 MB held for the length of the write, and it grows with
    # the graph — the trade is memory against a second full JSON serialisation of every
    # row.
    low_memory = os.environ.get("LACHESIS_KUZU_LOW_MEMORY") == "1"
    if low_memory:
        # Rebuild each JSON tail on demand instead of retaining one serialized tail
        # per node and edge. This trades the shared dictionary for a lower peak.
        props_dict = b""
        node_codec = PropsCodec()
        edge_codec = PropsCodec()
        deferred_codec = PropsCodec()
    else:
        node_texts = [_props_text(n.get("properties") or {}, elide_constants, _COLUMN_KEYS)
                      for n in nodes]
        edge_texts = [_props_text(e.get("properties") or {}, elide_constants)
                      for e in edges]
        deferred_texts = [_props_text(e.get("properties") or {}, elide_constants)
                          for e in deferred]
        props_dict = build_props_dictionary(
            itertools.chain(node_texts, edge_texts, deferred_texts))
        node_codec = PropsCodec(props_dict, node_texts)
        edge_codec = PropsCodec(props_dict, edge_texts)
        deferred_codec = PropsCodec(props_dict, deferred_texts)

    # The other manifest-carried table: the id prefixes the coded columns are written
    # against. Nodes only — every coded column is on the node table — and the whole
    # table has to exist before the first row is written, since a code is an index into
    # it. Edge endpoints need no pass of their own: an endpoint is a node id, so its
    # prefix is already here by way of that node's own `id`.
    # The one exception is a deferred edge: its far endpoint is a node this store does not
    # hold, so no pass over `nodes` will ever have seen that prefix, and leaving it out
    # would store the longest ids in the file uncoded.
    # The index tables' id columns join the pass too. Their `node_id`s are node ids this
    # store holds, so their prefixes are already here by way of `n.get("id")` — but an
    # `owner_id` can name a node that pruning dropped, and a prefix missing from the
    # table means that column is stored uncoded, which is the one case the codec cannot
    # notice on its own.
    id_prefixes = build_id_prefixes(itertools.chain(
        (n.get("id") for n in nodes),
        ((n.get("properties") or {}).get(column)
         for n in nodes for column in CODED_PROP_COLUMNS),
        (end for e in deferred for end in (e.get("source"), e.get("target"))),
        (row.get(column)
         for row in itertools.chain(decl_rows, callsite_rows)
         for column in _INDEX_ID_COLUMNS),
    ))
    id_codes = {prefix: _prefix_code(i) for i, prefix in enumerate(id_prefixes)}

    if pa is not None and pq is not None:
        with tempfile.TemporaryDirectory(prefix="kuzu_stage_") as stage_dir:
            _load_nodes_bulk(conn, nodes, elide=elide_constants, stage_dir=stage_dir,
                             codec=node_codec, id_codes=id_codes)
            _load_edges_bulk(conn, edges, elide=elide_constants, stage_dir=stage_dir,
                             node_units=node_units, codec=edge_codec,
                             id_codes=id_codes)
            _load_deferred_bulk(conn, deferred, elide=elide_constants,
                                stage_dir=stage_dir, node_units=node_units,
                                codec=deferred_codec, id_codes=id_codes)
            _load_index_bulk(conn, "DeclIndex", _DECL_INDEX_COLUMNS, decl_rows,
                             stage_dir=stage_dir, id_codes=id_codes)
            _load_index_bulk(conn, "CallsiteIndex", _CALLSITE_INDEX_COLUMNS,
                             callsite_rows, stage_dir=stage_dir, id_codes=id_codes)
    else:  # pragma: no cover - exercised only without pyarrow
        _load_nodes_rowwise(conn, nodes, elide=elide_constants, codec=node_codec,
                            id_codes=id_codes)
        _load_edges_rowwise(conn, edges, elide=elide_constants, node_units=node_units,
                            codec=edge_codec, id_codes=id_codes)
        _load_deferred_rowwise(conn, deferred, elide=elide_constants,
                               node_units=node_units, codec=deferred_codec,
                               id_codes=id_codes)
        _load_index_rowwise(conn, "DeclIndex", _DECL_INDEX_COLUMNS, decl_rows,
                            id_codes=id_codes)
        _load_index_rowwise(conn, "CallsiteIndex", _CALLSITE_INDEX_COLUMNS,
                            callsite_rows, id_codes=id_codes)
    # counts describe what the store actually holds, which is the pruned set, not the
    # composed input — a reader comparing them against a scan should find them equal.
    payload = manifest_payload(graph, snapshots)
    payload["node_count"] = len(nodes)
    payload["edge_count"] = len(edges)
    # What the input had and the store does not. Zero for an ordinary lossless write; a
    # reader that finds these non-zero knows the store is a projection of a larger graph
    # rather than the whole of one, which is a different thing to reason about.
    payload["dropped_node_count"] = dropped_node_count
    payload["unresolved_edge_count"] = unresolved_edge_count
    # How many of those unresolved edges are still in the store, waiting for a recompile
    # to give them their far endpoint back. Equal to `unresolved_edge_count` for a
    # deferred store, zero for every other one.
    payload["deferred_edge_count"] = len(deferred)
    # Counts, not booleans. "The index exists" is true of an empty table and tells a
    # reader nothing; a zero here on a store that holds functions is a visible fault.
    payload["decl_index_count"] = len(decl_rows)
    payload["callsite_index_count"] = len(callsite_rows)
    # A reduced store is not a smaller graph, it is half of one: the bodies are missing on
    # purpose and a load has to recompile them. Saying so in the manifest is what lets a
    # reader tell that apart from a store that simply holds less.
    payload["reduced"] = bool(carry_unresolved_edges)
    if source_dir:
        payload["source_dir"] = os.path.abspath(source_dir)
    if source_content_hash:
        payload["source_content_hash"] = source_content_hash
    payload["enriched"] = bool(enriched)
    # Base64 rather than raw bytes because the manifest is JSON, and in the manifest
    # rather than a sidecar file because losing it makes every `props` blob in the
    # store unreadable: it is part of the store, not metadata about it.
    payload[PROPS_DICT_KEY] = base64.b64encode(props_dict).decode("ascii")
    # Plain JSON strings, not base64: the prefix table is short, and leaving it legible
    # means a coded column can be read by hand from a Cypher dump. Same reason as the
    # dictionary for living here rather than in a sidecar — a code is an index into
    # this list, so losing it makes every coded value unreadable.
    payload[ID_PREFIX_KEY] = id_prefixes
    # The hash describes what was *stored*, so pruning is inside the key: a pruned core
    # and a lossless one are different cores and must not share a derived cache.
    payload["core_content_hash"] = (
        core_content_hash if core_content_hash is not None
        else (None if enriched else graph_content_hash(nodes, edges))
    )
    with open(store_manifest_file(db_dir), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    if os.path.exists(target_db_dir):
        shutil.rmtree(target_db_dir) if os.path.isdir(target_db_dir) else os.remove(target_db_dir)
    os.replace(db_dir, target_db_dir)
    return target_db_dir


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
    if column == "props":
        return pa.binary()
    return pa.int64() if column in _INT_COLUMNS else pa.string()


def _utf8_safe(text: str) -> str:
    """Strip code points that cannot round-trip through UTF-8.

    Parquet/Arrow string columns are UTF-8, so a lone UTF-16 surrogate — e.g. an
    astral emoji that a byte-offset snippet sliced through the middle of — is not
    encodable and makes ``pa.array`` raise, aborting the whole graph write over a
    single node. The authoritative copy of this value lives in the ``props`` blob
    (this column is a denormalized promotion the tail overrides on read), so
    replacing the unencodable point here is invisible to reconstruction."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")


def _cell(column: str, value):
    """Coerce a promoted-column value to its Parquet type.

    A value this has to coerce is one `_column_faithful` refused, so it is still in
    the ``props`` tail and the tail wins on read: the coercion stays invisible in
    reconstructed dicts. That is now a two-sided invariant — loosen the check there
    and this silently starts rewriting properties."""
    if value is None:
        return None
    if column == "props":
        return value  # already bytes from `PropsCodec.blob`; str() would corrupt it
    if column in _INT_COLUMNS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return _utf8_safe(value if isinstance(value, str) else str(value))


def _str_col(values: list) -> "pa.Array":
    return pa.array(
        [None if v is None else _utf8_safe(str(v)) for v in values], pa.string())


def _load_nodes_bulk(conn, nodes: list[dict], *, elide: bool, stage_dir: str,
                     codec: PropsCodec, id_codes: Optional[dict] = None) -> None:
    if not nodes:
        return
    columns = ["id", "kind", "label", *PROMOTED_NODE_PROPS, "props"]
    data: dict[str, list] = {c: [] for c in columns}
    for index, node in enumerate(nodes):
        props = node.get("properties") or {}
        data["id"].append(encode_id(node["id"], id_codes or {}))
        data["kind"].append(node.get("kind"))
        data["label"].append(node.get("label"))
        for prop in PROMOTED_NODE_PROPS:
            data[prop].append(_coded_cell(prop, _promoted_value(props, prop),
                                          id_codes or {}))
        data["props"].append(codec.blob(index, props, elide, _COLUMN_KEYS))
    table = pa.table({c: pa.array([_cell(c, v) for v in data[c]], type=_arrow_type(c))
                      for c in columns})
    path = os.path.join(stage_dir, "node.parquet")
    pq.write_table(table, path)
    conn.execute(f"COPY Node FROM '{path}'")


def _load_edges_bulk(conn, edges: list[dict], *, elide: bool, stage_dir: str,
                     node_units: dict, codec: PropsCodec,
                     id_codes: Optional[dict] = None) -> None:
    # group edges by destination table; column order is the rel-COPY contract
    # (endpoint PKs first, then properties in table-definition order).
    hot: dict[str, dict[str, list]] = {
        kind: {"src": [], "tgt": [], "unit": [], "props": []}
        for kind in HOT_REL_KINDS
    }
    cold: dict[str, list] = {"src": [], "tgt": [], "kind": [], "sem": [],
                             "unit": [], "props": []}
    # An endpoint is matched against the `id` column, so it has to be coded the same way
    # that column was — the staged Parquet holds coded ids, not the graph's own.
    codes = id_codes or {}
    for index, edge in enumerate(edges):
        kind = edge.get("kind")
        props = edge.get("properties") or {}
        unit = _edge_unit(edge, node_units)
        stored = codec.blob(index, props, elide)
        src, tgt = encode_id(edge["source"], codes), encode_id(edge["target"], codes)
        if kind in _HOT_SET:
            bucket = hot[kind]
            bucket["src"].append(src)
            bucket["tgt"].append(tgt)
            bucket["unit"].append(unit)
            bucket["props"].append(stored)
        else:
            cold["src"].append(src)
            cold["tgt"].append(tgt)
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
            "props": pa.array(bucket["props"], pa.binary()),
        })
        path = os.path.join(stage_dir, f"rel_{kind}.parquet")
        pq.write_table(table, path)
        conn.execute(f"COPY {kind} FROM '{path}'")

    if cold["src"]:
        table = pa.table({
            "src": _str_col(cold["src"]), "tgt": _str_col(cold["tgt"]),
            "kind": _str_col(cold["kind"]), "sem": _str_col(cold["sem"]),
            "unit": _str_col(cold["unit"]),
            "props": pa.array(cold["props"], pa.binary()),
        })
        path = os.path.join(stage_dir, "rel_EDGE.parquet")
        pq.write_table(table, path)
        conn.execute(f"COPY EDGE FROM '{path}'")


def _load_deferred_bulk(conn, deferred: list[dict], *, elide: bool, stage_dir: str,
                        node_units: dict, codec: PropsCodec,
                        id_codes: Optional[dict] = None) -> None:
    if not deferred:
        return
    codes = id_codes or {}
    columns = {"seq": [], "kind": [], "src": [], "tgt": [], "unit": [], "props": []}
    for seq, edge in enumerate(deferred):
        columns["seq"].append(seq)
        columns["kind"].append(edge.get("kind"))
        columns["src"].append(encode_id(edge["source"], codes))
        columns["tgt"].append(encode_id(edge["target"], codes))
        columns["unit"].append(_edge_unit(edge, node_units))
        columns["props"].append(
            codec.blob(seq, edge.get("properties") or {}, elide))
    table = pa.table({
        "seq": pa.array(columns["seq"], pa.int64()),
        "kind": _str_col(columns["kind"]), "src": _str_col(columns["src"]),
        "tgt": _str_col(columns["tgt"]), "unit": _str_col(columns["unit"]),
        "props": pa.array(columns["props"], pa.binary()),
    })
    path = os.path.join(stage_dir, "deferred.parquet")
    pq.write_table(table, path)
    conn.execute(f"COPY DeferredEdge FROM '{path}'")


def _index_cell(column: str, value, codes: dict):
    """One index cell in stored form: ids coded, booleans real booleans, rest as-is."""
    if column in _INDEX_ID_COLUMNS:
        return encode_id(value, codes) if value else None
    if column in _INDEX_BOOL_COLUMNS:
        return bool(value)
    return value


def _load_index_bulk(conn, table_name: str, columns: tuple, rows: list, *,
                     stage_dir: str, id_codes: Optional[dict] = None) -> None:
    if not rows:
        return
    codes = id_codes or {}
    staged = {"seq": pa.array(list(range(len(rows))), pa.int64())}
    for column in columns:
        cells = [_index_cell(column, row.get(column), codes) for row in rows]
        if column in _INDEX_BOOL_COLUMNS:
            staged[column] = pa.array(cells, pa.bool_())
        elif column in _INDEX_INT_COLUMNS:
            staged[column] = pa.array(
                [None if cell is None else int(cell) for cell in cells], pa.int64())
        else:
            staged[column] = _str_col(cells)
    path = os.path.join(stage_dir, f"{table_name.lower()}.parquet")
    pq.write_table(pa.table(staged), path)
    conn.execute(f"COPY {table_name} FROM '{path}'")


# -- per-row fallback (no pyarrow): same output, one CREATE per row ------------

def _blob_param(blob: bytes) -> str:
    """A ``props`` blob as something a Cypher parameter can actually carry.

    Kùzu 0.11.3 binds no Python type to ``BLOB``: ``bytes`` and ``bytearray`` both come
    back as "Unknown parameter type". So the parameter is a string of ``\\xHH`` escapes
    and the statement casts it, which round-trips all 256 byte values. Only the rowwise
    path needs this; the bulk path hands Kùzu an Arrow binary column and never binds a
    parameter at all.
    """
    return "".join("\\x%02X" % byte for byte in blob)

def _load_nodes_rowwise(conn, nodes: list[dict], *, elide: bool,
                        codec: PropsCodec,
                        id_codes: Optional[dict] = None) -> None:
    columns = ["id", "kind", "label", *PROMOTED_NODE_PROPS, "props"]
    placeholders = ", ".join(
        f"{c}: CAST($props AS BLOB)" if c == "props" else f"{c}: ${c}"
        for c in columns)
    stmt = f"CREATE (n:Node {{{placeholders}}})"
    conn.execute("BEGIN TRANSACTION")
    try:
        for index, node in enumerate(nodes):
            props = node.get("properties") or {}
            params = {"id": encode_id(node["id"], id_codes or {}),
                      "kind": node.get("kind"),
                      "label": node.get("label")}
            for prop in PROMOTED_NODE_PROPS:
                params[prop] = _coded_cell(prop, _promoted_value(props, prop),
                                           id_codes or {})
            params["props"] = _blob_param(
                codec.blob(index, props, elide, _COLUMN_KEYS))
            conn.execute(stmt, params)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _load_edges_rowwise(conn, edges: list[dict], *, elide: bool, node_units: dict,
                        codec: PropsCodec,
                        id_codes: Optional[dict] = None) -> None:
    hot_stmt = {
        kind: (f"MATCH (a:Node), (b:Node) WHERE a.id = $s AND b.id = $t "
               f"CREATE (a)-[:{kind} "
               f"{{unit: $unit, props: CAST($props AS BLOB)}}]->(b)")
        for kind in HOT_REL_KINDS
    }
    edge_stmt = ("MATCH (a:Node), (b:Node) WHERE a.id = $s AND b.id = $t "
                 "CREATE (a)-[:EDGE {kind: $kind, semantic_kind: $sem, "
                 "unit: $unit, props: CAST($props AS BLOB)}]->(b)")
    conn.execute("BEGIN TRANSACTION")
    try:
        for index, edge in enumerate(edges):
            kind = edge.get("kind")
            props = edge.get("properties") or {}
            base = {"s": encode_id(edge["source"], id_codes or {}),
                    "t": encode_id(edge["target"], id_codes or {}),
                    "unit": _edge_unit(edge, node_units),
                    "props": _blob_param(codec.blob(index, props, elide))}
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


def _load_deferred_rowwise(conn, deferred: list[dict], *, elide: bool,
                           node_units: dict, codec: PropsCodec,
                           id_codes: Optional[dict] = None) -> None:
    if not deferred:
        return
    stmt = ("CREATE (d:DeferredEdge {seq: $seq, kind: $kind, src: $src, tgt: $tgt, "
            "unit: $unit, props: CAST($props AS BLOB)})")
    codes = id_codes or {}
    conn.execute("BEGIN TRANSACTION")
    try:
        for seq, edge in enumerate(deferred):
            conn.execute(stmt, {
                "seq": seq, "kind": edge.get("kind"),
                "src": encode_id(edge["source"], codes),
                "tgt": encode_id(edge["target"], codes),
                "unit": _edge_unit(edge, node_units),
                "props": _blob_param(
                    codec.blob(seq, edge.get("properties") or {}, elide)),
            })
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _load_index_rowwise(conn, table_name: str, columns: tuple, rows: list, *,
                        id_codes: Optional[dict] = None) -> None:
    if not rows:
        return
    codes = id_codes or {}
    placeholders = ", ".join(["seq: $seq"] + [f"{c}: ${c}" for c in columns])
    stmt = f"CREATE (r:{table_name} {{{placeholders}}})"
    conn.execute("BEGIN TRANSACTION")
    try:
        for seq, row in enumerate(rows):
            params = {"seq": seq}
            for column in columns:
                cell = _index_cell(column, row.get(column), codes)
                params[column] = (
                    None if cell is None and column in _INDEX_INT_COLUMNS
                    else (int(cell) if column in _INDEX_INT_COLUMNS else cell)
                )
            conn.execute(stmt, params)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def write_kuzu_shards(shard_reader, db_dir: str, snapshots=None, *, prune: bool = True,
                      overwrite: bool = True) -> str:
    """Materialize a streaming shard reader without a whole graph dictionary."""
    if kuzu is None:
        raise RuntimeError("kuzu is required for streamed materialization")
    target_db_dir = os.path.abspath(db_dir)
    if os.path.exists(target_db_dir):
        if not overwrite:
            raise FileExistsError(target_db_dir)
    # Build beside the requested path and publish only after all tables, indices,
    # and the manifest are complete. An interrupted large run must not expose a
    # directory that looks like a valid but partial store.
    db_dir = tempfile.mkdtemp(prefix=".lachesis-stream-",
                              dir=os.path.dirname(target_db_dir))

    kept_ids: set[str] = set()
    node_units: dict[str, str] = {}
    prefixes: set[str] = set()
    # Index candidates are spilled while the large node/edge streams are loaded.
    # Keeping hundreds of thousands of full property dictionaries alive here was a
    # surprising multi-GB peak on Linux/net; the index builders only need them again
    # after the graph tables are complete.
    index_stage = tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8",
                                               prefix="lachesis-index-", delete=False)
    for node in shard_reader.nodes():
        kind = node.get("kind")
        if prune and kind in PRUNE_NODE_KINDS:
            continue
        node_id = node["id"]
        props = node.get("properties") or {}
        kept_ids.add(node_id)
        if props.get("file"):
            node_units[node_id] = props["file"]
        for value in (node_id, props.get("compiler_node_id")):
            match = _ID_SHAPE.match(value) if isinstance(value, str) else None
            if match:
                prefixes.add(match.group(1))
        if kind in INDEXED_KINDS or kind in CALLSITE_KINDS:
            index_stage.write(json.dumps(node, ensure_ascii=False, separators=(",", ":")))
            index_stage.write("\n")

    exported: set[str] = set()
    unresolved_count = 0
    for edge in shard_reader.edges():
        if edge.get("kind") == "EXPORTS" and edge.get("target"):
            exported.add(edge["target"])
        if edge.get("source") not in kept_ids or edge.get("target") not in kept_ids:
            unresolved_count += 1
        for value in (edge.get("source"), edge.get("target")):
            match = _ID_SHAPE.match(value) if isinstance(value, str) else None
            if match:
                prefixes.add(match.group(1))
    id_codes = {prefix: _prefix_code(i) for i, prefix in enumerate(sorted(prefixes))}

    # Streamed materialization is explicitly the bounded-memory path. Keep a
    # predictable 1 GiB cache by default; callers can raise/lower it with the env.
    db = kuzu.Database(
        db_file(db_dir), buffer_pool_size=_kuzu_buffer_pool_size(1 << 30),
        checkpoint_threshold=_kuzu_checkpoint_threshold(256 << 20),
    )
    conn = kuzu.Connection(db)
    conn.execute(_node_ddl())
    for stmt in _rel_ddl():
        conn.execute(stmt)
    for stmt in _index_ddl():
        conn.execute(stmt)
    codec = PropsCodec()
    bulk = pa is not None and pq is not None
    stage = tempfile.TemporaryDirectory(prefix="kuzu_stream_stage_") if bulk else None

    def load_nodes(batch: list[dict]) -> None:
        if not batch:
            return
        if bulk:
            _load_nodes_bulk(conn, batch, elide=True, stage_dir=stage.name,
                             codec=codec, id_codes=id_codes)
        else:
            _load_nodes_rowwise(conn, batch, elide=True, codec=codec, id_codes=id_codes)

    def load_edges(batch: list[dict]) -> None:
        if not batch:
            return
        if bulk:
            _load_edges_bulk(conn, batch, elide=True, stage_dir=stage.name,
                             node_units=node_units, codec=codec, id_codes=id_codes)
        else:
            _load_edges_rowwise(conn, batch, elide=True, node_units=node_units,
                                codec=codec, id_codes=id_codes)

    batch: list[dict] = []
    for node in shard_reader.nodes():
        if prune and node.get("kind") in PRUNE_NODE_KINDS:
            continue
        batch.append(node)
        if len(batch) >= 10_000:
            load_nodes(batch)
            batch.clear()
    if batch:
        load_nodes(batch)

    batch = []
    kept_edge_count = 0
    for edge in shard_reader.edges():
        if edge.get("source") not in kept_ids or edge.get("target") not in kept_ids:
            continue
        batch.append(edge)
        kept_edge_count += 1
        if len(batch) >= 10_000:
            load_edges(batch)
            batch.clear()
    if batch:
        load_edges(batch)
    index_stage.flush()
    index_stage.seek(0)
    indexed_nodes = (json.loads(line) for line in index_stage if line.strip())
    decl_rows = index_rows(build_decl_index(indexed_nodes, exported))
    index_stage.seek(0)
    indexed_nodes = (json.loads(line) for line in index_stage if line.strip())
    callsite_rows = index_rows(build_callsite_index(indexed_nodes))
    index_stage.close()
    os.unlink(index_stage.name)
    if bulk:
        _load_index_bulk(conn, "DeclIndex", _DECL_INDEX_COLUMNS, decl_rows,
                         stage_dir=stage.name, id_codes=id_codes)
        _load_index_bulk(conn, "CallsiteIndex", _CALLSITE_INDEX_COLUMNS,
                         callsite_rows, stage_dir=stage.name, id_codes=id_codes)
    else:
        _load_index_rowwise(conn, "DeclIndex", _DECL_INDEX_COLUMNS, decl_rows,
                            id_codes=id_codes)
        _load_index_rowwise(conn, "CallsiteIndex", _CALLSITE_INDEX_COLUMNS,
                            callsite_rows, id_codes=id_codes)
    if stage is not None:
        stage.cleanup()
    payload = manifest_payload({"nodes": [], "edges": []}, snapshots)
    payload.update({
        "node_count": len(kept_ids), "edge_count": kept_edge_count,
        "unresolved_edge_count": unresolved_count,
        "dropped_node_count": 0, "deferred_edge_count": 0,
        "decl_index_count": len(decl_rows), "callsite_index_count": len(callsite_rows),
        "streamed": True, PROPS_DICT_KEY: "", ID_PREFIX_KEY: sorted(prefixes),
    })
    with open(store_manifest_file(db_dir), "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    if os.path.exists(target_db_dir):
        shutil.rmtree(target_db_dir) if os.path.isdir(target_db_dir) else os.remove(target_db_dir)
    os.replace(db_dir, target_db_dir)
    return target_db_dir
