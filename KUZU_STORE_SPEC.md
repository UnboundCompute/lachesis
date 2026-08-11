# Lachesis graph store: JSON → Kùzu migration spec

**Status:** landed, and the migration is finished. The Kùzu store is now the only
graph store: the JSON writer and the JSON load path have been removed, so the
"current-state map" in §1 and the dual-write instruction in §3 describe the
before-state this spec was written against, not the code today. Everything about
the on-disk layout, the prune levers, and the incremental unit key still holds.
**Audience:** the engine session that writes Lachesis/nav code.
**Author of spec:** referee session (validation + design only).

---

## 0. Why (the validated basis — don't re-litigate)

Measured on a real single-package L graph (the largest package in the reference workload):

| | nodes | edges | on-disk |
|---|---|---|---|
| baseline JSON | 505,925 | 926,245 | **879 MB** |
| drop `token`+`source-span` (pure lexical) | 246,633 | 495,622 | 509 MB (−42%) |
| + compact encoding (int-ids, drop constant keys) — *projection* | 246,633 | 495,622 | 336 MB (−62%, projected) |
| **measured pruned Kùzu DB (this session)** | 246,633 | 495,622 | **433 MB (−49%)** |

> **Correction (measured, don't plan against −62%):** the pruned Kùzu DB is **433 MB (−49% vs 879 MB
> JSON)**, not the projected 336 MB. The long-tail props stored as a JSON string column dominate and Kùzu
> adds page overhead, so "the encoding tax is free in Kùzu" was overstated on *disk*. **This is not a
> blocker — disk was never the ceiling. RAM was.** The real, validated win: serving off Kùzu is **385 MB
> RSS, opens in 1.6 s**, versus the JSON path parsing the whole ~850 MB into multi-GB RAM over ~124 s. The
> store serves correctly (functions=1438; the parity test proved nav equivalence).

Nav (`hubs`/`search`/`callers`/`callees`/`read_body`) verified **intact** on the pruned graph.

Two independent shrink levers were proven:
- **Lever A — node granularity:** `token` (171K) + `source-span` (87K) are pure lexical/positional nodes no nav tool reads. Dropping them = −51% nodes. `read_body` reads the *source file by offset*, not these nodes, so it is lossless.
- **Lever B — encoding tax (~45%):** every node id is a ~50-byte string (`v2:frontend:typescript-compiler-api:function:0033aa2979bbad970b58`) repeated as `source`/`target` on all 926K edges; plus constant keys `fact_origin:"compiler"`, `confidence:"exact"`, `evidence_ids:[]` on nearly every node **and** edge; plus per-edge `relationship_class`/`source_tier`/`frontend_id`.

**Kùzu removes the RAM ceiling** (the actual prize) and recovers part of the encoding tax:
- String PK is **dictionary-encoded** → each id stored once, referenced internally as a dense int. The id tax on endpoints largely evaporates with zero compaction code.
- Constant/low-cardinality columns compress well; but the **non-promoted long-tail props still ride as a JSON string column**, which (plus page overhead) is why disk lands at −49%, not the projected −62%. Disk is a secondary benefit, not the goal.
- **Disk-backed columnar + mmap** → the nav server no longer loads the whole graph into RAM (today's 16 GB ceiling): **measured 385 MB RSS / 1.6 s open** vs multi-GB / ~124 s JSON parse. This is what blocks-then-unblocks whole-repo.
- Lever A stays an explicit ingest-time prune (below).

Net: this is what makes **whole-repo** graphs viable, which is a *correctness* requirement, not a nicety — a partial graph produces confidently-wrong reachability/safety verdicts (the SSRF-guard-outside-scope failure we already hit).

---

## 1. Current-state map (what you're changing — real file:lines)

### Writer (`Lachesis/pipeline.py`)
- `snapshot_graph` (`:15`) → one frontend snapshot to canonical `{"nodes":[...], "edges":[...]}`; stamps `frontend_id`/`frontend_tier` into node props (`:24-27`).
- `combine_graphs` (`:43`) → unions per-frontend graphs; dedupes edges by `(kind, source, target, json.dumps(properties, sort_keys=True))` (`:55-58`); rejects conflicting node ids + dangling edges.
- `_enrich_graph` (`:115`) → overlay/ecosystem/security enrichment before write.
- `write_project_graph` (`:179`) → builds `payload = {"manifest": {...v2 inventory...}, "nodes":[...], "edges":[...]}`; **disk write is `pipeline.py:199`**: `output.write_text(json.dumps(payload, indent=2) + "\n")`.
- CLI entry: `Lachesis/cli/analyze.py:25`.

### Loader / store (`nav/`)
- `GraphStore` (`nav/graph_store.py:75`); `.load(graph_path, overlay_path)` (`:90`) → `load_graph` (`Lachesis/cli/query.py:15`, `json.loads`).
- In-memory index: `GraphIndex` (`Lachesis/core/query.py:8`), wrapped by `GraphLib` (`nav/graphlib.py`). Builds once:
  - `self.nodes = {node["id"]: node}` — **dict by id**
  - `self.outgoing` / `self.incoming` — **adjacency lists** keyed by `edge["source"]` / `edge["target"]` (the core seam Kùzu replaces)
  - secondary: `by_kind`, `by_label`, `by_file`, `by_owner`
  - accessors: `targets(src, *kinds)` (`:74`), `sources(tgt, *kinds)` (`:81`), `outgoing_of_kind`/`incoming_of_kind` (`:88`/`:96`), `nodes_owned_by(owner_id)` (`:51`), `semantic_edge_kind(edge)` (`:55`, unwraps `EXPANDS_TO`→`properties.via`).

### MCP nav server (`nav/mcp_server.py`)
Dispatch: `call_tool` (`:266`). **Two classes of tool:**

- **Single-hop / index lookups** (map directly to indexed Kùzu queries or stay in the ported index):
  `hubs` (`:289`, precomputed fan_in/out over call edges, `nav/hubs.py:66`), `search` (`:293`, name index over `store.entries`), `callers`/`callees` (`:297`, `index.sources/targets` + one INDIRECT hop), `read_body` (`:305`, single node fetch + `gl.source_text`/`gl.body_nodes` by offset), `open_file`/`open_folder`, `points_to` (`:348`, 1 hop), `aliases` (`:357`, fixed 2 hops value→heap→sibling), `guards`/`call_roles`/`siblings`.

- **Multi-hop traversal — DO NOT Cypher-ify** (`nav/reachability.py`, class `Reachability` `:64`):
  `flow` (`:331`), `reaches` (`:337`), `sources_of` (`:342`). Driven by `_walk` (`:114`) over an adjacency `_build` (`:76`) filtered to `FLOW_EDGE_KINDS = {VALUE_FLOWS_TO, POINTS_TO}` + synthesized reverse alias-via-heap edges. **This BFS is context-sensitive** (push/pop `context-parameter`/`context-return` context-ids, `:137-144`) and does **alias-via-heap bridging** (`:98-104`). A fixed-length Cypher pattern will not reproduce the context-balancing — **keep the algorithm in Python** (§4).

### Id scheme (the incremental enabler)
- Content-hash ids, generated **in the frontends**, passed through unchanged.
- `Lachesis/core/identities.py:18` `stable_id(owner, namespace, kind, *parts)` → `sha256("v2\0{owner}\0{namespace}\0{kind}\0{parts}")[:20]`, formatted `v2:{owner}:{namespace}:{kind}:{digest}`. Parts = **file path + start/end offsets + name** (C: `frontends/c/build_graph.py:662`; TS: `frontends/typescript/build_graph.mjs:97`). Per-file `content_hash` stamped into props.
- **Consequence:** a node's id is stable iff its content is unchanged → re-ingesting a changed file yields new ids only for changed nodes, identical ids for unchanged ones. This is what makes incremental re-ingest tractable.
- Base-graph edges have **no id**; identity is the `(kind, source, target, props)` tuple.

### Existing re-ingestable unit
- No cross-run composed-graph cache. But each frontend already writes a **layered bundle** (`manifest.json` + per-tier JSON) via `write_layered_graph` (`Lachesis/projections/layered.py:668`), re-loaded independently by `load_snapshot` (`Lachesis/core/snapshot.py:23`). `semantic_snapshot_graph` (`pipeline.py:174`) re-enriches a single snapshot. **This per-frontend/per-package bundle is the coarse incremental unit that exists today.**

---

## 2. Kùzu schema

**Not** one-table-per-kind (65 node kinds × 90 edge kinds = brittle, and rel tables would need FROM/TO pair enumeration). Instead: **one generic `Node` table + hot typed rel tables + one catch-all rel table.** This gives fast typed traversal on the dataflow moat while staying evolvable as frontends add kinds.

### Node table
Promote only the columns the nav tools actually read; everything else rides in a JSON `props` blob.

```cypher
CREATE NODE TABLE Node(
  id                STRING,       -- v2:...:<hash>  (dictionary-encoded PK)
  kind              STRING,       -- 65 kinds; drives by_kind
  label             STRING,       -- search / display
  symbol_name       STRING,       -- search / name resolution
  file              STRING,       -- rel path (by_file, = incremental unit key, see `unit`)
  absolute_file     STRING,       -- read_body opens this
  start_line        INT32,
  end_line          INT32,
  start_offset      INT64,        -- read_body slices source by offset
  end_offset        INT64,
  owner_function_id STRING,       -- by_owner / body_nodes
  type              STRING,
  package_name      STRING,
  content_hash      STRING,       -- per-file hash (incremental skip check)
  unit              STRING,       -- = source file rel path; ALL nodes from parsing that file share it
  props             STRING,       -- JSON: the cold long-tail props (token_kind, type_facts, roles, …)
  PRIMARY KEY (id)
);
```
Index `kind`, `file`, `owner_function_id`, `symbol_name`, `unit` (Kùzu builds a PK index automatically; add secondary indexes for these where supported, else keep the small `by_*` maps materialized at load).

### Hot rel tables (traversal-critical — one per kind, `FROM Node TO Node`)
These are the edges the multi-hop + call tools traverse; typed tables = columnar, index-backed, no `kind` filter on the hot path:

```cypher
CREATE REL TABLE VALUE_FLOWS_TO (FROM Node TO Node, context_id STRING, position INT32, operator STRING, reason STRING);
CREATE REL TABLE POINTS_TO      (FROM Node TO Node, relationship STRING, abstract BOOLEAN);
CREATE REL TABLE TAINT_FLOWS_TO (FROM Node TO Node, context_id STRING, transition STRING);
CREATE REL TABLE ALIASES        (FROM Node TO Node);
CREATE REL TABLE ALIASES_VALUE  (FROM Node TO Node, definition_id STRING);
CREATE REL TABLE CALLS          (FROM Node TO Node, callsite STRING);
CREATE REL TABLE MAY_INVOKE     (FROM Node TO Node, argument_id STRING, reason STRING);
CREATE REL TABLE INVOKES        (FROM Node TO Node, resolution STRING);
CREATE REL TABLE READS_FROM     (FROM Node TO Node);
CREATE REL TABLE WRITES_TO      (FROM Node TO Node);
CREATE REL TABLE DEFINES        (FROM Node TO Node);
CREATE REL TABLE REFERS_TO      (FROM Node TO Node);
```
(Selection rationale: `VALUE_FLOWS_TO`/`POINTS_TO` = the `Reachability` flow subgraph; `CALLS`/`MAY_INVOKE`/`INVOKES` = `callers`/`callees`/`hubs`; `READS_FROM`/`WRITES_TO`/`DEFINES`/`REFERS_TO` = symbol resolution; `TAINT_FLOWS_TO`/`ALIASES*` = security tier. `context_id` is carried as an **edge property** — the BFS context machinery needs no separate table.)

### Catch-all rel table (the ~75 cold edge kinds)
```cypher
CREATE REL TABLE EDGE (FROM Node TO Node, kind STRING, props STRING);
```
`AST_CHILD`, `NEXT_TOKEN`, `EXPANDS_TO`, CFG edges, structural/type edges, etc. Queried with a `kind` filter only when a tool needs them; they're not on any multi-hop hot path.

> **Fallback if the hybrid is too much surface for v1:** a single `EDGE(kind, props)` table for *everything* + a secondary index on `kind`. Simpler port, but the dataflow multi-hop (the moat) pays a `kind`-filter per hop. Start hybrid; the ~12 hot tables are cheap and it's the differentiated path.

### Store manifest (`lachesis-manifest.json`, beside `graph.kuzu`)

Not a table — a small JSON file the writer emits with the store. It carries the
per-frontend inventory (`frontend_id`, `languages`, `capabilities`, counts), the store's
own `node_count`/`edge_count`, and two fields that make deferred enrichment possible:

- `enriched` — whether the store holds the overlay dataflow tier or only the core tier.
- `core_content_hash` — a digest over sorted node ids and `(kind, source, target)`
  triples of what was actually stored. A core-only store stamps its own; the derived
  `<store>.enriched` cache stamps the hash of the core it was built from, and a load
  serves that cache only when the two agree.

It also carries `version`, the on-disk format. **v2** stores the full properties dict in
every `props` blob, so the promoted typed columns are duplicates the reader never touches.
**v3** stores only the tail in `props` and has the reader union the promoted columns back
in. A v3 reader reads a v2 store correctly, because the tail is a superset and wins on
merge; a v2 reader reads a v3 store *quietly wrong*, losing the promoted keys from every
node. Detecting that is the only reason the stamp exists. The `<store>.enriched` cache
needs no invalidation across the bump: `core_content_hash` covers ids and edge triples and
deliberately excludes properties, and an old-format cache read by the new reader
reconstructs correctly by the same tail-wins rule.

The languages and capabilities in the inventory are exactly the two inputs overlay
enrichment needs beyond the graph itself, which is why the tier can be rebuilt from a
core-only store with no re-compile.

---

## 3. Ingest / write path

Add a new writer alongside the JSON one — **dual-write during migration**, don't delete `write_project_graph`. *(Historical: the migration is complete and `write_project_graph` has since been deleted; `write_kuzu_graph` is the only writer.)*

- **New:** `Lachesis/kuzu_store.py` : `write_kuzu_graph(graph, snapshots, db_dir)`.
  - Consumes the **same composed `graph` dict** that `write_project_graph` gets (post `_enrich_graph`), so it slots in at `Lachesis/cli/analyze.py:25` behind a flag / second output path.
  - **Ingest-time prune (Lever A), gated by a flag so parity tests can disable it:**
    - drop nodes where `kind ∈ {token, source-span}`;
    - drop edges with a dropped endpoint (auto-kills `HAS_TOKEN` 171K + `NEXT_TOKEN` 171K + token-targeted `EXPANDS_TO`/`AST_CHILD`);
    - *optional, configurable:* drop `kind == diagnostic` and test-file nodes (regex on `file`) — keep configurable, tests are noise for the security engine but may matter elsewhere.
  - **Don't materialize constant props:** never store `fact_origin` (always `"compiler"`); store `confidence` only when `!= "exact"`; drop empty `evidence_ids`. Everything not promoted to a column → `props` JSON.
  - **Set `unit`** on every node/edge = the emitting source file (`properties.file`). This is the incremental key (§5).
  - Bulk load via Kùzu **`COPY FROM` staged Parquet** (one typed columnar file per table; endpoint PKs first, then props in table order). This is the perf-critical path: the initial per-row `conn.execute` loader measured **~9.4 min/package** (too slow for whole-repo); the `COPY FROM` rewrite is **~24× faster** (measured). Route each edge to its hot rel table by `kind`, else to `EDGE`.

Acceptance for this step: the reference graph writes a Kùzu DB dir; **measured DB size = 433 MB (−49% vs 879 MB JSON)** — *not* the earlier ≤~250 MB target, which was too optimistic (the JSON-string props column + page overhead dominate; see §0 correction). Disk is a secondary benefit — the acceptance that matters is the **RAM ceiling removed** (385 MB RSS / 1.6 s open). Node/edge counts match the pruned expectation (246,633 / 495,622).

---

## 4. Query path (the careful part)

**Principle: swap the storage, keep the algorithms.** Do not port `Reachability` to Cypher.

- **New:** `KuzuGraphIndex` implementing the **exact accessor surface** of `GraphIndex` (`Lachesis/core/query.py`): `nodes[id]`, `targets(src,*kinds)`, `sources(tgt,*kinds)`, `outgoing_of_kind`, `incoming_of_kind`, `nodes_owned_by`, `by_kind`/`by_label`/`by_file`/`by_owner`, `semantic_edge_kind`. Backed by Kùzu queries, with:
  - node fetch by id → PK lookup;
  - `targets/sources` of given kinds → hot-rel-table query (or `EDGE WHERE kind IN …` for cold);
  - the small secondary maps (`by_kind` etc.) can be materialized once at load from cheap aggregate queries — they're index-shaped, not the whole graph.
- `GraphStore.load` (`nav/graph_store.py:90`) gains a branch: **if `graph_path` is a Kùzu DB dir → build `KuzuGraphIndex`; else the existing JSON path.** `GraphStore`/`GraphLib`'s public surface is unchanged, so `mcp_server.py` and every tool are untouched.
- **`Reachability` stays byte-for-byte.** Its `_build` (`nav/reachability.py:76`) pulls the `FLOW_EDGE_KINDS` adjacency once — back that single build with **one Kùzu query** returning all `VALUE_FLOWS_TO` + `POINTS_TO` edges (`source, target, context_id`) into the existing in-memory adjacency dicts. The context-sensitive `_walk`, push/pop, and alias-via-heap bridging then run **exactly as today** over that adjacency. The flow subgraph is small (~105K edges on the reference graph), so materializing it on demand is cheap and preserves behavior precisely. Kùzu removes the RAM ceiling for the *full* node/edge set; the BFS only ever holds the flow slice.

This is the whole reason the port is safe: the expensive-but-correct traversal logic never touches Cypher; only the bulk store and the single-hop index lookups move.

---

## 5. Incremental update

**Goal:** re-analyze a changed file in seconds instead of rebuilding the whole graph — this is what turns the engine from point-in-time into **continuous**, so it can re-analyze on every commit or PR instead of on demand.

**Unit key:** `unit` column = source file rel path. All nodes/edges from parsing file F carry `unit = F`.

**Skip check:** maintain a `unit → content_hash` manifest (content_hash already stamped per file). On a run, re-ingest only units whose hash changed.

**Per-unit swap (single Kùzu transaction so queries never see a half state):**
```
BEGIN;
  MATCH (n:Node {unit:$F}) DETACH DELETE n;   -- drops F's nodes + all their edges
  -- COPY/MERGE freshly-ingested nodes for F, then its edges (routed to hot/EDGE tables)
COMMIT;
```

**Cross-file edge correctness — the one subtlety, call it out:**
An edge F→G (e.g. `CALLS` into a symbol defined in G) is emitted while parsing F, so `unit=F` and it's re-created on F's re-ingest. The risk is **incoming** edges: an unchanged file H holding an edge into one of F's nodes. Because ids are content-hashed, an unchanged declaration in F **keeps its id**, so H's edge still resolves. It only dangles if the *specific referenced node* in F changed identity.
- **v1 (safe, coarse):** incremental unit = **package** (reuse the existing per-frontend layered bundle, §1). Re-ingest the whole package; cross-file edges within it re-resolve together. Ship this first.
- **v2 (finer):** incremental unit = **changed file + its direct importers** (walk `DEPENDS_ON`/`EXPORTS`/`RE_EXPORTS` neighbors) re-ingested as one transaction, so cross-file references re-resolve. Add after v1 parity holds.
- After any incremental swap, run a **dangling-edge sweep** (`MATCH ()-[r]->() WHERE the endpoint id is absent`) as a cheap invariant check — mirrors what `combine_graphs` enforces today.

**Writer note:** Kùzu is single-writer/embedded — serialize ingest (build-then-serve, or take the write lock for incremental). Fine for this workload.

---

## 6. Rollout — revertible commits (per repo directive: every step auditable)

1. `Lachesis/kuzu_store.py` writer + prune + dual-write behind a flag. JSON writer untouched. **Commit.**
   *(Done — writer uses `COPY FROM` staged Parquet, ~24× faster than the initial per-row loader; also carries the `unit` incremental key on every node/edge.)*
2. `KuzuGraphIndex` + `GraphStore.load` branch. `Reachability` unchanged, flow-subgraph sourced from one Kùzu query. **Commit.**
3. **Parity harness** (`tests/`): run all nav tools (`hubs`/`search`/`callers`/`callees`/`read_body`/`open_file`/`open_folder`/`flow`/`reaches`/`sources_of`/`points_to`/`aliases`) against JSON-backed vs Kùzu-backed store on the reference graph; assert **identical** results (modulo the deliberate Lever-A prune — run parity with prune OFF first, then confirm the pruned graph still answers the nav set). **Commit.**
4. Incremental v1 (per-package unit swap + `unit→content_hash` manifest + dangling sweep). **Commit.**
5. Flip nav default to Kùzu; keep JSON export behind a debug flag. **Commit.**
6. (Later) Incremental v2 (file + importers).

---

## 7. Acceptance criteria / benchmarks

- **Size:** the reference Kùzu DB **measured 433 MB (−49% vs 879 MB JSON)** — disk is a secondary benefit, not the ceiling (the earlier ≤~250 MB target was too optimistic; see §0). Report actual on re-measure.
- **RAM:** nav server opens whole-repo graph without loading it all into memory; RSS bounded well under the old 16 GB ceiling.
- **Load:** open DB + build the small secondary maps in < a few seconds; no 124 s full-JSON parse.
- **Parity:** 100% identical nav results vs JSON on the reference graph for the full tool set (prune-off), and the pruned graph answers the nav set intact (already PoC-verified for hubs/search/callers/callees/read_body).
- **Whole-repo:** the multi-package graph (a several-package scope first, then the full repo) opens and serves without OOM — the thing that's impossible today.
- **Incremental:** re-ingest one changed package in seconds; dangling-edge sweep clean.

---

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Context-sensitive BFS doesn't map to Cypher | **Keep it in Python** over a Kùzu-sourced flow subgraph (§4). Non-negotiable. |
| Cross-file edges dangle after incremental | Content-hash ids preserve unchanged-node identity; ship per-package v1 first; dangling sweep as invariant; file+importers v2. |
| Schema drift as frontends add kinds/props | New props → `props` JSON automatically (promote a column only when a query needs it); new edge kind → catch-all `EDGE` unless promoted to a hot table. |
| Kùzu single-writer | Serialize ingest / take write lock; build-then-serve for full builds. |
| On-disk format stability across Kùzu versions | **Pin the Kùzu version**; treat the DB as a rebuildable artifact (source of truth is the frontends), so a format bump = rebuild, not migrate. |

---

## 9. One-line summary for the build session

Add a Kùzu writer that consumes the same composed graph (pruning `token`/`source-span`, dropping constant props, tagging every node with its source-file `unit`); add a `KuzuGraphIndex` that satisfies the existing `GraphIndex` accessor surface so `GraphStore`/`mcp_server`/all tools are untouched; **keep `Reachability`'s context-sensitive BFS in Python, feeding it the flow subgraph from one Kùzu query**; make incremental a per-`unit` delete+merge in a transaction, package-granular first. Dual-write + parity-test against JSON before flipping the default.
