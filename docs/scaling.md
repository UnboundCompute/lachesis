# Scaling large builds

Lachesis opens fast and stays cheap on ordinary trees with no tuning. This page is the
operational guide for the cases that need it: very large C subsystems, TypeScript
monorepos that exceed a single compiler heap, and constrained CI runners. For benchmark
history and the reference workload, see [`PERFORMANCE.md`](./PERFORMANCE.md); for the
on-disk layout and compression, see [`KUZU_STORE_SPEC.md`](./KUZU_STORE_SPEC.md) and
[`STORE_COMPRESSION_SPEC.md`](./STORE_COMPRESSION_SPEC.md).

## Why the store stays small

The store is columnar, which is what lets a graph with well over a million nodes open in
under a second on a laptop, holding only a few hundred megabytes of RAM to do it. A
pruned store of a large Python codebase (Django: 1.6M nodes / 2.6M edges) lands around
500 MB on disk, opens fast, and stays cheap to keep resident, because columnar scans read
only the columns a query touches.

Lossless `--prune` drops pure-lexical nodes (source is read from files by offset, not
stored twice), roughly halving the store.

For reproducible large-codebase measurements, use the direct-package commands and record
the results in [`PERFORMANCE.md`](./PERFORMANCE.md). The ledger tracks frontend build,
enrichment, Kùzu materialization, node/edge counts, and peak memory so an optimization
can be checked for both speed and graph completeness.

## The engine-only C build

The main engine-only command is:

```bash
LACHESIS_C_JOBS=1 LACHESIS_EMIT_TOKENS=0 LACHESIS_EMIT_PROOFS=0 \
  python3.11 -m lachesis.frontends.c.build_graph \
  /path/to/large-c-tree /tmp/lachesis-frontends
```

The C frontend keeps small trees parallel, uses two Clang ASTs by default for medium
trees, and limits large trees to one AST at a time so expanded headers cannot multiply
the runner's peak memory. Set `LACHESIS_C_JOBS` explicitly when the runner has a measured
safe capacity (the large Linux benchmark uses `LACHESIS_C_JOBS=1`; the `net/ipv4` medium
boundary measured 13.00s with `LACHESIS_C_JOBS=2`).

## Streaming shards into Kùzu

For a core-only store on a large mixed-language tree, stream frontend shards directly into
Kùzu to keep the parent process from composing one giant graph:

```bash
lachesis build /path/to/project /tmp/project.kuzu \
  --stream-shards /tmp/project-shards --prune
```

For large CI runners, bound Kùzu's cache explicitly so materialization cannot claim the
host's entire available RAM. The value is bytes; 1 GiB is a good starting point for
Linux/net-sized workloads:

```bash
LACHESIS_KUZU_BUFFER_POOL_SIZE=1073741824 \
  lachesis build /path/to/project /tmp/project.kuzu \
  --stream-shards /tmp/project-shards --prune
```

To print the streamed Kùzu phase timings while profiling a cold output directory, add
`LACHESIS_TIMINGS=1`. The timing lines cover header scanning, schema creation, node and
edge COPY, and index loading; they are silent by default:

```bash
LACHESIS_TIMINGS=1 LACHESIS_KUZU_BUFFER_POOL_SIZE=1073741824 \
  lachesis build /path/to/project /tmp/project.kuzu \
  --stream-shards /tmp/project-shards --prune
```

`--stream-shards` is a Pass-1/core-only Kùzu build, but it also emits the immutable binary
inputs required by later passes: `<store>.pass2.input.pb`, `<store>.pass2.facts.pb`, and
`<store>.pass3.substrate.pb`. Run `lachesis enrich <store>` after the build to consume
those sidecars without rerunning the frontends. The native Pass-1 projector accepts all
frontend shard sets together, so cross-language edges survive without a Python graph
reconstruction. Additive Pass-2 records remain in the compact internal
`<store>.dataflow.pb` sidecar; internal graph transport uses protobuf rather than JSON.
A full `.enriched` Kùzu cache remains the fallback for overlays that mutate core records.

The streaming scheduler runs independent C/C++, Python, and TypeScript/JavaScript
frontends concurrently, then releases their snapshots before Kùzu materialization. On
the pruned core libxml2 reference tree this measured 27.66 seconds cold at approximately
1.03 GiB peak RSS with no swap (406,952 nodes / 656,691 edges). Node batches remain at
2,000 rows for bounded RSS while edge batches use 10,000 rows. The previous 28.73-second
run used 2,000-row batches for both node and edge records; the older 38.03-second run used
the older streamed frontend handoff. This is a timing reference, not a cache-warm result; the measurement
is from one cold run and should be compared on the same machine and input.

## TypeScript monorepos

For a TypeScript monorepo whose packages or root lists do not fit in one compiler heap,
combine streaming with the bounded package splitter. Shards are compiled serially so
compiler heaps do not multiply, and each completed bundle is released before the next
starts:

```bash
LACHESIS_TS_MAX_OLD_SPACE_MB=4096 \
  lachesis build /path/to/monorepo /tmp/monorepo.kuzu \
  --parallel-packages --shard-large-packages 100 \
  --stream-shards /tmp/monorepo-shards --prune
```

This is a bounded fallback with an explicit package-resolution tradeoff; whole-program
analysis remains the highest-fidelity mode when it fits.

For a monorepo whose largest package does not fit in one compiler heap, the non-streaming
opt-in package-sharded build bounds each compiler root list (it is a semantic tradeoff, so
the CLI reports cross-shard edges that could not be merged):

```bash
lachesis build /path/to/monorepo /tmp/monorepo.kuzu \
  --parallel-packages --shard-large-packages 1000 --max-workers 1 --prune
```

Start with `--max-workers 1` on memory-constrained CI; increase it only after measuring
the runner's peak RSS. A whole-program TypeScript build remains the highest-fidelity mode
when it fits, while package sharding is the bounded fallback for very large trees.

The GitHub Action's SARIF step sets `LACHESIS_QUERY_EPHEMERAL_ENRICH=1`: its batch security
query uses the derived tier only for that process and avoids writing a second graph-sized
cache. Local query commands keep persistent enriched-cache behavior.

## Managing the local graph cache

The product CLI keeps one content-addressed index per source tree. Inspect it with:

```bash
lachesis cache list
```

To see what can be reclaimed without deleting anything, use the dry-run prune. It targets
entries whose source directory disappeared and entries older than 30 days:

```bash
lachesis cache prune --older-than 30
```

Add `--apply` only when you want those entries removed. To delete one project, pass its
source path to `lachesis cache clear`; deleting the entire cache requires the explicit
confirmation flag `lachesis cache clear --all`.

## Query-thread and buffer-pool tuning

The streamed path defaults to a 1 GiB Kùzu buffer pool. For very large subsystems such as
Linux `fs`, raise it when the runner has room (the tested fs run used 2 GiB):

```bash
LACHESIS_KUZU_BUFFER_POOL_SIZE=2147483648 \
  lachesis build /path/to/linux/fs /tmp/fs.kuzu \
  --stream-shards /tmp/fs-shards --prune --timeout 900
```

Disk-backed query/materialization scans use up to eight Kùzu execution threads by default.
Override this for a constrained runner with `LACHESIS_KUZU_QUERY_THREADS=2` (or another
positive integer); this changes read parallelism, not graph facts.

Use a clean output directory and monitor the process on very large trees. The command
builds the complete C graph directly; the token/proof switches remove only lexical facts
that `--prune` discards later.

## Three-pass resource and equivalence gate

`tools/profile_pipeline.py` runs each production pass in a separate process, applies one
aggregate process-tree RSS limit (5 GiB by default), and records attributable wall time and
peak RSS. It also hashes every published binary boundary so optimization work cannot silently
change the graph, derived facts, semantic graph, or findings:

```bash
python tools/profile_pipeline.py /path/to/source /tmp/project.kuzu \
  --report /tmp/project-profile.json
```

Use an existing Pass-1 store when iterating on Pass 2 or Pass 3:

```bash
python tools/profile_pipeline.py /tmp/project.kuzu --reuse-pass1 \
  --report /tmp/candidate.json --baseline /tmp/baseline.json
```

The baseline comparison is deliberately byte-exact. A failure caused only by record order is
still useful evidence that the producing pass is nondeterministic; stabilize that pass instead
of weakening the equivalence gate. Resource enforcement is a safety net for profiling. Product
passes must stay below the budget through bounded working sets and spill/backpressure rather
than depending on the supervisor to terminate an oversized run.
