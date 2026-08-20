# Performance and benchmark history

The north-star workload is the Linux `net` subsystem at
`/Users/riyandhiman/project/linux/net` (or an equivalent checkout on Linux). It is
large enough to exercise the full C graph rather than only a fixture or a small
directory. Benchmarks must use the direct Lachesis package path; do not benchmark the
GitHub Action wrapper as a substitute for the engine.

## Reproducible commands

Use Python 3.11+ and clean output directories. Run the direct package commands below;
do not substitute the GitHub Action wrapper when measuring engine performance.

```bash
cd /path/to/arachne
python3.11 -m pip install -e '.[dev]'
time env LACHESIS_C_JOBS=1 LACHESIS_EMIT_TOKENS=0 LACHESIS_EMIT_PROOFS=0 \
  python3.11 -m lachesis.frontends.c.build_graph \
  /Users/riyandhiman/project/linux/net /tmp/lachesis-bench/frontends

# On a Linux environment with kuzu installed, time the composed/enriched path too:
time python3.11 -m lachesis.cli.analyze \
  /Users/riyandhiman/project/linux/net /tmp/lachesis-bench/net.kuzu \
  --frontend-out /tmp/lachesis-bench/frontends --prune --enrich
```

When memory is the limiting resource during store materialization, add
`LACHESIS_KUZU_LOW_MEMORY=1`. It removes the in-memory property-text compression
arrays and preserves graph facts; the tradeoff is a larger/slightly slower store write.
For a hard Kùzu cache ceiling, set `LACHESIS_KUZU_BUFFER_POOL_SIZE` to a byte count
(for example `1073741824` for 1 GiB). This is especially important in GitHub Action
runners, where automatic pool sizing can otherwise consume the runner before the
graph is published. The explicit `--stream-shards` path defaults to a 1 GiB pool;
set the variable when tuning that bound for a particular runner.

The bounded core-only path uses the same direct package command exposed in README:

```bash
lachesis-analyze /path/to/project /tmp/project.kuzu \
  --stream-shards /tmp/project-shards --prune
```

For a safe first run on a constrained machine, set `LACHESIS_C_JOBS=1`. The command
still builds the complete subsystem; this only makes Clang scheduling predictable.
For a warm incremental measurement, repeat with `--incremental` and the same
`--frontend-out` and record path.

Do not compare a run with different `--prune`, token/proof emission, Python, Clang,
or source revisions. Record those changes alongside the result.

## History

| Date | Revision | Workload | Build s | Enrichment s | Kùzu s | Nodes | Edges | Peak GiB | Notes |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| 2026-08-20 | `d841e61` | Linux `net` | 191* | — | — | 1,833,812 | 3,507,808 | 4.34* | Direct C frontend; full bundle validated. |
| 2026-08-20 | `d841e61` | Linux `fs` | >421* | — | — | — | — | >4.77* | Safety-stopped before completion; next scale boundary. |
| 2026-08-20 | `ad44b90` | Linux `net` CLI + `--enrich` | >160* | — | — | — | — | >5.30* | Frontend child exceeded safety cap before composition; pass 2 not measured. |
| 2026-08-20 | `2c00f9d` | Linux `net` CLI + `--stream-shards` | >541* | — | partial | — | — | ~4.2* | Frontend completed; rowwise Kùzu load did not finish. Stream publication is now atomic. |
| 2026-08-20 | `2db7808` | Linux `net` shard materialization, 1 GiB Kùzu pool | >298* | — | stopped | — | — | ~3.6* | Memory stayed bounded; stopped on host disk exhaustion before manifest publication. Not a valid graph result. |
| 2026-08-20 | `109a3aa` | Linux `net` shard materialization, 1 GiB pool + 256 MiB checkpoints | — | — | 678.7 | 1,822,752 | 3,485,899 | ~4.1* | Completed and reopened; manifest/index counts match the Kùzu tables. Peak is the highest sampled RSS, not a kernel max-RSS reading. |
| 2026-08-20 | `5bd50eb` | Linux `net` shard materialization, coalesced node/edge COPY | — | — | 94.66 | 1,822,752 | 3,485,899 | ~1.6* | Completed and reopened; all manifest/index counts match. One Parquet stream/COPY per table removes per-batch Kùzu overhead. |
| 2026-08-20 | `04a6a5b` | Linux `fs` bundle → language-neutral shard persistence | — | — | 64.98 | 3,157,724 | 6,210,355 | ~3.5* | Existing completed C bundle persisted without record-copy amplification; shard counts match the frontend manifest. |
| 2026-08-20 | `a2404de` | Linux `fs` shard materialization, 2 GiB Kùzu pool | — | — | 171.76 | 3,157,724 | 6,210,355 | ~2.1* | Completed and reopened; manifest/index counts match. The 1 GiB default hit Kùzu buffer exhaustion, so this larger workload needs the documented pool override. |
| 2026-08-20 | `84224eb` | Linux `fs` lazy dataflow enrichment from streamed core | — | >131* | not published | — | — | >5.4* | Overlay/index materialization exceeded the safety RSS ceiling before derived-cache publication; bounded Kùzu serialization did not remove this pre-writer peak. |
| 2026-08-20 | `c9c4512` | Linux `fs` streamed core, partitioned node/edge COPY, 1 GiB pool | — | — | 618.03 | 3,157,724 | 6,210,345 | ~5.5* | Completed and reopened under the previously failing 1 GiB pool; direct relation counts sum exactly to the manifest. Partitioning removed the buffer-pool failure, but the end-to-end build remains slow. |
| 2026-08-20 | `50e5cfd` | Linux `fs` lazy dataflow enrichment, partitioned node/edge cache COPY | — | >300* | not published | — | — | ~5.0* | Hard process-group timeout at 300s; memory stayed bounded, but pass 3 did not publish a cache. Further incremental/targeted enrichment work is required. |
| 2026-08-20 | superseded | Linux `fs` additive dataflow sidecar prototype | — | >300* | not published | — | — | ~3.6* | JSON/marshal prototype; superseded by the protobuf sidecar migration. |
| 2026-08-20 | `16c1cfa` | Linux `fs` core Kùzu materialization, 8 query threads | — | — | 150.66 | 3,157,724 | 6,210,345 | ~3.9* | Read-only materialization completed with exact counts under the 5-minute cap; bounded Kùzu query parallelism is configurable via `LACHESIS_KUZU_QUERY_THREADS`. |
| 2026-08-20 | `ff8ea37` | Linux `fs` Action-style ephemeral `security-paths` query | — | >300* | no cache | — | — | ~4.3* | The Action no longer writes a graph-sized enriched sibling on this path, but whole-graph materialization/enrichment still exceeded the 300s cap. Next target is scoped security extraction. |
| 2026-08-20 | `e966f98` | Linux `fs/ext4` incremental cold → warm | 17.42 → 7.88 | — | included | 131,635 | 286,007 | not sampled | Warm reuse skipped the frontend subprocess; remaining time is graph composition/Kùzu write. Proof-emission settings are now part of the reuse key. |
| 2026-08-20 | `e966f98` | Linux `fs/ext4` incremental store-artifact reuse | 17.17 → 1.96 | — | skipped | 131,635 | 286,007 | not sampled | Matching frontend fingerprint, prune, and enrichment settings reused the existing Kùzu store and skipped the rewrite entirely. |
| 2026-08-20 | `0fc41c5` | Linux `fs/netfs` streamed core after C path/macro caching | — | — | 2.64 | 13,185 | 24,719 | ~0.36* | 27 files / 10,293 LOC; tokens and proof leaves disabled, `LACHESIS_C_JOBS=1`; graph reopened with matching manifest counts. |
| 2026-08-20 | `0fc41c5` | Linux `drivers/usb` streamed core after C path/macro caching | — | — | 131.47 | 858,016 | 1,694,180 | ~3.99* | 790 files / 582,731 LOC; tokens and proof leaves disabled, `LACHESIS_C_JOBS=1`; completed and reopened with matching manifest counts under the 300s cap. |
| 2026-08-20 | working tree | TypeScript fixture typed protobuf tiers | 0.71 | — | — | 2,677 | 4,539 | — | 3.63 MiB of `.pb` tiers + manifest; 3.5% smaller than compact JSON-equivalent. |
| 2026-08-21 | working tree | TypeScript fixture streamed protobuf tier writer | 0.53 | — | — | 2,677 | 4,539 | ~0.24* | Fresh output directory; 3.5 MiB bundle, writes framed tier records in bounded 1 MiB batches instead of constructing a full outer tier buffer; snapshot parity exact. |
| 2026-08-20 | working tree | Python fixture typed protobuf tiers | 0.19 | — | — | 2,182 | 2,968 | — | 2.40 MiB of `.pb` tiers + manifest; 3.9% smaller than compact JSON-equivalent. |
| 2026-08-20 | `8240bd9` | Linux `fs/netfs` C frontend typed protobuf tiers | 2.20 | — | — | 13,185 | 24,719 | ~0.17* | 27 files / 10,293 LOC; tokens/proofs disabled, `LACHESIS_C_JOBS=1`; 15 MiB bundle, direct frontend command, cold output directory. |
| 2026-08-21 | working tree | Linux `fs/netfs` C frontend in-place default emission | 1.94 | — | — | 13,185 | 24,719 | ~0.09* | 27 files / 10,293 LOC; fresh direct frontend output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; exact snapshot parity, avoids a second per-record dict/property copy during protobuf flush. |
| 2026-08-20 | `8240bd9` | Linux `drivers/usb` full CLI + typed protobuf tiers | >195* | — | — | — | — | ~4.3* | 790 files / 582,731 LOC; pass 1 remained in C frontend serialization and was stopped before publication under the 240s safety cap. This is a regression boundary versus the prior 131.47s streamed-core record; do not treat it as a valid graph result. |
| 2026-08-20 | working tree | Linux `drivers/usb` direct C pass 1, incremental typed protobuf tiers | 101.46 | — | — | 858,016 | 1,694,180 | ~3.09* | 790 files / 582,731 LOC; tokens/proofs disabled, `LACHESIS_C_JOBS=1`; cold direct frontend output completed and was cleaned after measurement. |
| 2026-08-21 | working tree | Linux `drivers/usb` direct C pass 1 after bounded emission | 98.57 | — | — | 858,016 | 1,693,995 | ~2.08* | 790 files / 582,731 LOC; fresh output, tokens/proofs disabled, automatic large-tree jobs=1; `/usr/bin/time -l` peak 2,231,894,016 bytes. Manifest counts were emitted successfully; full Kùzu publication was not run in this row. |
| 2026-08-20 | `fe20eb8` | Linux `fs/netfs` direct CLI streamed core, typed protobuf tiers | 2.00 | — | 8.34 | 13,185 | 24,719 | ~0.54* | 27 files / 10,293 LOC; end-to-end 10.34s / 550 MiB max RSS, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; pass 2 is total minus the direct frontend measurement and includes shard/Kùzu publication. |
| 2026-08-20 | working tree | Linux `fs/netfs` CLI with bundle-to-shard streaming | 2.00 | — | 8.83 | 13,185 | 24,719 | ~0.38* | Cold output directory; end-to-end 10.83s / 377 MiB max RSS. Frontend protobuf tiers are parsed in bounded chunks and persisted directly to shards, avoiding a second full snapshot copy. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI raw protobuf bundle-to-shard handoff | 2.00 | — | 1.78 | 13,185 | 24,719 | ~0.39* | Cold output directory; end-to-end 3.78s / 387 MiB max RSS. Raw NodeRecord/EdgeRecord bytes are retagged and framed without dict decode/re-encode. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI header-only shard membership scan | 2.00 | — | 1.69 | 13,185 | 24,719 | ~0.38* | Cold output directory; end-to-end 3.69s / 377 MiB max RSS. First shard scan decodes only id/kind/file/compiler-id fields; full properties are decoded once for Kùzu load. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI fused Kùzu index scan | 2.00 | — | 1.57 | 13,185 | 24,719 | ~0.38* | Cold output directory; end-to-end 3.57s / 376 MiB max RSS. Declaration and call-site index candidates are decoded in one bounded protobuf pass; graph counts match the prior row. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI header-only edge scan | 2.00 | — | 1.06 | 13,185 | 24,719 | ~0.37* | Cold output directory; end-to-end 3.43s / 373 MiB max RSS. The first membership/export scan skips recursive edge-property decoding; full edge properties are still decoded once for Kùzu load, with exact store counts. |
| 2026-08-21 | working tree | Linux `drivers/usb` CLI with prune defaults + bundle-to-shard streaming | >180* | — | stopped | — | — | ~3.11* | 790 files / 582,731 LOC; C pass completed, but Kùzu publication did not finish before the 180s safety cap. The exact temp graph/shards were removed; no graph result is claimed. |

`*` The first full-subsystem measurement was run with token and proof emission disabled
and `LACHESIS_C_JOBS=1`; it predates this harness, so pass-level timings should be
replaced by a fresh JSON record before using it as a regression baseline.

The `fs` result is intentionally retained as a failure boundary. A large-codebase
optimization must move that row from “stopped” to a validated node/edge count; a
smaller successful subsystem is not considered a substitute.

The Linux `fs` cold-start source scan used for the current north-star measurement
contains **2,185 C/C++/header files and 1,634,709 source lines** (about 50 MB). Its
source-to-core run completed in 618.03s; the 64.98s shard-persistence and 150.66s
Kùzu-materialization figures are warm/component measurements and must not be presented
as cold-start user experience.

The C frontend now defaults to one Clang AST at a time for trees with at least 128
source roots, preventing multiple expanded-header JSON trees from multiplying peak
RSS. `LACHESIS_C_JOBS` remains an explicit override; no large-tree timing claim is
attached to this guard until a complete cold run publishes matching graph counts.

The CLI/enrichment row is also a boundary, not a timing result: the frontend process
must finish before composition and enrichment can begin. It is kept to prevent a
misleading claim that pass 2 has been optimized when pass 1 has not yet completed on
the larger end-to-end path.

The internal additive dataflow cache is a versioned, core-content-hash-keyed protobuf
sidecar (`<store>.dataflow.pb`). JSON remains reserved for user-facing output; it is
not used for this internal cache.

The protobuf migration now covers graph shards, C tiers, TypeScript tiers, and Python
tiers. Typed tier records avoid repeating record field names. On the current fixtures,
the TypeScript and Python tier bundles are 3.5% and 3.9% smaller than compact JSON
equivalents. A 100k-record local microbenchmark showed typed protobuf payloads 12–28% smaller than marshal, but Python
protobuf encode/decode was slower (roughly 5–10× encode and 1.3–4.5× decode for the
sample records). This makes the storage win real, while leaving the hot producer/reader
loops as candidates for a Rust/C++ implementation once the schema is stable.

### Internal wire-format decision

The shard record contract and on-disk encoding are now versioned length-framed protobuf.
Generated bindings are checked in for the Python engine; other frontends can consume the
`.proto` contract without depending on Python internals.

### Rejected scheduling experiment

On Linux `fs/ext4` (51 files, 69,304 LOC), raising `LACHESIS_C_JOBS` from 1 to 4
reduced the frontend wall time from 11.85s to 9.51s, but changed the graph: edges
went from 286,007 to 286,015, with a 317/325 edge-set differential. The faster setting
is therefore not accepted as a default; deterministic fact preservation takes priority.

### Rejected shard-reader experiment

An `mmap` reader was benchmarked on a 400k-record shard stream (200k nodes and
199,999 edges). It was about 19% slower than the existing buffered `read()` loop
(0.225s versus 0.189s in the local run), so it was reverted in `eb249b8`. The current
length-framed marshal format remains the faster measured implementation.

### C frontend path-resolution reduction

The C macro/dependency passes now memoize repeated preprocessor marker and dependency
paths (`3ad17ad`). On the 4-file C fixture, the cProfile count of `Path.resolve()` calls
dropped from 2,167 to 319; the emitted graph remained 442 nodes and 784 edges. This
is a CPU/syscall reduction, not a large-codebase timing claim; the Linux `fs` run still
needs a fresh bounded measurement before its pass-1 row can change.

Macro recovery also streams preprocessor lines (`0fc41c5`) instead of creating a
temporary `splitlines()` list, reducing transient memory without changing the fixture
graph.

## Regression rules

An optimization is not accepted on speed alone. Compare node/edge counts and validate
the resulting bundle. A meaningful regression is either:

1. changed graph counts or failed snapshot validation;
2. increased peak RSS that makes the north-star workload unsafe; or
3. increased any pass time by more than 10% without a documented precision or coverage
   improvement.

The GitHub Action can benefit from these engine improvements, but its cache-hit and
cache-miss timings must be recorded separately in the action repository.
