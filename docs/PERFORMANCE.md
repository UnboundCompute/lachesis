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

For TypeScript monorepos whose largest package exceeds the Node heap, use the bounded
package-sharded streaming form. It serializes compiler jobs, writes each completed
bundle to protobuf shards, and releases its snapshot before starting the next job:

```bash
LACHESIS_TS_MAX_OLD_SPACE_MB=4096 \
  lachesis-analyze /path/to/monorepo /tmp/project.kuzu \
  --parallel-packages --shard-large-packages 100 \
  --stream-shards /tmp/project-shards --prune
```

This bounds live compiler memory but changes package/type-resolution boundaries; use
whole-program mode when it fits and record the shard size with the benchmark.
The streaming writer applies the same ownership rule as the non-streaming package
merge: imported workspace views are discarded in the importing shard, while one
deterministic copy of external library/synthetic nodes is retained. This prevents
duplicate Kùzu primary keys without holding a package-sized winner map.

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
| 2026-08-21 | `67f91a3` | Linux `fs/netfs` C frontend after dedup-index release | 1.94 | — | — | 13,185 | 24,719 | ~0.07* | 27 files / 10,293 LOC; fresh direct frontend output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak 70,304,272 bytes. The edge dedup table is released before tier serialization; counts remain unchanged. |
| 2026-08-21 | `04623ab` | Linux `fs/netfs` C frontend after one-pass tier partition | 1.92 | — | — | 13,185 | 24,719 | not sampled | 27 files / 10,293 LOC; fresh direct frontend output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; node/edge counts match the prior row after replacing five full tier scans with one partition. |
| 2026-08-21 | working tree | Linux `fs/netfs` C frontend streaming tier emission | 1.91 | — | — | 13,185 | 24,719 | ~0.063* | 27 files / 10,293 LOC; fresh direct frontend output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; records are sorted by compact references and encoded one at a time, reducing sampled peak RSS to 66,142,208 bytes. |
| 2026-08-20 | `8240bd9` | Linux `drivers/usb` full CLI + typed protobuf tiers | >195* | — | — | — | — | ~4.3* | 790 files / 582,731 LOC; pass 1 remained in C frontend serialization and was stopped before publication under the 240s safety cap. This is a regression boundary versus the prior 131.47s streamed-core record; do not treat it as a valid graph result. |
| 2026-08-20 | working tree | Linux `drivers/usb` direct C pass 1, incremental typed protobuf tiers | 101.46 | — | — | 858,016 | 1,694,180 | ~3.09* | 790 files / 582,731 LOC; tokens/proofs disabled, `LACHESIS_C_JOBS=1`; cold direct frontend output completed and was cleaned after measurement. |
| 2026-08-21 | working tree | Linux `drivers/usb` direct C pass 1 after bounded emission | 98.57 | — | — | 858,016 | 1,693,995 | ~2.08* | 790 files / 582,731 LOC; fresh output, tokens/proofs disabled, automatic large-tree jobs=1; `/usr/bin/time -l` peak 2,231,894,016 bytes. Manifest counts were emitted successfully; full Kùzu publication was not run in this row. |
| 2026-08-21 | working tree | Linux `drivers/usb` cold streamed core-only CLI | 185.10 | — | 57.71 | 858,016 | 1,693,850 | ~2.25* | 790 files / 582,731 LOC; direct CLI, fresh output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`, 1 GiB Kùzu pool. Kùzu phases: 7.654s scan, 24.174s nodes, 24.662s edges, 1.129s indexes; manifest and node-count reopen matched. Peak RSS 2,421,063,680 bytes. Prune retained 1,693,850 of the frontend's 1,693,995 edges. |
| 2026-08-21 | working tree | Linux `drivers/usb` direct C pass 1, streaming tier emission | 93.85 | — | — | 858,016 | 1,693,921 | ~1.85* | 790 files / 582,731 LOC; fresh direct frontend output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 1,984,430,080 bytes. The Linux checkout had unrelated modified files, so edge count is not used as a clean-tree parity claim. |
| 2026-08-21 | working tree | Linux `drivers/usb` cold streamed core + Kùzu, disposable Python 3.11 env | 186.00 | — | 186.00 included | 858,016 | 1,693,808 | ~1.86* | 790 files / 582,731 LOC; direct CLI, 1 GiB Kùzu pool, tokens/proofs disabled. Store published/reopened with `streamed=true`, `enriched=false`; peak RSS 1,997,045,760 bytes. Linux checkout had unrelated modifications, so edge count is not clean-tree parity evidence. |
| 2026-08-21 | working tree | Linux `net/ipv4` direct C pass 1 | 15.75 | — | — | 164,437 | 313,693 | ~0.39* | 130 C/header files / ~114k LOC; cold direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 422,166,528 bytes. Linux checkout was dirty, so counts are a scale-boundary measurement. |
| 2026-08-21 | working tree | Linux `net/ipv4` cold streamed core + Kùzu | 37.81 | — | 10.48 | 164,437 | 313,693 | not sampled | 130 C/header files / ~114k LOC; disposable Python 3.11/Kùzu env, 1 GiB pool, tokens/proofs disabled. Kùzu phases: 1.467s scan, 4.695s nodes, 3.959s edges, 0.238s indexes; store publication completed under the 120s cap. |
| 2026-08-21 | working tree | Linux `net/ipv4` lazy pass-3 overview/enrichment | 27.33 | 8.05 enrichment | — | 164,437 | 313,696 | ~1.91* | 130 C/header files / ~114k LOC; ephemeral query over the streamed store. Core materialization took 5.407s; overlay fold 8.052s; peak RSS 1,908,375,552 bytes. Overlay deltas were recorded per registry; no graph writes were retained. |
| 2026-08-21 | working tree | Linux `fs/ext4` direct C pass 1 | 14.80 | — | — | 131,635 | 286,007 | ~0.54* | 51 C files; fresh direct frontend output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 574,504,960 bytes. This is a bounded complex-filesystem scale point below the USB/net north star. |
| 2026-08-21 | `78ba14e`/`5b54358` | Pass-3 index microbenchmark | 0.283 → 0.238 | — | — | 120,000 | 180,000 | 244.0 → 235.5 MB* | Synthetic 120k-node/180k-edge graph: compact lazy indexes cut construction time ~16% and sampled RSS ~8.5 MB; layered security now reuses one index instead of rebuilding three additional copies. This is an implementation signal, not a north-star workload result. |
| 2026-08-21 | working tree | Materialized-edge ordering microbenchmark | 0.347 → 0.062 | — | — | — | 180,000 | — | Synthetic unique-edge-heavy stream: grouped sorting preserves exact encoded-property tie ordering while avoiding property serialization for unique triples (~5.6× sort speedup). Real-store validation is recorded in the following row. |
| 2026-08-21 | `bc60917` | Linux `fs/netfs` cold streamed core + Kùzu after grouped materialization sort | 3.54 | — | 1.13 | 13,185 | 24,719 | ~0.37* | Fresh Python 3.11 disposable env, 1 GiB pool, tokens/proofs disabled; store published and reopened. Standalone whole-store materialization was 0.258s with exact node/edge counts. `/usr/bin/time -l` peak RSS 398,721,024 bytes. This is a bounded validation, not a claim of north-star regression/improvement from the earlier 3.57s row. |
| 2026-08-21 | working tree | Kùzu property-tail cache microbenchmark + netfs reopen | 0.373 → 0.177* | — | 1.04 | 13,185 | 24,725 | — | Bounded 4,096-entry cache cuts a repeated 100k-edge tail batch ~2.1× (unique tails remain ~0.50s); short-tail bytes only, so memory cannot grow with graph size. Fresh Python 3.11/Kùzu run reopened with exact manifest/materialized counts; Linux checkout was dirty, explaining the edge-count difference from earlier rows. Kùzu phases: 1.039s total, edge load 0.336s. |
| 2026-08-21 | working tree | Linux `net` cold streamed core-only CLI | >300* | — | >17* | — | — | >3.0* | 1,738 C/header files / 1,292,818 LOC; direct CLI, tokens/proofs disabled, `LACHESIS_C_JOBS=1`, 1 GiB Kùzu pool. Pass 1 reached publication, but the run was safety-stopped before Kùzu finished (header scan 17.089s, schema 0.090s); no manifest or graph result is claimed. Partial output was removed. |
| 2026-08-21 | working tree | nginx 1.31.3 cold streamed core-only CLI | 197.28 | — | 38.00 | 585,243 | 1,189,617 | ~1.55* | 403 C/header files / 250,780 LOC; direct CLI, tokens/proofs disabled, `LACHESIS_C_JOBS=1`, 1 GiB Kùzu pool. Kùzu phases: 5.192s scan, 16.010s nodes, 16.151s edges, 0.531s indexes; manifest and node-count reopen matched. Peak RSS 1,664,499,712 bytes. |
| 2026-08-21 | working tree | n8n whole-repo TypeScript frontend, 4 GiB Node heap | >26.12* | — | — | — | — | >4.16* | 19,138 TypeScript/JavaScript files / 506,031 LOC; direct frontend, first-party dependency types only. V8 OOMed before bundle output at 4,470,030,336-byte RSS; no graph result is claimed. |
| 2026-08-21 | working tree | n8n `packages/nodes-base` TypeScript frontend after compact edge dedup | >29.48* | — | — | — | — | >4.13* | 4,609 TypeScript/JavaScript files; direct frontend, 4 GiB Node heap. V8 still OOMed before output at 4,434,984,960-byte RSS, showing compiler-program/AST retention dominates the frontend heap rather than edge-key storage. |
| 2026-08-21 | `28eafc8` | TypeScript workspace package-sharded streaming smoke test | 0.9 | — | — | 401 | 657 | — | Two package units, one root per shard; protobuf readers matched the emitted records without composing snapshots. Large n8n validation is intentionally pending a capped run. |
| 2026-08-21 | `428e0cd` | TypeScript workspace sharded-stream parity audit | 1.4 | — | — | 392 | 647 | — | One-root chunks had zero duplicate node IDs; node IDs and edge triples exactly matched the existing serial package-partition reference. Imported workspace views were filtered by ownership. |
| 2026-08-21 | working tree | n8n `packages/nodes-base` 100-root streaming subset | 6.9 | — | — | 41,917 | 70,480 | not sampled | Direct TypeScript compiler, fresh protobuf shard output, one bounded shard; snapshot released and all 41,917 node IDs were unique. This validates the production handoff without claiming a full n8n graph. |
| 2026-08-20 | `fe20eb8` | Linux `fs/netfs` direct CLI streamed core, typed protobuf tiers | 2.00 | — | 8.34 | 13,185 | 24,719 | ~0.54* | 27 files / 10,293 LOC; end-to-end 10.34s / 550 MiB max RSS, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; pass 2 is total minus the direct frontend measurement and includes shard/Kùzu publication. |
| 2026-08-20 | working tree | Linux `fs/netfs` CLI with bundle-to-shard streaming | 2.00 | — | 8.83 | 13,185 | 24,719 | ~0.38* | Cold output directory; end-to-end 10.83s / 377 MiB max RSS. Frontend protobuf tiers are parsed in bounded chunks and persisted directly to shards, avoiding a second full snapshot copy. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI raw protobuf bundle-to-shard handoff | 2.00 | — | 1.78 | 13,185 | 24,719 | ~0.39* | Cold output directory; end-to-end 3.78s / 387 MiB max RSS. Raw NodeRecord/EdgeRecord bytes are retagged and framed without dict decode/re-encode. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI header-only shard membership scan | 2.00 | — | 1.69 | 13,185 | 24,719 | ~0.38* | Cold output directory; end-to-end 3.69s / 377 MiB max RSS. First shard scan decodes only id/kind/file/compiler-id fields; full properties are decoded once for Kùzu load. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI fused Kùzu index scan | 2.00 | — | 1.57 | 13,185 | 24,719 | ~0.38* | Cold output directory; end-to-end 3.57s / 376 MiB max RSS. Declaration and call-site index candidates are decoded in one bounded protobuf pass; graph counts match the prior row. |
| 2026-08-21 | working tree | Linux `fs/netfs` CLI header-only edge scan | 2.00 | — | 1.06 | 13,185 | 24,719 | ~0.37* | Cold output directory; end-to-end 3.43s / 373 MiB max RSS. The first membership/export scan skips recursive edge-property decoding; full edge properties are still decoded once for Kùzu load, with exact store counts. |
| 2026-08-21 | working tree | Linux `fs/netfs` streamed Kùzu with experimental 25k-row batches | 6.11 | — | 1.15 | 13,185 | 24,719 | not sampled | Fresh disposable Python 3.11/Kùzu env, 1 GiB pool, tokens/proofs disabled, `LACHESIS_STREAM_BATCH_ROWS=25_000`. Small fixture phases improved from 1.23s to 1.15s, but USB confirmation regressed to 59.67s, so the production default remains the measured 10k. |
| 2026-08-21 | working tree | Linux `fs/netfs` cold streamed core with disposable Python 3.11/Kùzu env | 15.17 | — | included | 13,185 | 24,719 | ~1.69* | 27 files / 10,293 LOC; direct CLI, 1 GiB Kùzu pool, tokens/proofs disabled. Store published and reopened with `streamed=true`, `enriched=false`, and exact manifest counts. Peak RSS 1,810,612,224 bytes. |
| 2026-08-21 | `5cb1071` | GitHub Action build-step simulation, `--prune --incremental` | 6.80 | — | included | 13,185 | 24,719 | ~0.48* | Linux `fs/netfs`; disposable Python 3.11 env, Action-equivalent 1 GiB Kùzu ceiling, direct `lachesis-analyze` invocation. Cold store published with exact counts; peak RSS 510,869,504 bytes. SARIF export was not run in this timing row. |
| 2026-08-21 | `4bffec4` | GitHub Action SARIF export simulation | 12.3 | — | included | 13,185 | 24,719 | not sampled | Linux `fs/netfs`; same disposable compatible env and build flags. SARIF export completed with 0 findings; nested query used the current interpreter rather than host `python3`, fixing mixed-runtime protobuf failures. |
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

### Rejected streaming Clang-JSON experiment

A prototype that spilled Clang's AST JSON to a mmap'd file and scanned root children
one at a time was tested on Linux `drivers/usb`. It produced 857,999 nodes and
1,693,850 edges instead of the reference 858,016 / 1,693,995, took 173.39s versus
about 99s for the direct frontend, and peaked at 2.35 GiB. The prototype was reverted:
the Python byte scanner was both slower and lossy, so it is not an accepted memory
optimization. A future streaming parser must prove byte-for-byte graph parity before
being used on large trees.

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
