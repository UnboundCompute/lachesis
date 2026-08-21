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
For medium C trees that fit the runner's memory budget, `LACHESIS_C_JOBS=2` is an
opt-in throughput setting; the `net/ipv4` boundary measured 13.00s versus 15.52s at
one job with no observed RSS increase. Keep one job for large trees until a local
measurement proves the extra AST concurrency is safe.
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
| 2026-08-21 | `5bcc2c1` | Linux `drivers/usb` streamed core after post-edge map release | 183.24 | — | 59.264 included | 858,016 | 1,693,866 | ~2.02* | 790 files / ~582k LOC; fresh disposable Python 3.11/Kùzu/Arrow environment, 1 GiB pool, tokens/proofs disabled. `kept_ids`/`node_units` released before index construction; store reopened with exact 858,016-node and 1,693,866-edge manifest/index counts. Dirty checkout: edge count is a current validation datapoint, not clean-tree parity. |
| 2026-08-21 | working tree | Linux `net/ipv4` direct C pass 1 | 15.75 | — | — | 164,437 | 313,693 | ~0.39* | 130 C/header files / ~114k LOC; cold direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 422,166,528 bytes. Linux checkout was dirty, so counts are a scale-boundary measurement. |
| 2026-08-21 | working tree | Linux whole `net/` direct C pass 1 safety boundary | >120* | — | — | — | — | ~3.22* | 1,738 C/header files / 37 MiB source tree; cold direct frontend with tokens/proofs disabled and `LACHESIS_C_JOBS=1`. The bounded 120s run timed out during compilation before publishing a shard, with `/usr/bin/time -l` peak RSS 3,223,060,480 bytes. This is a failure boundary, not a graph result; whole-tree sharding/streaming is required before retrying. |
| 2026-08-21 | `6826a43` | Linux whole `net/` direct C pass 1 after property-map copy removal | >120* | — | — | — | — | ~3.08* | Same 1,738-file / 37 MiB tree and bounded settings; compilation still timed out before publishing a shard, but peak RSS fell to 3,082,240,000 bytes (~140 MiB lower). This remains a failure boundary, not a graph result; bounded whole-tree emission is still required. |
| 2026-08-21 | `6826a43` | Linux whole `net/` direct C pass 1 completed | 219.66 | — | — | 1,833,812 | 3,508,461 | ~3.44* | Same 1,738-file / 37 MiB tree, fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`, hard 300s cap. `/usr/bin/time -l` peak RSS 3,442,147,328 bytes; the complete graph was published and the output was cleaned after measurement. This is the current whole-net cold builder baseline. |
| 2026-08-21 | `6826a43` | nginx 1.31.3 direct C pass 1 | 134.36 | — | — | 585,243 | 1,189,604 | ~1.34* | 403 C/header files / 15 MiB source; fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`, hard 300s cap. `/usr/bin/time -l` peak RSS 1,335,033,856 bytes; graph publication completed and the temporary output was cleaned. This is an independent large C codebase boundary. |
| 2026-08-21 | `6826a43` | Linux `net/netfilter` direct C pass 1 | 20.68 | — | — | 163,942 | 305,022 | ~0.45* | 254 C/header files / 3.9 MiB source; fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 472,891,392 bytes. This completes well below the safety cap and gives a larger bounded subsystem point below whole `net/`. |
| 2026-08-21 | working tree | Linux `net/ipv4` cold streamed core + Kùzu | 37.81 | — | 10.48 | 164,437 | 313,693 | not sampled | 130 C/header files / ~114k LOC; disposable Python 3.11/Kùzu env, 1 GiB pool, tokens/proofs disabled. Kùzu phases: 1.467s scan, 4.695s nodes, 3.959s edges, 0.238s indexes; store publication completed under the 120s cap. |
| 2026-08-21 | working tree | Linux `net/ipv4` streamed Kùzu after post-edge map release | 34.81 | — | 9.97 | 164,437 | 313,699 | ~0.65* | Fresh disposable Python 3.11/Kùzu/Arrow environment, 1 GiB pool, tokens/proofs disabled; `kept_ids` and `node_units` were released before index loading. Store reopened with matching manifest/index node counts; `/usr/bin/time -l` peak RSS 652,492,800 bytes. Dirty checkout: edge count is not clean parity evidence; wall time is compared only as a bounded datapoint. |
| 2026-08-21 | working tree | Linux `net/ipv4` lazy pass-3 overview/enrichment | 27.33 | 8.05 enrichment | — | 164,437 | 313,696 | ~1.91* | 130 C/header files / ~114k LOC; ephemeral query over the streamed store. Core materialization took 5.407s; overlay fold 8.052s; peak RSS 1,908,375,552 bytes. Overlay deltas were recorded per registry; no graph writes were retained. |
| 2026-08-21 | working tree | Linux `net/ipv4` lazy pass-3 overview after compact/shared indexes | 22.40 | — | — | 218,376 | 418,665 | ~1.84* | Fresh Python 3.11/Kùzu streamed store, ephemeral enrichment, no retained cache; `/usr/bin/time -l` peak RSS 1,840,955,392 bytes. Query returned the enriched canonical manifest successfully. This is ~18% faster and ~68MiB lower sampled RSS than the prior 27.33s row; Linux checkout was dirty, so counts are not a clean-tree parity claim. |
| 2026-08-21 | `2bd9fd9` | Linux `net/ipv4` cold streamed core + pass-3 overview after seed-container release | 31.14 | 21.93 | 10.12 included | 218,374 | 131,524 cross-tier | ~1.84* | Fresh disposable Python 3.11/Kùzu environment, 1 GiB pool, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; core store published and overview returned security/integrity summaries. Core Kùzu phases totalled 10.118s; pass-3 `/usr/bin/time -l` peak RSS 1,835,646,976 bytes. Dirty Linux checkout: counts are a timing/validation datapoint, not clean-tree parity evidence. |
| 2026-08-21 | working tree | Linux `net/ipv4` ephemeral pass-3 with deferred Kùzu navigation maps | — | 21.33 | — | 218,376 | 418,665 | ~1.82* | Action-style query opened the core store with `defer_maps=True`, skipping unused navigation bucket construction. `/usr/bin/time -l` peak RSS 1,824,817,152 bytes. Full-map and deferred-map enrichments produced identical 218,376-node / 418,665-edge graphs and identical content hashes; security summary remained 172 sources / 13 sinks. Dirty checkout: timing/memory validation only. |
| 2026-08-21 | working tree | Action-style `fs/netfs` build + batch security query | 7.66 | — | included | 13,185 | 24,719 | ~0.46* | Disposable Python 3.11/Kùzu env, 1 GiB pool, Action defaults (`--prune --incremental`), ephemeral `security-paths` export; build reopened with exact manifest counts and query completed successfully. This validates the shared engine path used by the GitHub Action; no Action wrapper change was required. |
| 2026-08-21 | working tree | Linux `fs/netfs` streamed Kùzu storage footprint | — | — | — | 13,185 | 24,719 | — | Fresh pruned core store reopened with exact counts; on-disk footprint is 16,340,062 bytes total (`graph.kuzu` 16,338,944 bytes + 1,118-byte protobuf manifest). This is the baseline for future compression/index-space experiments. |
| 2026-08-21 | working tree | Linux `fs/netfs` non-streamed Kùzu storage comparison | 7.83 | — | included | 13,185 | 24,719 | ~0.48* | Fresh Python 3.11/Kùzu build with the ordinary writer, 1 GiB pool, prune enabled; exact counts after reopen. On-disk footprint 16,207,655 bytes (`graph.kuzu` 16,162,816 + 44,839-byte manifest), only ~0.8% smaller than streamed mode, while peak RSS was 513,703,936 bytes. A shared-dictionary redesign is not justified by this space delta. |
| 2026-08-21 | working tree | `fs/netfs` pass-3 Kùzu query-thread comparison | 1.25 → 1.26 | — | — | 13,185 | 24,719 | ~0.25* | Same ephemeral overview at `LACHESIS_KUZU_QUERY_THREADS=1` and `8`; outputs identical, peak RSS 264,683,520 → 266,567,680 bytes. No small-workload tuning benefit; bounded default remains unchanged. |
| 2026-08-21 | working tree | Linux `fs/ext4` direct C pass 1 | 14.80 | — | — | 131,635 | 286,007 | ~0.54* | 51 C files; fresh direct frontend output, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 574,504,960 bytes. This is a bounded complex-filesystem scale point below the USB/net north star. |
| 2026-08-21 | `78ba14e`/`5b54358` | Pass-3 index microbenchmark | 0.283 → 0.238 | — | — | 120,000 | 180,000 | 244.0 → 235.5 MB* | Synthetic 120k-node/180k-edge graph: compact lazy indexes cut construction time ~16% and sampled RSS ~8.5 MB; layered security now reuses one index instead of rebuilding three additional copies. This is an implementation signal, not a north-star workload result. |
| 2026-08-21 | working tree | Materialized-edge ordering microbenchmark | 0.347 → 0.062 | — | — | — | 180,000 | — | Synthetic unique-edge-heavy stream: grouped sorting preserves exact encoded-property tie ordering while avoiding property serialization for unique triples (~5.6× sort speedup). Real-store validation is recorded in the following row. |
| 2026-08-21 | `bc60917` | Linux `fs/netfs` cold streamed core + Kùzu after grouped materialization sort | 3.54 | — | 1.13 | 13,185 | 24,719 | ~0.37* | Fresh Python 3.11 disposable env, 1 GiB pool, tokens/proofs disabled; store published and reopened. Standalone whole-store materialization was 0.258s with exact node/edge counts. `/usr/bin/time -l` peak RSS 398,721,024 bytes. This is a bounded validation, not a claim of north-star regression/improvement from the earlier 3.57s row. |
| 2026-08-21 | working tree | Kùzu property-tail cache microbenchmark + netfs reopen | 0.373 → 0.177* | — | 1.04 | 13,185 | 24,725 | — | Bounded 4,096-entry cache cuts a repeated 100k-edge tail batch ~2.1× (unique tails remain ~0.50s); short-tail bytes only, so memory cannot grow with graph size. Fresh Python 3.11/Kùzu run reopened with exact manifest/materialized counts; Linux checkout was dirty, explaining the edge-count difference from earlier rows. Kùzu phases: 1.039s total, edge load 0.336s. |
| 2026-08-21 | working tree | Linux `fs/netfs` direct C pass 1 after bounded protobuf property cache | 1.90 | — | — | 13,185 | 24,719 | ~0.065* | 27 C files; fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 67,780,608 bytes. Repeated metadata shapes are cached per tier (≤1,024 entries); location/offset/hash-bearing unique maps bypass the cache. Counts match the prior direct pass. |
| 2026-08-21 | working tree | Linux `net/ipv4` direct C pass 1 after bounded protobuf property cache | 16.35 | — | — | 164,437 | 313,693 | ~0.40* | 130 C/header files / ~114k LOC; fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 424,509,440 bytes. Counts match the prior boundary row; timing/RSS are slightly above the 15.75s / 422,166,528-byte baseline and are recorded as variance, not an improvement claim. |
| 2026-08-21 | working tree | Linux `net/ipv4` direct C pass 1 after fast metadata cache keys | 15.52 | — | — | 164,437 | 313,693 | ~0.39* | 130 C/header files / ~114k LOC; fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 419,528,704 bytes. Replacing recursive cache-key freezing with metadata-only scalar keys brings the boundary below the 15.75s / 422,166,528-byte baseline; counts remain exact. |
| 2026-08-21 | working tree | Linux `net/ipv4` direct C pass 1 with opt-in `LACHESIS_C_JOBS=2` | 13.00 | — | — | 164,437 | 313,693 | ~0.39* | Same 130-file / ~114k LOC workload and emission settings; `/usr/bin/time -l` peak RSS 418,004,992 bytes. Two in-flight Clang jobs cut wall time ~16% with exact counts and no observed RSS increase here; the default remains one job for larger trees because AST stdout can multiply memory. |
| 2026-08-21 | `82aae6a` | Linux `net/ipv4` direct C pass 1 with adaptive medium-tree default | 12.87 | — | — | 164,437 | 313,693 | ~0.39* | Same workload with `LACHESIS_C_JOBS` unset; the new 128–511-file policy selected two jobs automatically. `/usr/bin/time -l` peak RSS 417,366,016 bytes; exact counts preserved. Trees with 512+ files still default to one job. |
| 2026-08-21 | working tree | Linux `net/ipv4` direct C pass 1 after property-map copy removal | 12.14 | — | — | 164,437 | 313,693 | ~0.40* | Same 130-file / ~114k LOC workload with adaptive jobs and tokens/proofs disabled; `/usr/bin/time -l` peak RSS 416,792,576 bytes. Removing the redundant second copy of each fresh `**properties` map preserved exact counts and measured a lower wall/RSS boundary; single-run variance applies. |
| 2026-08-21 | working tree | Linux `fs/netfs` direct C pass 1 after fast metadata cache keys | 1.91 | — | — | 13,185 | 24,719 | ~0.063* | 27 C files; fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 66,240,512 bytes. Exact counts retained; timing is consistent with prior 1.90–1.94s runs. |
| 2026-08-21 | working tree | Linux `drivers/usb` direct C pass 1 after fast metadata cache keys | 93.31 | — | — | 858,016 | 1,693,859 | ~1.84* | 790 files / 582,731 LOC; fresh direct frontend, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; `/usr/bin/time -l` peak RSS 1,981,251,584 bytes. This is slightly below the prior 93.85s / 1,984,430,080-byte USB row; the Linux checkout was dirty, so edge counts are not a clean parity claim. |
| 2026-08-21 | working tree | Linux `drivers/usb` cold streamed core + Kùzu after property-tail cache | 186.55 | — | 59.50 | 858,016 | 1,693,823 | ~1.85* | 790 files / 582,731 LOC; fresh Python 3.11 disposable env, 1 GiB pool, tokens/proofs disabled, `LACHESIS_C_JOBS=1`; store reopened with exact manifest/materialized counts. Peak RSS 1,989,656,576 bytes. This is slightly above the earlier 186.00s / ~1.86GiB row, so it is a bounded validation rather than an end-to-end improvement claim; checkout was dirty. |
| 2026-08-21 | working tree | Linux `net` cold streamed core-only CLI | >300* | — | >17* | — | — | >3.0* | 1,738 C/header files / 1,292,818 LOC; direct CLI, tokens/proofs disabled, `LACHESIS_C_JOBS=1`, 1 GiB Kùzu pool. Pass 1 reached publication, but the run was safety-stopped before Kùzu finished (header scan 17.089s, schema 0.090s); no manifest or graph result is claimed. Partial output was removed. |
| 2026-08-21 | working tree | nginx 1.31.3 cold streamed core-only CLI | 197.28 | — | 38.00 | 585,243 | 1,189,617 | ~1.55* | 403 C/header files / 250,780 LOC; direct CLI, tokens/proofs disabled, `LACHESIS_C_JOBS=1`, 1 GiB Kùzu pool. Kùzu phases: 5.192s scan, 16.010s nodes, 16.151s edges, 0.531s indexes; manifest and node-count reopen matched. Peak RSS 1,664,499,712 bytes. |
| 2026-08-21 | working tree | nginx 1.31.3 cold streamed core-only CLI, fresh protobuf/Kùzu env | 223.33 | — | 44.90 | 585,243 | 1,189,604 | ~1.61* | Same 403-file / ~250k LOC tree, direct package command, 1 GiB Kùzu pool, tokens/proofs disabled. Kùzu phases: 5.959s scan, 18.581s nodes, 19.596s edges, 0.626s indexes; store publication completed under the 300s cap. This is a validation row, not an improvement claim, because environment and checkout variance exceed the earlier 197.28s run. |
| 2026-08-21 | working tree | nginx 1.31.3 pass-3 ephemeral overview, 8 Kùzu query threads | 99.42 | — | — | 655,637 | 1,418,968 | ~5.01* | Reopened the fresh core-only store with `LACHESIS_QUERY_EPHEMERAL_ENRICH=1`; canonical manifest and security summary returned successfully. `/usr/bin/time -l` peak RSS 5,005,393,920 bytes; no enriched cache was retained. |
| 2026-08-21 | working tree | nginx 1.31.3 pass-3 ephemeral overview, 1 Kùzu query thread | 96.51 | — | — | 655,637 | 1,418,968 | ~5.08* | Same store and query output byte-for-byte identical to the 8-thread run. One thread was not a memory win (5,079,597,056-byte peak RSS) and only a single-run wall-time variance, so the default remains unchanged. |
| 2026-08-21 | working tree | nginx 1.31.3 pass-3 after compact ecosystem index | 99.18 | — | — | 655,637 | 1,418,964 | ~4.84* | Fresh streamed store, 8 query threads, ephemeral enrichment. Peak RSS fell to 4,839,129,088 bytes (~166 MiB below the prior 8-thread run) with the same security summary and canonical node count; the dirty checkout changed four edge rows, so this is a memory result rather than a clean graph-parity claim. |
| 2026-08-21 | `bb3d425` | nginx 1.31.3 pass-3 with stale-index/core-cache lifetime fixes | 101.14 | — | — | 655,636 | 1,418,978 | ~4.89* | Fresh streamed store, 8 query threads, ephemeral enrichment; security summary returned successfully. Peak RSS 4,890,214,400 bytes, within run variance of the 4.84–5.01 GiB nginx rows, so this is validation only. Pass-two build for this same run was 223.07s / 1.61 GiB. |
| 2026-08-21 | working tree | Linux `fs/netfs` cold streamed core + pass-3 after compact ecosystem accumulator | 6.05 | — | 1.48 | 18,252 | 34,227 | ~0.40* | Fresh Python 3.9/Kùzu disposable env, 512 MiB pool, tokens/proofs disabled; pass-two store publication completed in the 4.57s build, then ephemeral overview completed with exact reopened counts. Query peak RSS was 291,373,056 bytes; this checkout's counts differ from older netfs rows, so timing/memory only. |
| 2026-08-21 | working tree | Linux `fs/netfs` pass-3 after dropping stale ecosystem index | 1.47 | — | — | 18,252 | 34,227 | ~0.27* | Fresh streamed store and ephemeral overview; the ecosystem index is released before model/security overlays. Exact summary/counts matched the prior current checkout row; `/usr/bin/time -l` peak RSS 287,440,896 bytes (a small-workload validation, not a whole-net claim). |
| 2026-08-21 | `2f221d7` | Linux `fs/netfs` pass-3 after dropping each overlay registry index before final sort | 1.49 | — | — | 18,252 | 34,227 | ~0.28* | Fresh streamed store, ephemeral overview, exact summary/counts; `/usr/bin/time -l` peak RSS 289,062,912 bytes. This is within run variance of the preceding row and is recorded as lifetime validation, not a speed/RSS claim. |
| 2026-08-21 | working tree | Linux `fs/netfs` pass-3 after removing redundant materialization sort | 1.49 | — | — | 18,252 | 34,241 | ~0.28* | Fresh streamed store, ephemeral overview; final node ordering remains deterministic because the post-overlay sort is retained. Query completed with exact reopened counts; peak RSS 291,192,832 bytes. This validates parity, not a timing claim. |
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

### Rejected compact Clang raw-ID map

An experiment normalized hexadecimal Clang declaration ids to integer dictionary keys
(``raw-id`` micro-optimization). It lowered the 254-file ``net/netfilter`` sample by
about 3.6 MiB, but the whole 1,738-file ``linux/net`` run rose from 3,442,147,328 to
3,761,340,416 bytes peak RSS (wall time stayed near 219s). The change was reverted;
the whole-tree result, not the small-subsystem result, is the acceptance gate.

### Rejected early C scratch-index release

Releasing the declaration maps, source caches, and spilled AST directory immediately
after their apparent last pass reduced the 254-file ``net/netfilter`` sample to about
465 MiB RSS, but the complete 1,738-file ``linux/net`` run rose to 3,800,219,648 bytes
(from the 3,442,147,328-byte baseline). It was reverted; allocator/page-cache effects
make the small-subsystem result non-predictive at whole-tree scale.

### Rejected ``PYTHONMALLOC=malloc`` allocator setting

The system allocator reduced the 254-file ``net/netfilter`` sample by about 26 MiB,
but a whole ``linux/net`` run failed the 300-second cap before publishing and reached
3,753,066,496 bytes peak RSS with substantially higher system time. It is not a safe
GitHub Action default; the process allocator remains unchanged.

### Rejected post-build tier record release

The serializer was changed to release each tier's node records immediately after its
protobuf write. Fixture and cross-TU parity stayed exact, but whole ``linux/net`` rose
to 226.94s / 3,450,372,096 bytes peak RSS versus the 219.66s / 3,442,147,328-byte
baseline. The implementation was reverted; retaining the graph through serialization
is currently the faster measured path.

### Rejected shared empty edge-property map

Sharing one empty property dictionary for propertyless edges lowered the 254-file
``net/netfilter`` sample by about 8 MiB, but whole ``linux/net`` rose to 223.59s and
3,752,067,072 bytes peak RSS. It was reverted; the serializer's copy-on-default path
did not translate the local allocation saving to the aggregate workload.

### Rejected C offset lookup via ``bisect_right``

Replacing the per-node Python line-offset search with ``bisect_right`` made whole
``linux/net`` pass one about 3s faster (216.64s), but peak RSS rose from the 3.44 GiB
baseline to 3.79 GiB. Since memory is the adoption constraint, the CPU-only change was
reverted despite the wall-time improvement.

### Rejected manual cyclic-GC tuning

Disabling cyclic GC cut the whole ``linux/net`` builder to 206.20s, but retained
garbage raised peak RSS to 3,779,624,960 bytes. Leaving normal GC enabled and forcing
one final collection was slower still (231.77s / 3,689,349,120 bytes), so both runtime
experiments were reverted.

### C frontend path-resolution reduction

The C macro/dependency passes now memoize repeated preprocessor marker and dependency
paths (`3ad17ad`). On the 4-file C fixture, the cProfile count of `Path.resolve()` calls
dropped from 2,167 to 319; the emitted graph remained 442 nodes and 784 edges. This
is a CPU/syscall reduction, not a large-codebase timing claim; the Linux `fs` run still
needs a fresh bounded measurement before its pass-1 row can change.

Macro recovery also streams preprocessor lines (`0fc41c5`) instead of creating a
temporary `splitlines()` list, reducing transient memory without changing the fixture
graph.

### Pass-3 seed-container lifetime

The overlay registry now releases the original graph dictionary and its seed list
wrappers immediately after the first overlay is absorbed (`4f9fde2`). The accumulator
already owns the canonical records, so retaining those wrappers through every later
overlay and the final sort was redundant. Core overlay/ecosystem/projection parity
tests pass. The fresh `net/ipv4` Kùzu-backed validation is recorded in the history
(`c218e34`); it is a lifetime/parity datapoint, not a claimed whole-net improvement.

### Rejected ephemeral Kùzu-index release

The Action-style ephemeral query was experimentally changed to drop its navigation
index immediately after core materialization. On two fresh `linux/net/ipv4` runs the
overview remained byte-compatible and took 21.93s / 1,835,646,976 bytes RSS before
the change versus 21.74s / 1,851,916,288 bytes after it. The small wall-time delta
was within run variance and RSS was slightly worse, so the change was reverted; the
navigation index is not a demonstrated pass-3 memory bottleneck.

### Rejected direct protobuf property append

Pass-1 profiling showed property conversion as a medium-subsystem hotspot, so an
experiment appended unique property fields directly into protobuf repeated fields
instead of building a temporary Python list. `linux/net/ipv4` improved from 15.52s
to 15.04s with essentially unchanged RSS, but the whole `linux/net/` gate rose to
3,768,434,688 bytes RSS (3.77 GiB) despite a 210.21s wall time. The graph emitted
1,833,812 nodes; the dirty checkout produced 3,507,809 edges versus the historical
3,508,461. The memory regression exceeds the acceptance rule, so the experiment was
reverted.

### Rejected property-key sort fast path

Avoiding `str()` calls for the usual string property keys was tested with a fallback
for non-string mappings. The bounded `linux/net/ipv4` run measured 15.89s and
420,970,496 bytes RSS, slower and slightly larger than the nearby 15.04s trial, so
the change was reverted without spending another whole-net run on it.

### Rejected cached-property tuple return

Returning the immutable cached protobuf-field tuple directly (instead of copying it
to the list expected by the existing serializer) was tested twice on `linux/net/ipv4`:
15.60s / 419,872,768 bytes RSS and 15.64s / 421,445,632 bytes. Neither run improved
the nearby 15.52s baseline, so the compatibility-preserving list copy remains.

### Rejected cross-tier property cache sharing

Sharing the bounded protobuf property cache across the five C tiers was tested to
reuse metadata shapes between tier files. The `linux/net/ipv4` run measured 15.70s
and 424,558,592 bytes RSS, worse than the nearby per-tier-cache baseline, so the
experiment was reverted; each tier retains its own bounded cache.

### Rejected macro line-slicing rewrite

Macro recovery was changed experimentally to inspect continuation lines through the
cached offset table instead of rebuilding `splitlines()` for each macro. Focused C
and graph-wire tests passed, but `linux/net/ipv4` measured 15.55s and 419,463,168
bytes RSS, indistinguishable from the existing 15.52s baseline. The rewrite was
reverted without a whole-net run.

### Rejected per-build file-string cache

Sharing repeated `properties.file` strings through a per-build cache was tested to
reduce AST position-map duplication without global interning. The bounded
`linux/net/ipv4` run measured 15.47s and 419,971,072 bytes RSS versus the nearby
15.52s / 419,528,704-byte baseline, which is within noise and slightly larger in
RSS; the cache was reverted without a whole-net run.

### Rejected slotted node-tier refactor

Moving immutable tier membership from the separate `node_tier` dictionary into each
slotted node looked like a graph-sized memory saving. The required whole `linux/net`
gate emitted the same 1,833,812 nodes but reached 3,823,108,096 bytes RSS (218.79s)
versus the 3,442,147,328-byte baseline (219.66s); the dirty checkout had 3,507,612
edges. The large RSS regression caused the refactor to be reverted.

## Regression rules

An optimization is not accepted on speed alone. Compare node/edge counts and validate
the resulting bundle. A meaningful regression is either:

1. changed graph counts or failed snapshot validation;
2. increased peak RSS that makes the north-star workload unsafe; or
3. increased any pass time by more than 10% without a documented precision or coverage
   improvement.

The GitHub Action can benefit from these engine improvements, but its cache-hit and
cache-miss timings must be recorded separately in the action repository.

## Scale boundary

The local Linux checkout is approximately 2.0 GiB on disk. It contains about 64k
C/C++ source/header files; `drivers/` alone contains 33,835 C/header files, while
the north-star `net/` workload contains 1,738. A full-tree cold graph build is not
currently an acceptable benchmark: it exceeds the ten-minute safety budget and
would consume substantially more memory than the validated subsystem runs. We use
`net/`, `drivers/usb`, and smaller `fs/*` slices as staged scale boundaries until
the builder can process the full tree within that cap. No full-tree result is
claimed or used to tune numbers.
