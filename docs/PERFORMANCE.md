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

`*` The first full-subsystem measurement was run with token and proof emission disabled
and `LACHESIS_C_JOBS=1`; it predates this harness, so pass-level timings should be
replaced by a fresh JSON record before using it as a regression baseline.

The `fs` result is intentionally retained as a failure boundary. A large-codebase
optimization must move that row from “stopped” to a validated node/edge count; a
smaller successful subsystem is not considered a substitute.

The CLI/enrichment row is also a boundary, not a timing result: the frontend process
must finish before composition and enrichment can begin. It is kept to prevent a
misleading claim that pass 2 has been optimized when pass 1 has not yet completed on
the larger end-to-end path.

## Regression rules

An optimization is not accepted on speed alone. Compare node/edge counts and validate
the resulting bundle. A meaningful regression is either:

1. changed graph counts or failed snapshot validation;
2. increased peak RSS that makes the north-star workload unsafe; or
3. increased any pass time by more than 10% without a documented precision or coverage
   improvement.

The GitHub Action can benefit from these engine improvements, but its cache-hit and
cache-miss timings must be recorded separately in the action repository.
