# Phase 0 — one shared index, and a snapshot that lets go

Both files here come out of `tools/profile_build.py`, pointed at `./lachesis` on an
Apple Silicon machine. Reproduce with:

    python3 tools/profile_build.py ./lachesis --json out.json

`LAZY_GRAPH_SPEC.md` §1 quotes a build over the whole repository root; these numbers are
over `lachesis/` alone, because the repository root now also contains agent scaffolding
that `source_inventory` does not filter and that has nothing to do with the graph. The
shape of the table is the same and the two runs here are directly comparable.

| | before | after |
|---|---|---|
| total wall | 30.51s | 25.15s |
| **enrich wall** | **20.69s** | **15.31s** |
| enrich Δ peak RSS | +360 MB | +102 MB |
| **process peak RSS** | **1263 MB** | **1013 MB** |

Two changes, and each moves one column.

**One index absorbed forward through the core fold.** Every overlay used to build its
own `GraphIndex` over a graph that grows as the fold proceeds, so the eighth overlay paid
to index the first seven's output from scratch. The registry now builds one index and
hands it down, absorbing each delta into it. The overlays that contributed least were
paying the most — `parameter-property-effects` contributes 1 node and 5 edges and cost
1.79s, of which essentially all was indexing; it is now 0.31s. `async-events` went 2.40s
to 0.72s, `module-initialization` 1.93s to 0.40s on the same output.

**A snapshot releases its payload once the graph exists.** `snapshot_graph` copies every
node and its `properties` dict, so from the combine onwards the frontend snapshots held a
second complete copy of the graph — and they were held to the end of the build, because
the store manifest is written last. Enrichment's peak was measured on top of that
duplicate. Nothing reads the payload after the combine except two lengths in
`manifest_payload`, which `release()` keeps.

Two caveats on reading the table.

The "after" run is over a *slightly larger* tree — the Phase 0 tests are themselves
`lachesis/` source, so the core graph grew from 209,034 to 211,360 nodes between the two
runs. The improvement is real and marginally understated, not the other way round.

Per-overlay wall is not additive with the `enrich` row. `enrich` covers all four
registries plus `GraphAccumulator.view()` between overlays, which re-sorts ~500k edges per
delta and is deliberately untouched here: removing it would change the edge iteration
order the overlays consume. On this evidence it is now the largest single remaining item
in enrichment, and it is the next thing to measure.
