# The eager-vs-lazy equality harness

The lazy-resolution work replaces eager whole-graph enrichment with resolution done on
demand. The failure it risks is not a crash: it is `callers(X)` answering `[]` because
resolution has not run, which looks exactly like a clean codebase. Every other kind of
regression announces itself. That one does not, so it gets a harness.

    LACHESIS_BLESS=1 python3 -m lachesis.nav.checks --bless git:HEAD:lachesis
    LACHESIS_EQUALITY_HARNESS=golden python3 -m pytest lachesis/nav/checks.py

The baseline lives at `lachesis/nav/goldens/eager_baseline.json.gz` (158 KB) and records
**316 calls over 24 seeds** — 16 Python, 4 TypeScript, 4 C — carrying 7,300 rows plus
every scalar field the tools answer. Blessing refuses without `LACHESIS_BLESS=1`: an
agent that can regenerate the baseline it is judged against is not being judged.

## Two things that had to be got right

**The corpus is pinned to a commit, not to the working tree.** Arachne analyzes itself,
so a baseline recorded over `./lachesis` makes the corpus and the analyzer the same
files. The first blessing did exactly that, and the next run failed on twenty-odd rows —
all of them because editing `nav/checks.py` had shifted line numbers inside the graph
being compared. Those failures are indistinguishable from the regressions the harness
exists to catch, which makes the harness worse than useless. `git:<rev>:<subpath>`
exports the commit instead, and the golden records the resolved sha;
`LACHESIS_EQUALITY_HARNESS=golden` re-exports whatever the golden pins.

**The export goes to a fixed path, not a fresh temp directory.** C and TypeScript stamp
absolute paths into node ids, so a corpus that moved between two runs produced a
different `graph_content_hash` and different rows for identical code — the comparison was
permanently stuck in identity-relaxed mode, with every TypeScript row reading as changed.
Naming the export `~/.lachesis/corpora/<sha>/` makes the corpus reproducible on disk and
not merely in content, and it is what lets the current baseline compare in **strict**
mode. Re-exporting the same revision afterwards is free.

Answers are made checkout-independent by stripping every spelling of two roots: the
corpus root, and arachne's own checkout — TypeScript resolves its standard library out of
arachne's `node_modules`, so `lib.es2015.d.ts` paths leak into `call_roles` results and
have nothing to do with the corpus. Both are stripped in `/private`-symlinked and plain
form, because macOS hands out both and the frontends disagree about which they keep.

## What is compared

Asymmetrically, per spec §9. A golden row missing from the run is always a failure. An
extra row is also a failure by default, downgradeable per tool through
`ALLOWED_EXTRA_ROWS` with a comment naming the phase that justifies it — Phase 2's
`resolve` tier legitimately adds `callers`/`callees` rows, and that is when the entry gets
written.

Rows are not the whole answer, and an early version of this compared only rows. That left
**48 of the 316 calls comparing zero bytes**: `read_body` and `guards` answer no rows at
all, and every `counts`/`manifest`/`total`/`verdict` went unchecked. `scalars_of` takes
the other half, and the two are compared as one.

`hubs` is a ranking, so it is compared by membership plus a Spearman correlation against
the golden with a 0.9 floor — the §10 measurement.

Ten unit tests cover the comparison itself, unconditionally, because a compare step
exercised only by the two-minute run it gates is one nobody discovers is broken until
after it has passed something it should not have.

## Surviving Phase 1

Phase 1 changes Python call-site node ids without changing a source byte. The golden's
`graph_content_hash` is the tripwire: on mismatch the harness drops to **identity-relaxed**
mode, where a row is keyed on `(name, file, line, at, via, resolved, kind)` and ids nested
in scalars (`manifest.seed`, `manifest.src`, `function.node_id`) are masked rather than
deleted — so a field that stops carrying an id at all still shows up as a difference. What
relaxed mode still asserts about ids is that within any one answer they are distinct and
present in the graph, which is exactly the property the homonym work must not break.

Phase 1 runs relaxed and re-blesses; Phase 2 runs strict.

## Known limits

- The two-minute cost is the build, not the calls. Gate it behind its own CI job.
- `store_format_version` is recorded but not asserted; the v9 bump in Phase 1 will need a
  re-bless anyway, and `graph_content_hash` already catches it.
- Seeds are derived from the graph and re-derived on every run, so a seed that stops
  resolving is a failure rather than a silently dropped call. A seed set that *shrank* is
  itself asserted against.
