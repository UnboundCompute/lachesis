# Phase 2 — the resolution tier

`lachesis/resolution.py` answers "what does this call site call" for one call site, from
the persisted graph plus Phase 1's two name indices. It has no consumer yet: rewiring the
tools is Phase 3, and that is deliberate, because it means the equality harness can prove
nothing moved.

## It is a superset, not a replacement

The decision the spec does not make. Each frontend resolves with information that never
reaches the canonical graph — TypeScript asks the compiler's checker for overload
selection, Python's resolver knows import bindings and the MRO, C's post-pass keys on
clang's per-run AST ids. A name-join over the persisted graph cannot reproduce any of it,
so a resolver that *replaced* those answers would lose edges. Rung 1 is therefore
"believe the frontend", and rungs 2–7 only ever fire where the frontend gave up.

```
1. primary_target_id, or a trusted INVOKES edge          -> exact
2. a `static` declaration of the name in the same file   -> exact
3. exactly one non-static definition project-wide        -> exact
4. exactly one candidate under the name                  -> high
5. more than one candidate                               -> conservative + all
6. no candidate, but an indirect edge leaves the site    -> unresolved, edge kept
7. nothing                                               -> unresolved, no candidates
```

Rung 2 precedes rung 3 because C's file-local `static` shadows whatever else is linked
in; the other order labels a shadowed extern `exact` and is simply wrong.

**Deviation from the plan, and why.** The plan's rung 1 trusts an edge whose `resolution`
is in `{exact, cross-tu, binding, registration}`. That set is C's vocabulary. Python and
TypeScript record an edge's certainty in `confidence` instead — an `import-binding`
INVOKES at `confidence: exact` is as decided as C's `cross-tu` — so rung 1 also trusts
`confidence in {exact, high}`, and `compiler-local` was added to the resolution set for
symmetry with the `primary_target_id` it accompanies. Without this, a fully resolved
Python call would fall through to the name-join and could come back with a *different*
answer, which is the one thing a superset may not do.

No rung removes an edge. Rung 5 returns a candidate list and says `conservative`; rung 6
returns the indirect edge's targets rather than reporting silence. Invariant 2
("unresolved must be an edge, not an absence") is a Phase 3 obligation and is untouched.

## What the fixture actually tests

The Phase 1 write-up claimed `fixtures_homonym/` was left `dynamic-or-unresolved` by the
frontend. Measured, that is false: both calls are intra-TU, clang resolves them, and
`sole_definition` never gets asked. Corrected in `phase1.md` and in the fixture's own
header.

The fixture is still the right one, for a sharper reason — the *name* `funcA` is
ambiguous and the *file* is not. `HomonymResolutionTests._blinded` strips
`primary_target_id` and every `INVOKES`/`CALLS` edge out of a copy of the graph, which is
exactly the state a C tree is in when clang could not see the definition, and asks again.
Rung 2 answers, and its answer must equal the frontend's. That single assertion tests the
rung in isolation *and* pins the superset property; neither half is worth much alone.

The same trick on `fixtures_crosstu/` exercises rung 3: no static shadow anywhere, one
external definition, promote it — and unblinded, rung 1 inherits the post-pass's
`cross-tu` answer, targeting the definition in `lib.c` rather than the prototype in
`lib.h`.

One trap worth recording: `shared.c` forward-declares `alpha_entry`, so the graph holds
two nodes with that name and the bodyless one owns no call sites at all. A test that took
the first match by label would pass or fail on frontend ordering. `_definition()` takes
the one that is not `declaration_only` and asserts uniqueness.

## Scope and cost

```python
resolve(index, call_site_id)          -> {target, candidates, confidence, via, truncated}
resolve_decl(index, node_id, depth=1) -> {call_site_id: result}
resolve_cone(index, node_id, budget=256) -> {members: frozenset, truncated: bool}
```

`DECL_DEPTH = 1` and `CONE_BUDGET = 256` are different numbers on purpose (invariant 3):
sharing a default would let a caller who wanted the cheap question pay for the expensive
one by accident, and a test asserts they differ. `resolve_cone` is budgeted BFS mirroring
`planner.dominance.call_closure`; the budget is a *stop*, so `truncated` means "there was
more" and never "some was skipped". The apex is a member of its own cone.

`via` names the rung that answered. An `exact` from rung 1 is the compiler's word and an
`exact` from rung 2 is this module's reading of C linkage, and anyone auditing a
surprising edge needs to know which they are looking at.

`CANDIDATE_CAP = 64` comes from Phase 1's measurement, not from taste: nine `SBB_RB_*`
names on Suricata resolve to 473 declarations each. Rung 2 filters by file *before*
reading a single node, so that pathological case narrows to one candidate without paying
for the other 472; the cap only binds on rungs 3 and 5, and when it binds it is reported.

`owned_callsites` was lifted out of `nav/symbol_index.py`, which now imports it back.
One definition, so the sites the resolver binds and the sites nav reports indirect edges
from cannot drift apart.

## The memo

Per-`Resolver`, in process, keyed by call-site id; the cone memo by `(node_id, budget)`.
`flush_memos(db_dir)` appends it to the v9 `ResolveMemo` / `ConeMemo` tables after the
current high-water `seq`, stamping `graph_hash` on every row — the base store and its
`.enriched` sidecar are two databases whose call sites resolve differently, and a memo
that crossed between them would be a confident wrong answer.

`flush_memos` is best-effort: a read-only store, a pre-v9 store, or no `kuzu` are all
reasons to have no memo and none of them are reasons to fail a query already answered
correctly in memory. The in-process memo is the contract; the table is the optimization.
Ids go in raw rather than prefix-coded, because the prefix table is sealed when the store
is written and a memo is appended long after.

`GraphStore.resolver` is lazy like `entries`, and is bound to `store.index` rather than to
the store: `ensure_dataflow_tier` swaps the index for a larger one, and a resolver cached
on the store would go on memoizing answers about a graph nobody is querying any more.

## Verification

`HomonymResolutionTests` — 11 tests: the superset property on both fixtures, rungs 2 and 3
in isolation under `_blinded`, idempotence, `resolve_decl` visiting exactly one call site,
the cone reaching both `funcA`s untruncated, a budget of 2 stopping and admitting it, the
two defaults differing, the memo round-tripping through Kùzu with one distinct
`graph_hash`, and `GraphIndex` / `KuzuGraphIndex` resolving identically.

The equality harness stays **strict** and passes unchanged, which is the point: Phase 2
adds a tier and rewires nothing.
