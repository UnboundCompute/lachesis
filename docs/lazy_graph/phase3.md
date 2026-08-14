# Phase 3 — wiring the tools to the resolver

Phase 2 built a resolution ladder and gave it no consumers. This phase gives it two,
and fixes the older bug that made having one worth doing.

## The collapse

`_seed` was three lines:

```python
def _seed(store, token):
    if store.node(token):
        return token
    hits = store.resolve(token)
    return hits[0]["node_id"] if hits else None
```

`store.resolve` returns a *ranked list* of everything a name could mean. `hits[0]`
throws the rest away, silently, and eleven of the seventeen tools were built on it. On a
tree with four `funcA`s, `callers("funcA")` answered about one of them and looked like a
complete answer — which is the failure mode the spec's §3 names: not an error, not an
empty result, just a smaller truth with nothing marking it as small.

### What replaced it

`si.peers(hits, name)` decides which hits are genuine rivals. Not all of them are: a
bodyless prototype, a lower-ranked reference and a fuzzy near-miss all sort below the
definition and lose on the merits, and promoting them to equals would trade one wrong
answer for a noisier one. A peer is an exact-name hit tying on every discriminator about
*what a node is* — kind rank, prototype-or-not, exported, test-or-not.

Degree is deliberately excluded. It is in `_resolve`'s sort key, but it is a popularity
signal, and two genuine homonyms nearly always differ on it — including it would collapse
precisely the case this exists for.

Then:

- `callers` / `callees` **union over every peer**. Rows carry their own `node_id`, so the
  union stays separable; deduplication is by node id, so a caller reached through two
  homonyms is one row.
- Every other seeded tool still takes one seed — `flow` from four different `funcA`s is
  four answers, not one — but now reports `homonyms: [{node_id, name, at}]` when there was
  a choice. The collapse becomes visible, and undoable with an explicit `node_id`.
- The key is **absent** when a name is unambiguous. A key that is always there stops
  meaning anything.

## The resolver, consumed

Both `callers` and `callees` walked edges only. That is fine when the frontend resolved
the call and useless when it did not — and "the frontend did not resolve it" and "nobody
calls this" produced the same empty list.

- `callees(..., resolver=)` walks the declaration's own call sites a second time and asks
  the ladder. A decided target becomes a `via="resolved"` row; a conservative candidate
  list becomes `via="candidate"`, `resolved=False`. It never overrules: a target already
  reported keeps the tag it already had, because `_add` keeps the first tag it sees.
- `callers(..., resolver=)` needs the reverse direction, which the resolver did not have.
  `Resolver.resolve_callers` is new: the forward question can be exhaustive because a call
  site names one callee, but the reverse cannot, so it starts from `callsite_index[name]`
  — every site that *mentions* this declaration's name — and puts each through the same
  ladder, keeping only those that land here. A homonym's callers therefore never leak into
  its twin's, which is the entire point.
- `CALLER_SITE_CAP = 2048` bounds it, and the bound is reported. A different cap from
  `CANDIDATE_CAP` because it bounds a different thing: `CANDIDATE_CAP` is how wide one
  answer may be, this is how much work one question may buy. `get` and `len` name tens of
  thousands of sites.

Both parameters default to `None`, so every existing caller of these two functions gets
exactly what it got before. Only `mcp_server` passes a resolver.

## Invariant 2, without drowning the answer

"An unresolved call must be an edge, not an absence." The literal reading — emit a row per
undecidable call site — would put every `printf` and every builtin into `callees`, which
is both a large behavioural change and noise: a row in that list means *this is called*,
and a site with no decidable callee is not that. It is a question.

So they are reported, and reported apart: `callees` grows an `unresolved` field listing
each such site as itself — `{node_id, callee, file, line, via}`. The hole has an address.
An agent asking "why does this function seem to call nothing" gets something it can open,
and the rows that claim a callee still all mean it.

`direct_only` remains the escape hatch it was: edges only, no inference, no `unresolved`.

## What this does *not* do

It does not make the build faster. The dispatch still calls `ensure_dataflow_tier()` for
every tool, and the comment there gives the reason: `callers`/`callees` traverse
`MAY_INVOKE` / `CONTEXT_CALLS` / `READS_CALLEE`, which are overlay-derived, so a
selectively-enriched store would answer differently depending on which tool ran first.
Skipping enrichment is Phase 4's job — scoped overlays — not this one. The build-time
number still stands where Phase 0 left it (30.51s → 25.15s, 1263 → 1013 MB).

## The harness

Phase 3 is the first phase that changes an answer, so it is the first to spend the
harness's asymmetry. Two entries in `ALLOWED_EXTRA_ROWS` (`callers`, `callees`) and two in
the new `ADDED_FIELDS` (`homonyms`, `unresolved`), each naming the phase. `ADDED_FIELDS`
is separate on purpose: those fields are the answer describing how it was arrived at
rather than rows about the graph, so they are permitted on any tool while a *third* new
field still has to justify itself. The `missing` half stays a hard failure everywhere —
nothing here can hide a lost row.

`ADDED_FIELDS` has to be honoured in two places, which is worth recording because it was
not obvious. `rows_of` drops empty lists, so `unresolved: []` — the common case, on every
call the ladder decides completely — never reaches the row comparison at all. It arrives
as a *scalar*, and was reported as a new field on exactly the calls where it had nothing
to say. The row loop and the scalar loop both skip it now.

## Verification

`HomonymNavigationTests` in `lachesis/frontends/checks.py`, eight tests over the C
homonym fixture, in two halves.

The collapse: both `funcA`s seed, the `alpha_entry` prototype does not, `callers("funcA")`
names both entries, `homonyms` carries two distinct ids, and an unambiguous name carries
no `homonyms` key at all.

The recovery, on `_blinded(graph)` — the same graph with `primary_target_id` and every
`INVOKES`/`CALLS` edge removed, i.e. the state a C tree is in when the compiler could not
see the definition. There, `callers("funcA")` used to return nothing; it now returns both
entry points, every row tagged `resolved`, because no edge carried them and the ladder
did. Deleting the `alpha_entry` declarations as well leaves a genuine hole, and that hole
turns up in `unresolved` with a real node id and `shared.c` as its file.
