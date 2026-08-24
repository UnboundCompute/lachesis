# SKELETON.md — the frozen flow-skeleton schema (v1)

**Status: FROZEN for the first implementation.** This is the schema Claus emits and the
matcher consumes. It is the concrete realization of `ARCH.md` (read that first for *why*).
Frozen after two review rounds; every "correction baked in" below is a real error that was
made and overturned — do not silently revert them.

Companion: `ARCH.md` (the architecture), the 6-phase build plan (§10 here).

---

## 0. One-paragraph orientation

Claus explores **forward** from every `SOURCE_REACHABLE` entry and builds a **semantic flow
graph** (never a linear stream): per-function **fragments** joined at **seams** (call/return),
carrying object identities, symbolic generations, guard proofs, and source tags. Claus does
**not** decide bugs. The **matcher** is a separate stage that does **pushdown reachability
with temporal progress** over that graph: it advances loose ordered patterns
(`ALLOC →* FREE →* USE`) along a single branch-compatible path, respecting object identity,
generation, and a **call continuation** so shared fragments cannot return to the wrong caller.

---

## 1. Object model — storage vs pointee (do not conflate)

Two kinds of object identity, always kept distinct:

- **Storage object** — a single allocation (`O_buf` = `malloc(sizeof(Buf))`). Its *own
  fields* are memory physically contained in it.
- **Pointee object** — a separately-allocated block reachable *through* a field/slot of a
  storage object (`O_payload`, stored in `O_buf.data`).

`free(O_buf)` releases `O_buf` and its **contained field storage** — so any read that
*dereferences* `O_buf` to reach a field is a use-after-free. It does **not** release
`O_payload`. A value already captured out of the field into an independent name
(`saved = b->data`) refers to `O_payload` directly and survives `free(b)`.

> Correction baked in: prefix/containment invalidation applies to the freed allocation's own
> storage, **not** to separately-allocated pointees stored in its fields. `saved = b->data;
> free(b); use(saved)` is **safe** and must not be flagged.

### ObjRef

```
ObjRef = (base, path, generation)
  base       = alloc-site | Param(pos) | decl:id        (symbolic inside a fragment)
  path       = ordered selectors: *, .field, [i]
  generation = G  (symbolic inside a fragment; bound at the seam to caller_generation(O))
```

- **Inside a reusable fragment**, `base` and `generation` are **symbolic** (`Param(0)`,
  `G_p`). They are bound at the seam: `p ← caller actual`, `G_p ← caller_generation(O)`.
- A **new generation** is a different **lifetime incarnation** of the same abstract object.
  Generation advances **only** on incarnation events: successful `realloc`, a later allocation
  represented by the same allocation-site abstraction, loop widening that collapses repeated
  allocations, or explicit reuse of the same storage (placement). Different generations never
  link in the matcher.
- **Assignment does NOT advance a generation.** `p = q` rebinds the name `p`; `b->data = other`
  overwrites a slot's contents. Neither changes the identity or incarnation of any object —
  `q`'s object, `other`'s object, and the previously-stored object all keep their generation.

> Correction baked in: no literal `#0` inside a reusable fragment. `FREE p#G_p`, not
> `FREE p#0`. Access-path generations are symbolic too.
> Correction baked in: reassignment/slot-store is **not** an incarnation event — advancing a
> generation on `p = q` would break valid alias relationships and conceal real UAFs. Generation
> changes only when the lifetime incarnation an abstract object represents actually changes.

---

## 2. Event alphabet (frozen)

### 2.1 Lifecycle events — each *attempt* has explicit outcomes

```
ALLOC_ATTEMPT       -> success: ORIGIN O#g
                       failure: result = NULL

REALLOC_ATTEMPT(O#g) -> success: INVALIDATE O#g ; ORIGIN O#g+1 ; WRITE_STORAGE(slot, O#g+1)
                        failure: REALLOC_FAILED(O#g)            -- NO INVALIDATE(O#g) on this edge
                                 WRITE_STORAGE(slot, NULL)
                                 LOST_FROM_SLOT(slot, O#g)

FREE(O)             -> RELEASE(O) | INVALIDATE(O)      (guarded by O != NULL; free(NULL)=no-op)
```

- **Never** emit a bare `ALLOC O#0` next to a `branch O==NULL`. The allocation identity
  `ORIGIN` exists **only on the success edge**. A matcher must not start an `ALLOC(O)`
  pattern on a failed allocation.
- `REALLOC_ATTEMPT` is a **branch**, not an unconditional swap. Zero-size is an
  allocator-defined edge case noted on the node, not a separate rule.
- The **failure edge emits facts, never a verdict**: `REALLOC_FAILED(O#g)`, the *absence* of
  any `INVALIDATE(O#g)`/`RELEASE(O#g)` on that edge, `WRITE_STORAGE(slot, NULL)`, and
  `LOST_FROM_SLOT(slot, O#g)`. The skeleton does **not** stamp `O#g LIVE`. The matcher derives
  that `O#g` is still unreleased on that path *because* no invalidation/release occurred.
- `FREE` records **only** the release fact. Whether a later access is a UAF, and whether a
  lost slot is a leak, are **matcher conclusions** (§7), not encoded here.

> Correction baked in: realloc-failure does **not** imply a leak by itself — another alias
> (`saved = b->data`) may still reach the old block. Emit the facts (`REALLOC_FAILED`,
> `LOST_FROM_SLOT`, no invalidation); the leak matcher proves path-specific unreachability.
> Correction baked in: do **not** emit `O LIVE` / `stays LIVE` — that is a lifetime conclusion,
> and §2.4/§8 forbid the skeleton from persisting liveness verdicts. Emit `REALLOC_FAILED` +
> the absence of invalidation instead; the matcher concludes liveness.

### 2.2 Access events — dereference vs non-dereferencing value use (frozen split)

**A dereference is always a `READ_STORAGE`/`WRITE_STORAGE` with a base + path** (the path may be
`*`, `.field`, or `[i]`). A dereference requires the **base** object to be live. Using a pointer
*value* without dereferencing it (passing, comparing, returning) is a **different** event and
does **not** dereference anything.

```
-- DEREFERENCING (requires base live; path in {*, .field, [i], ...})
READ_STORAGE(base, path)          -- deref `base`, read the slot/target at `path`
WRITE_STORAGE(base, path, value)  -- deref `base`, write the slot/target at `path`

-- NON-DEREFERENCING value uses (touch the pointer value, not the pointee)
PASS_VALUE(O)                     -- pass the pointer value as an argument
COMPARE_VALUE(O)                  -- compare the pointer value (==, !=, <, ...)
RETURN_VALUE(O)                   -- return the pointer value
DERIVE(target, value_object)      -- bind `target` to a value_object loaded from storage
```

`*p`, `p[i]`, `p->f` are all `READ_STORAGE(base=O_p, path=…)` (or `WRITE_STORAGE` on the LHS) —
there is no separate "value dereference" event; dereferencing a local pointer *is* a storage
access on the object that local names.

A field expression is **two** events. `x = b->data` is:

```
READ_STORAGE(base=O_buf, path=.data)     -- dereferences O_buf (base must be live)
DERIVE(target=x, value_object=O_payload) -- x now names O_payload, decoupled from O_buf
```

and `log(b->data)` is `READ_STORAGE(O_buf,.data)` then `PASS_VALUE(<loaded pointee>)`. Whether
`log` itself dereferences the passed pointer comes from the **callee fragment / external-function
model**, never from the callsite — the callsite proves only that the value was passed.

This makes the shapes unambiguous. There is **one** UAF dereference pattern (a dereference of a
freed base, whether the path is `*` or a field):

```
uaf.deref:         RELEASE(O) ->* READ_STORAGE(base=O, *) | WRITE_STORAGE(base=O, *)
use.dangling-value: RELEASE(O) ->* PASS_VALUE(O) | COMPARE_VALUE(O) | RETURN_VALUE(O)
                    (weaker lead: using a dangling pointer VALUE is UB but not a deref)
```

> Correction baked in: one `OBSERVE (O_buf).data` event was wrong; but so is a plain
> `USE_VALUE(O)` that conflates a dereference with a pass/compare. Passing/comparing/returning
> a pointer is not a dereference — only `READ_STORAGE`/`WRITE_STORAGE` (base+path) is. So
> `USE_VALUE(NULL)`/`USE_VALUE(freed)` alone never proves a null-deref or a UAF *deref*.

### 2.3 Control & structure

```
branch(pred)  with guard proofs on each outgoing edge      (see §3)
merge         (join of branch arms)
loop          (back-edge; a re-allocation at the same site across iterations is an incarnation
               event.  The first re-entry is widened to one bounded `@loop:<node>` generation;
               repeated iterations reuse that abstract incarnation and reset the current slot's
               release state, while aliases captured before the loop retain their old generation.)
return(value)
seam_enter(callee, actual->formal bindings)   -- call edge
seam_exit(callee, return->receiver binding)   -- return edge
```

The graph keeps branches / merges / loops / calls / returns **as structure**. It is never
linearized. A total order does not exist for a nontrivial program.

### 2.4 Per-node facts (emitted, not concluded)

`object identity + generation`, `guard proofs in scope`, `source tags`, `line/node origin`.
Claus keeps **transient construction-time** state (aliases, feasible successors, strong/weak
updates, generation counters) to resolve identity — it just does **not** persist duplicated
`FREED/LIVE` lifetime verdicts on nodes. Liveness at a use is re-derived by the matcher.

---

## 3. Guard proofs (typed)

Guards annotate branch edges with what the predicate **proves** on that edge:

```
NONNULL(O) / ISNULL(O)      -- an actual pointer null-test
VALUE(expr) REL const       -- a relational fact, e.g. VALUE(O.len) > LIMIT   (REL in <,<=,>,>=,==,!=)
BOUNDED(index, bound)        -- a range/bounds fact
... (extensible; atropos-driven)
```

`if (b->len > LIMIT)` proves `VALUE(O_buf.len) > LIMIT` on the true edge and
`VALUE(O_buf.len) <= LIMIT` on the false edge — **not** `NONNULL(b.len)` (`.len` is an int).
Reading `b->len` also emits `READ_STORAGE(O_buf, .len)` (requires `O_buf` live).

> Correction baked in: a value comparison on an int field is `VALUE(...)`, never a pointer
> `NONNULL`.

---

## 4. Source semantics — two separate properties (frozen)

```
SOURCE_REACHABLE(op, S)  : op can execute after entering through source S
SOURCE_INFLUENCED(op, S) : data/control/size/index/lifetime behaviour of op is influenced by S
```

- **Claus exploration gates on `SOURCE_REACHABLE`.** Reachable-but-uninfluenced behaviour is
  still explored: unconditional bugs in a handler, call-ordering bugs, cleanup/error paths
  that don't consume the input, global state from an earlier request, callback/event-loop
  behaviour, and entry-point triggers all stay in scope.
- **`SOURCE_INFLUENCED` is evidence, not a gate.** It (from pass-2 taint/influence) is
  retained per lead and drives ranking:

```
Tier 1: SOURCE_INFLUENCED and SOURCE_REACHABLE
Tier 2: SOURCE_REACHABLE, no proven influence
```

**v1 is source-only** — Claus launches only from discovered sources, so every lead is at least
`SOURCE_REACHABLE`. There is **no Tier 3** in v1: a "no known external source" tier could only
be populated by a non-source-rooted analysis, which v1 does not run. A later fallback
lifecycle-rooted coverage mode may reintroduce `Tier 3: discovered through fallback analysis,
no known external source` — deferred, not part of the frozen v1.

> Correction baked in: do **not** gate Claus on influence. Strict taint would drop
> `handle(input){ run_periodic_cleanup(); }` when the UAF lives in the unconditional callee.
> Correction baked in: Tier 3 cannot coexist with source-only exploration — if Claus starts
> only from sources, a "no known source" lead is unreachable by construction. Removed from v1.

---

## 5. Seams & fragments

- The skeleton is an **interprocedural graph**: per-function **fragments** joined by
  `seam_enter`/`seam_exit` edges. (The graph itself is not a PDA; the *matcher* performs
  pushdown reachability over it — §7.)
- A fragment is **symbolic** in its parameters and their generations. Binding happens at the
  seam: actuals→formals in, return→receiver out; heap effects done in the callee remain in
  the abstract heap and are imported through the return.
- **Source status comes from the callsite binding.** `make_buf(in)`'s `in` is symbolic; it
  becomes externally sourced only when bound to `handle(input)` — unless `make_buf` is itself
  a public input boundary.
- **`free(NULL)` is a no-op** — the reusable `FREE` fragment carries the `p != NULL` guard so
  reuse preserves the semantic condition.
- **Fragment caching** coexists with the abstract heap (it transforms the heap, does not
  replace it). "One fragment per function" is **provisional** until cache context-sensitivity
  is defined; the cache may be keyed by `(function, input-state abstraction)` with subsumption
  reuse (see `ARCH.md`).

---

## 6. Worked sample (the frozen reference)

```c
#define INITIAL_SIZE 32
typedef struct { char *data; int len; } Buf;

Buf *make_buf(char *in) {                 // in : SOURCE (via callsite binding)
    Buf *r = malloc(sizeof(Buf));         // ALLOC_ATTEMPT (O_buf)
    if (!r) return NULL;                  // failure arm returns NULL
    r->data = malloc(INITIAL_SIZE);       // ALLOC_ATTEMPT (O_payload) -> O_buf.data
    r->len  = parse_len(in);              // SOURCE in influences O_buf.len
    return r;
}
void free_buf(Buf *p) { free(p); }        // free(NULL) is a no-op

void handle(char *input) {                // input : SOURCE
    Buf *b = make_buf(input);
    if (!b) return;                       // NULL guard (fix #2)
    if (b->len > LIMIT) {                 // VALUE(O_buf.len) > LIMIT  (input-influenced)
        free_buf(b);                      // FREE O_buf
        log(b->data);                     // eval b->data = READ_STORAGE(freed O_buf) => UAF
    } else {
        b->data = realloc(b->data, 64);   // eval b->data (READ_STORAGE), then REALLOC_ATTEMPT
        log(b->data);
    }
}
```

### Fragments

```
FRAGMENT make_buf(in = Param(0))                       [in : SOURCE @ bind]
  m1 ALLOC_ATTEMPT -> r_raw
       ├ failure [ISNULL(r_raw)]  -> return NULL
       └ success [NONNULL(r_raw)] -> ORIGIN R_buf#g0 ; DERIVE r <- R_buf#g0   -> m2
  m2 ALLOC_ATTEMPT -> d_raw
       ├ failure [ISNULL(d_raw)]  -> WRITE_STORAGE R_buf#g0 .data <- NULL     -> m3
       └ success [NONNULL(d_raw)] -> ORIGIN R_pay#g0 ;
                                     WRITE_STORAGE R_buf#g0 .data <- R_pay#g0 -> m3
  m3 WRITE_STORAGE R_buf#g0 .len <- influence(in)      [SOURCE in -> O.len]
  m4 return ret = R_buf#g0

FRAGMENT free_buf(p = Param(0))
  f1 branch (p == NULL)
       ├ true  [ISNULL(p)]  -> return                  (free(NULL) no-op, preserved)
       └ false [NONNULL(p)] -> FREE p#G_p  [RELEASE|INVALIDATE] -> return

FRAGMENT handle(input = Param(0))                       [input : SOURCE]
  n1 seam_enter make_buf(input)   bind in <- input(SOURCE)
     seam_exit ret -> b           ⇒ b := R_buf#g0 (imported) ; R_buf.data slot -> R_pay#g0
  n2 branch (b == NULL)
       ├ true  [ISNULL(b)]  -> return
       └ false [NONNULL(b)] -> n3                        (NONNULL(b) holds downstream)
  n3 READ_STORAGE R_buf#g0 .len          -- deref R_buf to read .len (base must be live)
     branch (len > LIMIT)
       ├ true  [VALUE(R_buf.len) > LIMIT]  -> n4          (input-influenced)
       └ false [VALUE(R_buf.len) <= LIMIT] -> n7
  n4 seam_enter free_buf(b)  bind p <- R_buf#g0, G_p <- g0
       (callee NONNULL(p) arm) FREE R_buf#g0
     seam_exit -> n5
  n5 READ_STORAGE R_buf#g0 .data     -- eval `b->data` derefs FREED R_buf  => UAF (deref) ✓
     ; PASS_VALUE <loaded pointee> -> log   (log's own deref, if any, is in log's fragment)
     -> n6
  n7 -- evaluate the realloc argument FIRST: `b->data` is a load through R_buf
     READ_STORAGE R_buf#g0 .data ; DERIVE realloc_arg <- R_pay#g0
        (if R_buf were freed here, THIS read is the UAF, before realloc runs)
     REALLOC_ATTEMPT(realloc_arg = R_pay#g0, size 64) -> t_raw
       ├ success [NONNULL(t_raw)]  INVALIDATE R_pay#g0 ; ORIGIN R_pay#g1 ;
       │                           WRITE_STORAGE R_buf.data <- R_pay#g1 ;
       │                           READ_STORAGE R_buf.data -> R_pay#g1 ; PASS_VALUE R_pay#g1 -> log
       └ failure [ISNULL(t_raw)]   REALLOC_FAILED R_pay#g0 ;   (no INVALIDATE emitted)
       │                           WRITE_STORAGE R_buf.data <- NULL ; LOST_FROM_SLOT(R_buf.data, R_pay#g0)
       │                           READ_STORAGE R_buf.data -> NULL ; PASS_VALUE NULL -> log
       -> n6
  n6 merge -> exit
```

`n7` failure emits only facts (`REALLOC_FAILED`, `LOST_FROM_SLOT`, no invalidation). Whether
`R_pay#g0` leaks is a matcher conclusion (does any live alias reach it on this path?); whether
`log(NULL)` is a null-deref depends on log's fragment dereferencing the passed pointer — the
callsite alone proves only `PASS_VALUE NULL`.

### Matcher trace — the true-arm UAF (with continuation)

```
state = (skeleton_node, guard/path_ctx, pattern_phase, obj_bind, gen_bind, call_continuation)

n4 seam_enter: PUSH cont = <return -> n5> ; bind p<-R_buf, G_p<-g0 ; enter free_buf
   f : FREE p#G_p  ▸ under binding = FREE R_buf#g0   -> phase = RELEASE(R_buf, g0)
   seam_exit: POP cont -> return ONLY to n5    (pushdown: cannot surface at any other caller)
n5 READ_STORAGE base=R_buf#g0 .data
   ▸ base=R_buf, gen g0, released, no new-incarnation ORIGIN(R_buf) between => USE-AFTER-FREE ✓

else arm (n7): the reads are READ_STORAGE(base=R_buf, .data) with R_buf NOT freed on this arm,
   then PASS_VALUE of R_pay#g1 / NULL. No READ_STORAGE(base=R_buf) after FREE(R_buf) => no UAF of
   R_buf. The failure arm's LEAK and possible null-deref are separate matcher conclusions (§9).
```

### No-false-positive contrast (the base/pointee distinction)

```c
char *saved = b->data;   // READ_STORAGE R_buf.data (R_buf live here) ; DERIVE saved <- R_pay#g0
free_buf(b);             // FREE R_buf#g0
log(saved);              // PASS_VALUE R_pay#g0   (no deref of R_buf; R_pay never freed) => no UAF ✓
```

`saved` captured the pointee identity via `DERIVE`; `log(saved)` is `PASS_VALUE(R_pay)`, not a
`READ_STORAGE(base=R_buf)`. `FREE(R_buf)` matches only a later `READ_STORAGE`/`WRITE_STORAGE`
with `base=R_buf`, so this is correctly clean. (Had it been `saved[0]` after the free, that
would be `READ_STORAGE(base=R_pay, [0])` — still clean, since `R_pay` is not freed.)

---

## 7. The matcher — pushdown reachability with temporal progress

Separate stage over the finished skeleton graph. Evaluates loose ordered patterns as
reachability along a **single branch-compatible path**, with arbitrary intervening ops.

**Matcher state (frozen):**

```
(skeleton_node, guard/path_context, pattern_phase, object_bindings,
 generation_bindings, call_continuation)
```

**Discipline:**

- **Continuation (pushdown) — the most important piece.** `seam_enter` **pushes** the
  expected return site; `seam_exit` **pops** and may return **only** to that site. Shared
  callee fragments therefore cannot produce impossible enter-from-A / return-to-B paths.
- **Identity + generation.** A link requires the same object `O` and the same generation `G`.
  A new generation (successful `realloc`, alloc-site reuse, widened loop allocation) never links
  to the old. **Reassignment does not create a generation** (§1) — it only rebinds a name, so
  aliases across an assignment keep linking to the same generation.
- **Branch compatibility.** Links never cross opposite arms of one branch; guard proofs on
  the path constrain feasibility.
- **"Eventually" = reachable later on one compatible path**, not an index in a flattened list.

Advanced through a worklist; multiple patterns compile into shared, event-indexed transitions.

> Correction baked in: per-object linear scan is too weak; the matcher is graph reachability
> with temporal progress + object bindings + feasibility + a call continuation.

---

## 8. Emitted-fact vs matcher-conclusion boundary (frozen)

| Emitted by Claus (fact)                                  | Concluded by matcher (verdict)               |
|----------------------------------------------------------|----------------------------------------------|
| `RELEASE`, `READ_STORAGE`/`WRITE_STORAGE`, `PASS_VALUE`, generations | use-after-free, double-free       |
| `REALLOC_FAILED(O)`, `LOST_FROM_SLOT(slot,O)`, absence of `INVALIDATE(O)` | **leak** (path-specific, no live root reaches O @exit) |
| `ISNULL`/`NONNULL`/`VALUE` guard proofs on edges         | null-deref, missing-bounds                   |
| source tags, `SOURCE_REACHABLE`/`INFLUENCED`             | tier / exploitability ranking                |

The skeleton never stamps `O LIVE`/`O FREED`. Liveness on a path is a matcher conclusion,
derived from the presence/absence of `RELEASE`/`INVALIDATE`/`ORIGIN` events along that path.

Claus never labels a bug. Every verdict is a reachability query the matcher answers.

---

## 9. Patterns (illustrative; data-driven, not hard-coded in the engine)

All patterns are matched along **one compatible path P** (branch-feasible, continuation-consistent),
with `->*` = graph-reachable-later on P, `same O,G` on every link.

```
uaf.deref       : RELEASE(O) ->* READ_STORAGE(base=O,*) | WRITE_STORAGE(base=O,*)
                    with no ORIGIN(O, new incarnation) between      [dereference of a freed base]
use.dangling    : RELEASE(O) ->* PASS_VALUE(O) | COMPARE_VALUE(O) | RETURN_VALUE(O)
                    (weaker lead: using a dangling pointer value is UB, not a deref)
double-free     : RELEASE(O) ->* RELEASE(O)   with no ORIGIN(O, new incarnation) between
null-deref      : ISNULL(O) [or WRITE_STORAGE(slot,NULL) then DERIVE x<-that slot]
                    ->* READ_STORAGE(base=O,*) | WRITE_STORAGE(base=O,*)   [deref only; pass/compare do NOT count]
leak            : exists exit state on P where
                    ORIGIN(O) occurred on P,
                    no RELEASE(O) occurred afterward on P (release on ANOTHER branch does not count),
                    and no live root/alias reaches O at that exit on P
```

Notes: `uaf.deref` unifies the old storage/value split — every UAF *dereference* is a
`READ_STORAGE`/`WRITE_STORAGE` on the freed base (path `*`, `.field`, or `[i]`). Merely passing
or comparing a freed/NULL pointer is not a dereference — hence `use.dangling` is a separate,
weaker lead and `null-deref` requires an actual `READ_STORAGE`/`WRITE_STORAGE`. `leak` and the
"no RELEASE" side-conditions are **path-specific**: a release on a different, incompatible branch
does not discharge them.

Patterns are atropos data; the engine only supplies the substrate the matcher walks.

---

## 10. Build plan (6 phases, in order)

```
Phase 0  this doc (schema) — DONE
Phase 1  CORE: Claus fragment builder emitting a GRAPH
           - reuse object_state.py env/heap/generation machinery
           - emit graph (branches/merges/loops/seams), NOT a linear stream
           - NO baked-in detection (move UAF/double-free out of AbstractState.apply)
           - split events per §2.2; ALLOC_ATTEMPT/REALLOC_ATTEMPT outcomes per §2.1
Phase 2  fragment store + seam stitching (symbolic bind at seams, §5)
Phase 3  source-rooted driver (pass 3): SOURCE_REACHABLE scheduling + backward source
           discovery (formal->actual/return/influence) + launch Claus forward
Phase 4  continuation-aware reachability matcher (§7) — replaces match_universal
Phase 5  wire pipeline.py to this path + validate on the 35-bug fixture
```

Current code to refactor, not reuse blindly: `flow/emit.py` (linearizes — replace with graph
emitter), `flow/skeleton_ir.py::match_universal` (linear scan — replace with §7),
`flow/object_state.py` (keep the heap/generation/disjunct machinery; remove baked-in
findings), `flow/pipeline.py` (rewire entry from lifecycle-slice to source-rooted).

---

## 11. Resolved policy decisions

- **GC / managed-language mapping:** GC-managed objects do not receive synthetic
  `ORIGIN`/`RELEASE` ownership events and are not reported as C-style leaks. Only
  explicit resource roles declared by Atropos (for example `open`/`close`, stream
  destruction, or URL revocation) enter typestate. This keeps the skeleton
  language-neutral without pretending that collector reachability is an ownership
  proof.
- **Cached heap dependencies:** object-state artifacts are semantic inputs to
  fragment construction and are included in the fragment/snapshot cache identity.
  A changed heap artifact set therefore rebuilds the affected semantic graph
  rather than reusing stale object identities.

The v1 implementation has explicit decisions for the former loop and cache questions:

- Loop widening uses the bounded incarnation policy described in §2.3; it is tested as a
  may-analysis abstraction and does not claim one concrete generation per runtime iteration.
- Fragment cache identity fingerprints the complete semantic inputs (frontend graph, functions,
  summaries, language, and reach summaries), while coverage states/contexts use subsumption so
  disjoint source-rooted regions can be merged without claiming unmaterialized coverage.
