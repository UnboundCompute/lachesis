# Phase 1 — identity, the two name indices, and what `search` was hiding

Phase 1 changes no tool's response shape and adds no resolution. It makes three things
true that Phase 2 needs and that were not true before: a node's id depends only on its
own file, a name can be looked up instead of scanned for, and a name that means several
things says so.

## 1a. The one real identity violation

A Python call site's id was hashed over `"construct" if resolution.constructed_class
else "call"`. That classification comes from the whole-tree resolver — `Thing()` is a
construct only when `Thing` names a class, which the calling file cannot know when
`Thing` is imported. So turning a class into a function two files away silently renamed
a node somewhere else, and every cached answer keyed on that id was invalidated by an
edit that had nothing to do with it.

The fix passes the literal `"call"` to `stable_id` while the node still reports its real
`kind`. This is safe because nothing reads semantics back out of an id: only segments 1
and 2 (owner, namespace) are ever parsed, and `build_id_prefixes` treats the prefix as a
compression key. `IdentityFileLocalityTests` builds a two-file tree twice, changing only
the file that is *not* under test, and asserts the ids it emits are identical.

The same tests document a gap they do not fix: whether an `allocation` node **exists**
still depends on another file, because the Python frontend emits one only when the
resolver reports a constructed class. Its id is file-local, so §4 holds; node existence
is a Phase 5 question.

C and TypeScript pass the audit unchanged. Both use absolute resolved paths in ids where
Python uses a repo-relative one — file-local, so conformant, but it makes a C or TS store
non-portable between checkouts. Flagged, not fixed.

## 1b/1c. `decl_index` and `callsite_index`

`lachesis/indices.py` builds both as **pure functions of a node list**, and imports
nothing from the rest of the package — `core/overlays/dispatch.py` and
`nav/symbol_index.py` now import `last_name` and `INDEXED_KINDS` *from* it, so there is
one definition of each and `search` and the persisted index cannot drift apart.

They are built inside `write_kuzu_graph`, not `enrich_graph`: a store need not be
enriched (`cli/indexer.py` writes one with `enrich=False`) and the writer is the single
choke point every store passes through. Being a function of a node list is the point —
Phase 5's per-unit rebuild becomes a filter on the input rather than a second code path.

The three frontends spell a callee three ways (Python `callee_name`, C `callee` +
`method_name`, TypeScript the full callee *expression* + `method_name`), so
`callee_name()` prefers whatever the frontend already normalized and falls back to
`last_name` over the raw text. `signature` is `properties.signature or properties.type`
and is never synthesized.

`STORE_FORMAT_VERSION` goes 8 → 9, declaring **four** tables in one DDL — both indices
and Phase 2's two memo tables, the latter shipping empty — so Phases 1 and 2 cost users
one rebuild rather than two. `CACHE_VERSION` goes 1 → 2 in the same change, because 1a
alters node ids **without changing a source byte** and `CacheEntry.status()` compares
only `source_content_hash`: every existing cache entry would otherwise stay `"fresh"`
while holding a store whose ids the new code disagrees with.

`GraphIndex` and `KuzuGraphIndex` both grow `decl_index(name)` / `callsite_index(name)`,
and a test asserts they return equal structures — the same parity the store has always
been held to.

## 1d. What `search` was hiding

`search_page` already returned every homonym with a real `total`. The collapse is
`_seed` in `mcp_server.py`, which takes `hits[0]` and feeds eleven of the seventeen
tools, so a codebase with four `funcA`s reads through the tools like a codebase with
one. Rewiring that is Phase 3. Phase 1 adds a `homonyms` field to a hit whose name is
not unique, so an agent at least knows to pass a `node_id`. The field is absent when the
name is unique — its presence is the signal — and it is same-name only, never fuzzy.

`search` (the unpaged list form used by `_resolve` and seed resolution) is deliberately
untouched, so nothing that resolves a name changed behaviour.

## 1e. The homonym distribution, measured before the schema was fixed

`fixtures_homonym/` is two translation units each defining `static int funcA(int)` plus
a `shared.c` calling both entry points.

*(Corrected in Phase 2, where it was measured rather than assumed: this paragraph
originally claimed the C post-pass abandons both call sites. It does not. Both calls are
intra-TU, so clang resolves them and stamps `primary_target_id`; `sole_definition`'s
give-up on two same-named definitions is real but never reached here. The fixture's
actual value is that the **name** `funcA` is ambiguous while the **file** is not — which
is what Phase 2's second rung decides on, and what its `_blinded` variant tests.)*

The §10 measurement (`homonym_distribution.json`), run before committing to v9:

| | arachne (py+ts) | suricata `src/` (c) |
|---|---|---|
| nodes | 203,177 | 1,975,709 |
| distinct declaration names | 1,789 | 17,712 |
| declaration rows | 2,256 | 52,645 |
| call sites | 10,194 | 22,233 |
| worst name | `__init__` (49) | `SBB_RB_FIND` (**473**) |

Python's tail is mild and bounded. C's is not: nine `SBB_RB_*` names resolve to 473
declarations each — red-black-tree macros expanded `static` into every translation unit
that includes the header — and the `TCPSACK_RB_*` family to 183. It is a thin tail (50
of 22,233 call sites, 0.2%), and that is the argument *for* handling it rather than
against: rare enough to go unnoticed, large enough to matter when it does not.

So `ResolveMemo` carries a `truncated BOOLEAN` alongside `ConeMemo`'s, decided here
rather than after the version bump. A capped candidate list that cannot say it was
capped is a wrong answer rather than a partial one.

## Harness

The 1a id change moves `graph_content_hash`, so the equality harness dropped to
identity-relaxed mode and passed there — every golden row still present, keyed on the
id-free projection. The golden was then re-blessed against the same pinned corpus
(`git:644d9e8:lachesis`, unchanged) with the Phase 1 analyzer, and passes **strict**
again. Phase 2 rewires nothing, so it must stay strict.
