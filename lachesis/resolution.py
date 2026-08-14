"""Deciding what a call site calls, on demand, from a graph that is already written.

This is the lazy tier. Eager enrichment answers "what does this call" for every call
site in the tree whether or not anyone asks; the functions here answer it for *one*
call site, from the persisted graph plus the two name indices, in a dictionary hit.

It is deliberately **not** an overlay: it produces no ``GraphDelta``, it must be
callable without a fold, and Phase 4 wants it at build time as well as at query time.
It is deliberately not under ``nav/`` either, because ``nav`` imports *up* into
``lachesis`` and never the reverse. It types against a narrow structural protocol
(``nodes.get``, ``outgoing_of_kind``, ``nodes_owned_by``, ``decl_index``) so the same
code runs over the in-memory ``core.query.GraphIndex`` and the disk-backed
``nav.kuzu_index.KuzuGraphIndex`` without importing either.

**It does not replace the frontends' own resolution. It is a strict superset of it.**

That is the load-bearing decision. Each frontend resolves with information that never
reaches the canonical graph — TypeScript asks the compiler's checker for overload
selection, Python's resolver knows import bindings and the MRO, C's post-pass keys on
clang's per-run AST ids. A name-join reading only the persisted graph cannot reproduce
any of it, so a resolver that *replaced* those answers would lose edges, and losing an
edge is the one thing this project is not allowed to do. Step 1 of the ladder below is
therefore "believe the frontend", and everything after it only ever fires where the
frontend already gave up.

What the ladder legitimately adds is the case the C post-pass abandons: two translation
units each defining ``static int funcA(int)``. ``sole_definition`` sees two definitions,
returns ``None``, and both call sites stay ``dynamic-or-unresolved`` — even though C
scoping decides each one exactly, and file-locally. Step 2 is that case.

    1. primary_target_id, or a trusted INVOKES edge          -> exact
    2. a `static` declaration of the name in the same file   -> exact
    3. exactly one non-static definition project-wide        -> exact
    4. exactly one candidate under the name                  -> high
    5. more than one candidate                               -> conservative + all
    6. no candidate, but an indirect edge leaves the site    -> unresolved, edge kept
    7. nothing                                               -> unresolved, no candidates

Step 2 has to precede step 3 or a shadowed extern is labelled ``exact`` and is simply
wrong: the file-local ``static`` wins in C regardless of what else is linked in.

Nothing here removes an edge or contradicts one. A step-5 answer is a candidate list,
not a decision, and it says so in ``confidence``.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Protocol, runtime_checkable

from .indices import CALLSITE_KINDS, callee_name

# Step 1's trust set. The `resolution` vocabulary is the frontends' own: `exact` and
# `compiler-local` are clang deciding a call within a translation unit, `cross-tu` is
# the C post-pass joining a prototype to its definition, `binding` is a function
# pointer whose assignment was seen, `registration` is an ops-struct slot. Confidence
# is the second gate because Python and TypeScript label an edge's certainty there
# rather than in `resolution` — an `import-binding` INVOKES at confidence `exact` is
# every bit as decided as C's `cross-tu`, and refusing to believe it would send a
# perfectly resolved Python call down the name-join path to a *different* answer.
TRUSTED_RESOLUTIONS = frozenset(
    {"exact", "compiler-local", "cross-tu", "binding", "registration"}
)
TRUSTED_CONFIDENCES = frozenset({"exact", "high"})

# Edges that mean "this site calls that declaration".
INVOKE_KINDS = ("INVOKES", "CALLS")
# Edges that mean "this site reaches that declaration, but not by a decided call".
# Step 6 exists to keep them visible: an unresolved call with a MAY_INVOKE hanging off
# it is a *documented* miss, and reporting it as "nothing" would delete that.
INDIRECT_KINDS = ("MAY_INVOKE", "READS_CALLEE", "CONTEXT_CALLS")

# Declaration kinds a call can land on. Used to prefer the callable homonyms of a name
# over its variables — never to discard the others, because a name that only matches a
# variable is better reported as a conservative candidate than as nothing.
CALLABLE_KINDS = frozenset(
    {"function", "method", "constructor", "class", "macro", "interface"}
)

# How many candidates a conservative answer will carry. Measured, not guessed: on
# Suricata's `src/`, `SBB_RB_FIND` and eight siblings resolve to 473 declarations each
# (red-black-tree macros expanded `static` into every TU that includes the header) and
# the `TCPSACK_RB_*` family to 183. Fifty of 22,233 call sites (0.2%) exceed eight.
# The list is capped and the cap is *reported*: a truncated answer that cannot say it
# was truncated is a wrong answer rather than a partial one.
CANDIDATE_CAP = 64

# How many call sites naming one symbol `resolve_callers` will decide before it stops
# and says so. A different cap from CANDIDATE_CAP because it bounds a different thing:
# CANDIDATE_CAP bounds one answer's width, this bounds how much work one question buys.
# `get` and `len` name tens of thousands of sites, and resolving all of them to discover
# that ten mean *this* `get` is a bad trade for an interactive tool.
CALLER_SITE_CAP = 2048

# Two different defaults, on purpose. `resolve_decl` is one declaration's own call
# sites; `resolve_cone` walks. Sharing a default would let a caller who wanted the
# cheap question pay for the expensive one by accident.
DECL_DEPTH = 1
CONE_BUDGET = 256

# Steps 2 and 3 encode C's linkage rules, and only C has them. The frontend does not
# stamp a language on a node, so the file suffix is the signal — explicit and checkable,
# rather than inferring a language from the presence of a property.
C_SUFFIXES = (".c", ".h")


@runtime_checkable
class ResolutionIndex(Protocol):
    """The five things a resolver needs from an index, and nothing else."""

    nodes: Mapping[str, dict]

    def outgoing_of_kind(self, source: str, *edge_kinds: str) -> tuple: ...
    def nodes_owned_by(self, owner_id: str, *kinds: str) -> tuple: ...
    def decl_index(self, name: Optional[str] = None): ...
    def callsite_index(self, name: Optional[str] = None): ...


def owned_callsites(index: Any, node_id: str) -> tuple:
    """The call-site / construct nodes a declaration owns.

    Where a declaration's outgoing calls physically start, which is what makes
    ``resolve_decl`` a bounded question. ``nav.symbol_index`` imports this rather than
    keeping its own copy, so the set of nodes the resolver binds and the set the
    navigator reports indirect edges from is one set by construction.

    The kinds go *into* the index rather than being filtered out here. A function body
    is hundreds of nodes and a handful of them are calls; asking for all of them and
    discarding the rest meant a store-backed index fetched every local, every literal
    and every branch of every function `callees` walked, to answer a question about
    four call sites.
    """
    return index.nodes_owned_by(node_id, *CALLSITE_KINDS)


def _properties(node: Optional[Mapping]) -> Mapping:
    return (node or {}).get("properties") or {}


def _is_c(path: Optional[str]) -> bool:
    return bool(path) and str(path).endswith(C_SUFFIXES)


def _result(target, candidates, confidence, via, truncated=False) -> dict:
    return {
        "target": target,
        "candidates": tuple(candidates),
        "confidence": confidence,
        # Which rung answered. Not decoration: an `exact` from step 1 is the compiler's
        # word and an `exact` from step 2 is this module's reading of C scoping, and a
        # caller auditing a surprising edge needs to know which it is looking at.
        "via": via,
        "truncated": bool(truncated),
    }


class Resolver:
    """A memoizing resolver bound to one index.

    The memo is per-instance and in-process. It is *not* written into the store here:
    ``write_kuzu_graph`` is a one-shot writer with no append path, so a memo persisted
    on the way past would be keyed on a graph hash the writer had not finished
    computing. ``flush_memos`` is the deliberate, explicit way to put it on disk, and
    it stamps ``graph_hash`` on every row — the ``.enriched`` sidecar and the base
    store are two databases over two hashes, and a memo that crossed between them
    would be a confident wrong answer, which is worse than no memo at all.
    """

    def __init__(self, index: Any, graph_hash: str = "") -> None:
        self.index = index
        self.graph_hash = graph_hash or ""
        self._memo: dict[str, dict] = {}
        self._cone_memo: dict[tuple, dict] = {}

    # -- one call site -------------------------------------------------------

    def resolve(self, call_site_id: str) -> dict:
        """What this call site calls: a target, a candidate list, and a confidence.

        Idempotent by construction — the second call is the memo — and total: every
        input gets a result, because "unresolved with no candidates" is an answer and
        an exception is not.
        """
        cached = self._memo.get(call_site_id)
        if cached is not None:
            return cached
        result = self._resolve_uncached(call_site_id)
        self._memo[call_site_id] = result
        return result

    def _resolve_uncached(self, call_site_id: str) -> dict:
        node = self.index.nodes.get(call_site_id)
        if node is None:
            return _result(None, (), "unresolved", "unknown-node")
        properties = _properties(node)

        decided = self._step_one(call_site_id, properties)
        if decided is not None:
            return decided

        name = callee_name(node)
        if not name:
            return self._indirect_or_nothing(call_site_id)

        candidates = self._candidates(name)
        if candidates:
            path = properties.get("file")
            if _is_c(path):
                shadowing = self._static_in_file(candidates, path)
                if shadowing is not None:
                    return _result(shadowing, (shadowing,), "exact", "static-same-file")
                sole = self._sole_external_definition(candidates)
                if sole is not None:
                    return _result(sole, (sole,), "exact", "sole-definition")
            ids = tuple(row["node_id"] for row in candidates)
            if len(ids) == 1:
                return _result(ids[0], ids, "high", "sole-candidate")
            return _result(None, ids[:CANDIDATE_CAP], "conservative", "homonyms",
                           truncated=len(ids) > CANDIDATE_CAP)

        return self._indirect_or_nothing(call_site_id)

    # -- the rungs -----------------------------------------------------------

    def _step_one(self, call_site_id: str, properties: Mapping) -> Optional[dict]:
        """Believe the frontend. Everything below this only runs where it did not."""
        primary = properties.get("primary_target_id")
        if primary and self.index.nodes.get(primary) is not None:
            return _result(primary, (primary,), "exact", "primary-target")

        trusted: list[str] = []
        for edge in self.index.outgoing_of_kind(call_site_id, *INVOKE_KINDS):
            edge_properties = edge.get("properties") or {}
            if (edge_properties.get("resolution") in TRUSTED_RESOLUTIONS
                    or edge_properties.get("confidence") in TRUSTED_CONFIDENCES):
                target = edge.get("target")
                if target and target not in trusted:
                    trusted.append(target)
        if len(trusted) == 1:
            return _result(trusted[0], trusted, "exact", "invokes-edge")
        if trusted:
            # More than one edge the frontend called decided. Rare, and not this
            # module's to arbitrate — report all of them rather than pick.
            return _result(None, trusted[:CANDIDATE_CAP], "conservative",
                           "invokes-edges", truncated=len(trusted) > CANDIDATE_CAP)
        return None

    def _candidates(self, name: str) -> tuple:
        """Declaration rows under a name, callables first and nothing thrown away."""
        rows = tuple(self.index.decl_index(name) or ())
        callable_rows = tuple(row for row in rows if row.get("kind") in CALLABLE_KINDS)
        return callable_rows or rows

    def _static_in_file(self, candidates: Iterable[Mapping], path: str) -> Optional[str]:
        """The `static` definition of this name in this very file, if there is one.

        C's rule, and the whole reason this tier exists: internal linkage shadows
        everything else that answers to the name, no matter how many translation units
        also define it. Filtering on the file *first* is also what keeps the pathological
        case cheap — 473 same-named statics narrow to one before a single node is read.
        """
        same_file = [row for row in candidates if row.get("file") == path]
        statics = []
        for row in same_file:
            if row.get("declaration_only"):
                continue
            properties = _properties(self.index.nodes.get(row.get("node_id")))
            if properties.get("storage_class") == "static":
                statics.append(row["node_id"])
        return statics[0] if len(statics) == 1 else None

    def _sole_external_definition(self, candidates) -> Optional[str]:
        """The one non-static definition of the name in the whole tree, if unique.

        Only reached when the caller's own file holds no static shadow, so promoting
        it is exactly what the linker would do. Bounded by the cap because the answer
        is a *uniqueness* claim, and a uniqueness claim over a list this module refused
        to read in full would be a guess.
        """
        definitions = [row for row in candidates if not row.get("declaration_only")]
        if not definitions or len(definitions) > CANDIDATE_CAP:
            return None
        external = [
            row["node_id"] for row in definitions
            if _properties(self.index.nodes.get(row.get("node_id")))
            .get("storage_class") != "static"
        ]
        return external[0] if len(external) == 1 else None

    def _indirect_or_nothing(self, call_site_id: str) -> dict:
        """Step 6 then step 7 — a documented miss, or an honest empty one."""
        targets = [edge.get("target")
                   for edge in self.index.outgoing_of_kind(call_site_id, *INDIRECT_KINDS)
                   if edge.get("target")]
        if targets:
            return _result(None, tuple(dict.fromkeys(targets))[:CANDIDATE_CAP],
                           "unresolved", "indirect",
                           truncated=len(targets) > CANDIDATE_CAP)
        return _result(None, (), "unresolved", "none")

    # -- one declaration, and a cone ----------------------------------------

    def resolve_decl(self, node_id: str, depth: int = DECL_DEPTH) -> dict:
        """``{call_site_id: result}`` for the call sites this declaration owns.

        At the default depth that is exactly the declaration's own body and nothing
        else — the cheap question, and the one a tool asking "what does this call"
        actually needs. Higher depths follow decided targets into their bodies.
        """
        results: dict[str, dict] = {}
        frontier = [node_id]
        visited = {node_id}
        for _ in range(max(1, int(depth))):
            following: list[str] = []
            for declaration in frontier:
                for site in owned_callsites(self.index, declaration):
                    site_id = site.get("id")
                    if not site_id or site_id in results:
                        continue
                    result = self.resolve(site_id)
                    results[site_id] = result
                    target = result["target"]
                    if target and target not in visited:
                        visited.add(target)
                        following.append(target)
            frontier = following
            if not frontier:
                break
        return results

    def resolve_callers(self, node_id: str,
                        cap: int = CALLER_SITE_CAP) -> dict:
        """The call sites that resolve to this declaration: ``{sites, truncated}``.

        The forward direction can afford to be exhaustive because a call site names one
        callee. The reverse cannot: a name is not an identity, so the only sites worth
        asking about are the ones that *mention* this declaration's name, which is
        exactly what ``callsite_index`` is for. Every mention is then put through the
        same ladder as the forward question and kept only if the ladder lands here — so
        a homonym's callers never leak into its twin's, which is the whole point.

        A site whose answer is a conservative candidate list containing this node is
        kept too, and its result says so. Dropping it would report "nothing calls this"
        about a site that demonstrably might, and a confident absence is the one answer
        this module is not allowed to give.
        """
        node = self.index.nodes.get(node_id)
        name = str((node or {}).get("label") or "")
        if not name:
            return {"sites": {}, "truncated": False}
        mentions = tuple(self.index.callsite_index(name) or ())
        truncated = len(mentions) > cap
        sites: dict[str, dict] = {}
        for row in mentions[:cap]:
            site_id = row.get("node_id")
            if not site_id or site_id in sites:
                continue
            result = self.resolve(site_id)
            if result["target"] == node_id or node_id in result["candidates"]:
                sites[site_id] = result
        return {"sites": sites, "truncated": truncated}

    def resolve_cone(self, node_id: str, budget: int = CONE_BUDGET) -> dict:
        """Every declaration reachable by decided calls from here, budget-stopped.

        Breadth-first over ``resolve_decl``, mirroring ``planner.dominance.call_closure``
        — cycle-safe through ``members``, and the budget is a *stop* rather than a
        filter, so ``truncated`` means "there was more" and never "some was skipped".
        The apex is a member of its own cone; a cone that did not contain its entry
        would make ``members`` mean something different from "what this reaches".
        """
        key = (node_id, int(budget))
        cached = self._cone_memo.get(key)
        if cached is not None:
            return cached
        members = {node_id}
        frontier = [node_id]
        truncated = False
        while frontier and not truncated:
            following: list[str] = []
            for declaration in frontier:
                for result in self.resolve_decl(declaration).values():
                    target = result["target"]
                    if not target or target in members:
                        continue
                    if len(members) >= budget:
                        truncated = True
                        break
                    members.add(target)
                    following.append(target)
                if truncated:
                    break
            frontier = following
        cone = {"members": frozenset(members), "truncated": truncated}
        self._cone_memo[key] = cone
        return cone

    # -- persistence ---------------------------------------------------------

    def memo_rows(self) -> tuple[list, list]:
        """The memo as the two v9 tables want it: ``(resolve_rows, cone_rows)``.

        Candidate lists and cone members go in as newline-joined ids rather than as
        coded ones. The prefix table is sealed when the store is written and a memo is
        appended long after; encoding against a sealed table would either need it
        reopened or silently drop an id that has no prefix, and a memo is not worth
        either.
        """
        resolve_rows = [
            {"graph_hash": self.graph_hash, "node_id": node_id,
             "target": result["target"], "candidates": "\n".join(result["candidates"]),
             "confidence": result["confidence"], "truncated": result["truncated"]}
            for node_id, result in sorted(self._memo.items())
        ]
        cone_rows = [
            {"graph_hash": self.graph_hash, "node_id": node_id, "budget": budget,
             "members": "\n".join(sorted(cone["members"])),
             "truncated": cone["truncated"]}
            for (node_id, budget), cone in sorted(self._cone_memo.items())
        ]
        return resolve_rows, cone_rows

    def flush_memos(self, db_dir: str) -> int:
        """Append the memo to a store's ``ResolveMemo`` / ``ConeMemo``. Rows written.

        Best-effort by design: a store opened read-only, a store older than v9, or no
        ``kuzu`` at all are all reasons to have no memo, and none of them are reasons
        to fail a query that has already been answered correctly in memory. The
        in-process memo is the contract; this is the optimization.
        """
        resolve_rows, cone_rows = self.memo_rows()
        if not resolve_rows and not cone_rows:
            return 0
        try:
            import kuzu

            from .kuzu_store import db_file

            connection = kuzu.Connection(kuzu.Database(db_file(db_dir)))
        except Exception:
            return 0
        written = 0
        try:
            written += _append_memo(connection, "ResolveMemo", resolve_rows)
            written += _append_memo(connection, "ConeMemo", cone_rows)
        except Exception:
            # A partially appended memo is still a correct memo: every row carries its
            # own graph_hash and node_id, and a reader takes rows it recognizes.
            pass
        return written


def _append_memo(connection, table: str, rows: list) -> int:
    """Insert rows after the table's current high-water ``seq``. Rows inserted."""
    if not rows:
        return 0
    result = connection.execute(f"MATCH (r:{table}) RETURN max(r.seq)")
    high = 0
    if result.has_next():
        value = result.get_next()[0]
        high = int(value) + 1 if value is not None else 0
    for offset, row in enumerate(rows):
        columns = ", ".join(f"{name}: ${name}" for name in row)
        connection.execute(
            f"CREATE (:{table} {{seq: $seq, {columns}}})",
            {"seq": high + offset, **row},
        )
    return len(rows)


# -- the free-function surface ----------------------------------------------
#
# The plan's signatures are `resolve(index, call_site_id)`, and a caller that has an
# index in hand should not have to know that memoization needs somewhere to live. The
# resolver is cached on the index's own `__dict__` — written directly because
# `GraphIndex.__getattr__` raises for anything outside its bucket names — so repeated
# free-function calls over one index share one memo, which is what makes `resolve`
# idempotent in cost as well as in value.


def resolver_for(index: Any, graph_hash: str = "") -> Resolver:
    """The resolver bound to this index, created once and reused."""
    existing = index.__dict__.get("_resolver")
    if existing is not None and (not graph_hash or existing.graph_hash == graph_hash):
        return existing
    resolver = Resolver(index, graph_hash)
    index.__dict__["_resolver"] = resolver
    return resolver


def resolve(index: Any, call_site_id: str) -> dict:
    return resolver_for(index).resolve(call_site_id)


def resolve_decl(index: Any, node_id: str, depth: int = DECL_DEPTH) -> dict:
    return resolver_for(index).resolve_decl(node_id, depth)


def resolve_callers(index: Any, node_id: str, cap: int = CALLER_SITE_CAP) -> dict:
    return resolver_for(index).resolve_callers(node_id, cap)


def resolve_cone(index: Any, node_id: str, budget: int = CONE_BUDGET) -> dict:
    return resolver_for(index).resolve_cone(node_id, budget)


__all__ = [
    "CALLER_SITE_CAP", "CANDIDATE_CAP", "CONE_BUDGET", "DECL_DEPTH",
    "Resolver", "ResolutionIndex", "owned_callsites",
    "resolve", "resolve_callers", "resolve_cone", "resolve_decl", "resolver_for",
]