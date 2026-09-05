"""Shared process-tree resource policy for production analysis passes."""
from __future__ import annotations

import os
import sys
from typing import Optional


DEFAULT_MEMORY_BUDGET_MB = 5120
MIN_MEMORY_BUDGET_MB = 1024


def memory_budget_mb() -> int:
    """Return the configured total process-tree memory budget in MiB."""
    raw = os.environ.get("LACHESIS_MEMORY_BUDGET_MB", str(DEFAULT_MEMORY_BUDGET_MB))
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError("LACHESIS_MEMORY_BUDGET_MB must be an integer MiB count") from error
    if value < MIN_MEMORY_BUDGET_MB:
        raise ValueError(
            f"LACHESIS_MEMORY_BUDGET_MB must be at least {MIN_MEMORY_BUDGET_MB}")
    return value


def typescript_heap_mb() -> int:
    """Bound V8 old-space while reserving memory for Node and its parent process."""
    budget = memory_budget_mb()
    ceiling = max(512, budget * 7 // 10)
    raw = os.environ.get("LACHESIS_TS_MAX_OLD_SPACE_MB", str(ceiling))
    try:
        configured = int(raw)
    except ValueError as error:
        raise ValueError("LACHESIS_TS_MAX_OLD_SPACE_MB must be an integer MiB count") from error
    return min(max(512, configured), ceiling)


def typescript_stack_kb() -> int:
    """V8 main-thread call-stack ceiling (KiB) for the TS/JS frontend.

    The default Node/V8 stack (~984 KiB) overflows on very large *single*
    bundled source files: the compiler frontend descends the AST recursively
    (`ts.forEachChild`), and a deeply nested bundle drives that recursion past
    the stack guard, aborting the whole build with SIGABRT (exit -6) before any
    graph is produced. Raising ``--stack-size`` gives the descent proportionally
    more headroom, so files that used to abort now parse.

    The ceiling must stay below the OS thread stack or a real overflow segfaults
    instead of unwinding. macOS pins the main-thread stack at 8 MiB regardless of
    RLIMIT_STACK, so we cap conservatively there; on Linux the frontend child
    raises RLIMIT_STACK (see ``core/runner.py``) so a much larger stack is backed
    by real OS stack. ``LACHESIS_TS_STACK_KB`` overrides the default.
    """
    ceiling = 7168 if sys.platform == "darwin" else 65536
    raw = os.environ.get("LACHESIS_TS_STACK_KB", str(ceiling))
    try:
        configured = int(raw)
    except ValueError as error:
        raise ValueError("LACHESIS_TS_STACK_KB must be an integer KiB count") from error
    return max(984, configured)


def c_chunk_files() -> int:
    """Translation units to compile per C-frontend process before starting a fresh one.

    The native C frontend holds its whole invocation's symbol/edge working set in
    memory, so a single process over a Linux-scale tree (tens of thousands of TUs)
    exhausts RAM. Splitting the roots into bounded chunks and compiling each in a
    fresh process caps the frontend's peak resident set at roughly one chunk's cost;
    the store-write pass stitches the per-chunk shard sets back into one graph, so
    the emitted graph is independent of the chunk boundary (only its peak memory is
    not). ``LACHESIS_C_CHUNK_FILES`` overrides the derived value.

    The default is derived from the process-tree memory budget using the measured
    marginal cost of the C frontend (~1.15 MiB resident per TU over a ~350 MiB base).
    The frontend is allotted ~55% of the budget so the store-write half and the
    Python parent keep headroom, which is comfortably above the single-chunk size of
    a typical project (so small and mid-size trees still build in one process,
    byte-for-byte as before) while forcing a Linux-scale tree to split.
    """
    raw = os.environ.get("LACHESIS_C_CHUNK_FILES")
    if raw is not None:
        try:
            value = int(raw)
        except ValueError as error:
            raise ValueError("LACHESIS_C_CHUNK_FILES must be a positive integer") from error
        if value < 1:
            raise ValueError("LACHESIS_C_CHUNK_FILES must be a positive integer")
        return value
    frontend_base_mb = 350.0
    frontend_marginal_mb_per_tu = 1.15
    frontend_share = 0.55
    allotment = memory_budget_mb() * frontend_share - frontend_base_mb
    derived = int(allotment / frontend_marginal_mb_per_tu)
    return max(250, derived)


def kuzu_buffer_pool_bytes() -> int:
    """Return a bounded Kùzu buffer-pool size in bytes derived from the budget.

    Kùzu's ``0`` default auto-sizes the buffer pool from *host* physical memory,
    so the store-write phase of a build grabs a fixed fraction of the machine's
    RAM regardless of the configured budget -- the pool becomes the dominant,
    host-scaled term of the build's peak and, on a Linux-scale graph, an OOM
    risk on a large host. The pool is a page cache over the on-disk store, not a
    correctness input: bounding it only trades some eviction/I/O for a hard RSS
    ceiling, and the emitted graph is byte-for-byte identical (verified: the
    store manifest content hash is unchanged when the pool is capped).

    The pool is allotted ~40% of the process-tree budget so the store-write
    half's Arrow/protobuf staging transients and the Python parent keep headroom
    under the same budget. ``LACHESIS_KUZU_BUFFER_POOL_SIZE`` (an explicit byte
    count) overrides the derived value, exactly as ``LACHESIS_C_CHUNK_FILES``
    overrides the derived chunk size.
    """
    raw = os.environ.get("LACHESIS_KUZU_BUFFER_POOL_SIZE", "")
    if raw:
        try:
            value = int(raw)
        except ValueError as error:
            raise ValueError(
                "LACHESIS_KUZU_BUFFER_POOL_SIZE must be an integer byte count") from error
        if value < 0:
            raise ValueError("LACHESIS_KUZU_BUFFER_POOL_SIZE must be non-negative")
        return value
    derived = memory_budget_mb() * 4 // 10
    return max(256, derived) << 20


def kuzu_max_db_size() -> Optional[int]:
    """Return an override for Kùzu's maximum on-disk database size, or ``None``.

    Kùzu reserves its store's address space by ``mmap``-ing a sparse file at a
    fixed maximum size (8 TiB by default) when the database is opened; the file
    stays sparse, so this costs no physical memory and never limits a real graph.
    Some constrained hosts -- notably CI runners inside a VM/container -- cannot
    satisfy an ``mmap`` of that span regardless of overcommit settings, and the
    open fails with ``Mmap for size 8796093022208 failed`` before a single row is
    written. ``LACHESIS_KUZU_MAX_DB_SIZE`` (an explicit byte count, which Kùzu
    requires to be a power of two) lowers the reservation to a size the host can
    map. It is a reservation ceiling, not a correctness input: any value that
    exceeds the store's actual footprint yields a byte-identical graph, so this
    changes nothing for a run that never sets it.

    Unset returns ``None`` so the open keeps Kùzu's own default -- production
    behaviour is unchanged unless the env is deliberately provided.
    """
    raw = os.environ.get("LACHESIS_KUZU_MAX_DB_SIZE", "")
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(
            "LACHESIS_KUZU_MAX_DB_SIZE must be an integer byte count") from error
    if value <= 0:
        raise ValueError("LACHESIS_KUZU_MAX_DB_SIZE must be positive")
    return value


def defer_translation_facts(substrate_bytes: int) -> bool:
    """Return whether to skip writing ``.pass2.facts.pb`` at build time.

    The translation-facts projection (``sidecar_to_translation``) rebuilds a
    whole-graph, string-keyed map of every node/edge in the substrate, so its
    peak resident set grows O(graph) -- on a Linux-scale tree it is the dominant
    build spike and an OOM risk. The file is redundant on disk for correctness:
    the native semantic pass recomputes it from the substrate with the *identical*
    producer when it is absent (byte-for-byte equivalent), so deferring only moves
    the cost out of the build and into the first ``enrich``, where it runs in an
    isolated worker instead of stacking on the store-write transients.

    ``LACHESIS_DEFER_TRANSLATION_FACTS`` forces the choice (``1``/``0``); unset
    auto-defers once the projection's *estimated* peak would exceed the build
    budget, so small builds keep writing the file exactly as before (their build
    artifacts stay byte-identical) while a large graph defers before it can OOM.
    The estimate scales the on-disk substrate size by a measured blow-up factor:
    the string-keyed whole-graph map peaks at ~26x the framed substrate (3449 MiB
    resident over a 134 MiB substrate, t4000). The factor is rounded up to bias
    toward deferring rather than OOMing, and is only a trigger heuristic -- the
    emitted graph and recomputed facts are byte-identical either way.
    """
    raw = os.environ.get("LACHESIS_DEFER_TRANSLATION_FACTS", "")
    if raw:
        if raw in {"0", "false", "no"}:
            return False
        if raw in {"1", "true", "yes"}:
            return True
        raise ValueError(
            "LACHESIS_DEFER_TRANSLATION_FACTS must be one of 1/0/true/false/yes/no")
    translate_blowup = 28  # substrate bytes -> translate-map peak, rounded up from ~26x
    estimated_peak_mb = (substrate_bytes >> 20) * translate_blowup
    return estimated_peak_mb > memory_budget_mb()


def frontend_jobs() -> int:
    """Return bounded compiler concurrency; serial is the memory-safe default."""
    raw = os.environ.get("LACHESIS_FRONTEND_JOBS", "1")
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError("LACHESIS_FRONTEND_JOBS must be a positive integer") from error
    if value < 1:
        raise ValueError("LACHESIS_FRONTEND_JOBS must be a positive integer")
    return value
