"""Shared process-tree resource policy for production analysis passes."""
from __future__ import annotations

import os
import sys


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
