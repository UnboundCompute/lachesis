"""Shared process-tree resource policy for production analysis passes."""
from __future__ import annotations

import os


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
