"""Opt-in function timing and call-count instrumentation for profiling."""
from __future__ import annotations

import atexit
import json
import os
import sys
import threading
import time
from functools import wraps


_enabled = os.environ.get("LACHESIS_TIMEIT", "").lower() not in {
    "", "0", "false", "no", "off"
}
_lock = threading.Lock()
_stats: dict[str, dict[str, float | int]] = {}
_local = threading.local()


def _record(name: str, elapsed: float, self_seconds: float) -> None:
    with _lock:
        row = _stats.setdefault(name, {
            "calls": 0, "total_seconds": 0.0, "self_seconds": 0.0,
            "max_seconds": 0.0,
        })
        row["calls"] += 1
        row["total_seconds"] += elapsed
        row["self_seconds"] += self_seconds
        row["max_seconds"] = max(row["max_seconds"], elapsed)


def timeit(func=None, *, name: str | None = None):
    """Decorate a function with call count, inclusive/self/max timings.

    It supports both ``@timeit`` and ``@timeit(name="short.label")``.  When
    ``LACHESIS_TIMEIT`` is unset, decoration returns the original function, so
    production runs pay no wrapper or clock overhead.
    """
    def decorate(target):
        if not _enabled:
            return target
        label = name or f"{target.__module__}.{target.__qualname__}"

        @wraps(target)
        def wrapped(*args, **kwargs):
            stack = getattr(_local, "stack", None)
            if stack is None:
                stack = []
                _local.stack = stack
            stack.append(0.0)
            started = time.perf_counter()
            try:
                return target(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - started
                child = stack.pop()
                if stack:
                    stack[-1] += elapsed
                _record(label, elapsed, elapsed - child)

        return wrapped

    return decorate(func) if func is not None else decorate


def report(*, limit: int = 100) -> dict:
    """Return rows ranked by self time, then inclusive time."""
    with _lock:
        rows = []
        for function, values in _stats.items():
            row = dict(values)
            calls = int(row["calls"])
            row["function"] = function
            row["average_seconds"] = (
                float(row["total_seconds"]) / calls if calls else 0.0)
            rows.append(row)
    rows.sort(key=lambda row: (row["self_seconds"], row["total_seconds"]), reverse=True)
    return {"enabled": _enabled, "functions": rows[:limit]}


def _write_report() -> None:
    if not _enabled:
        return
    payload = report()
    path = os.environ.get("LACHESIS_TIMEIT_REPORT")
    if path:
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
    else:
        print(json.dumps(payload), file=sys.stderr)


atexit.register(_write_report)

