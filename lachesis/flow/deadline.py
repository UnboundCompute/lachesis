"""A cooperative wall-clock budget for the flow pass.

Why cooperative rather than a signal or a watchdog: ``SIGALRM`` only fires on the main
thread, but the MCP server and any embedding host run the pass off-thread, so it would
raise "signal only works in main thread" or silently no-op; and a watchdog thread cannot
interrupt CPU-bound pure-Python. So the pass instead checks ``expired()`` at the phase
boundaries it already measures and at the object-analysis wave boundary (the dominant
cost), and on expiry returns the leads it has so far — it never raises. The budget bounds
*scheduling*, not a single in-flight function: one pathological function already running
cannot be preempted mid-transfer, so the granularity is a wave, not an instruction.

This lives in its own leaf module (no heavy imports) so ``pipeline`` and ``object_lifetime``
can both check a deadline without an import cycle; ``lachesis.session`` re-exports it as the
public ``Deadline`` name.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter


@dataclass(frozen=True)
class Deadline:
    """A wall-clock budget in seconds, counted from construction."""

    seconds: float
    _start: float = field(default_factory=perf_counter, compare=False)

    def expired(self) -> bool:
        return (perf_counter() - self._start) >= self.seconds

    def remaining(self) -> float:
        return max(0.0, self.seconds - (perf_counter() - self._start))

    @classmethod
    def of(cls, seconds: float | None) -> "Deadline | None":
        """Build a deadline, or ``None`` for an unbounded run (falsy/zero/negative)."""
        return cls(float(seconds)) if seconds and seconds > 0 else None
