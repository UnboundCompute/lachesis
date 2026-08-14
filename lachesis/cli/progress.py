#!/usr/bin/env python3
"""Progress reporting for the long operations, on stderr, out of the way of stdout.

A first index of a real repository takes minutes. Two minutes of silence reads as a
hang, so the rule here is that something moves on the terminal for as long as work is
happening, and that nothing at all is written when stderr is not a terminal — a CI log
does not want a spinner, and a pipe does not want cursor control. stdout is never
touched: `lachesis scan --json | jq` has to stay clean while the build narrates.
"""
from __future__ import annotations

import itertools
import os
import sys
import threading
import time

_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _interactive() -> bool:
    # NO_COLOR is about colour, not motion, but a caller setting it is telling us the
    # terminal is being read by something that wants plain text; TERM=dumb says the
    # same. Either way the answer is the same: print lines, not frames.
    return (sys.stderr.isatty()
            and os.environ.get("TERM") not in (None, "", "dumb")
            and not os.environ.get("NO_COLOR"))


class Progress:
    """One phase at a time, each with a spinner while it runs and a mark when it ends.

    Not a percentage bar: the honest unit of a compile is the phase, and inventing a
    denominator we cannot know ("47%") is worse than an elapsed clock that is true.
    """

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled and not os.environ.get("LACHESIS_NO_PROGRESS")
        self._animate = self.enabled and _interactive()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._label = ""
        self._started = 0.0

    def phase(self, label: str) -> None:
        """End the running phase, if any, and begin a new one."""
        self.done()
        if not self.enabled:
            return
        self._label = label
        self._started = time.monotonic()
        if self._animate:
            self._stop.clear()
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"  {label} ...", file=sys.stderr, flush=True)

    def done(self, mark: str = "✓") -> None:
        if not self.enabled or not self._label:
            return
        elapsed = time.monotonic() - self._started
        if self._thread is not None:
            self._stop.set()
            self._thread.join()
            self._thread = None
            self._clear()
        print(f"  {mark} {self._label} ({elapsed:.1f}s)", file=sys.stderr, flush=True)
        self._label = ""

    def fail(self) -> None:
        self.done(mark="✗")

    def note(self, message: str) -> None:
        """A line that is not a phase — a count, a cache hit, a warning."""
        if not self.enabled:
            return
        interrupted = self._label and self._thread is not None
        if interrupted:
            self._stop.set()
            self._thread.join()  # type: ignore[union-attr]
            self._clear()
        print(f"  {message}", file=sys.stderr, flush=True)
        if interrupted:
            self._stop.clear()
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()

    def _clear(self) -> None:
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()

    def _spin(self) -> None:
        for frame in itertools.cycle(_FRAMES):
            if self._stop.is_set():
                return
            elapsed = time.monotonic() - self._started
            sys.stderr.write(f"\r\033[2K  {frame} {self._label} ({elapsed:.0f}s)")
            sys.stderr.flush()
            # Long enough that the clock is readable, short enough that the spin looks
            # continuous. The stop event is what actually ends this, not the timeout.
            if self._stop.wait(0.1):
                return

    def __enter__(self) -> "Progress":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.fail()
        else:
            self.done()
