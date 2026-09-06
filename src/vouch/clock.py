"""Injectable clocks.

Wall-clock time is an input, not an ambient fact. Every component that needs
"now" is handed a Clock, which keeps the harness deterministic and
replayable in tests. The one documented exception is the timeout mechanism
in :mod:`vouch.executor`: it must use real elapsed time because it races a
worker thread.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float: ...


class SystemClock:
    """Real wall-clock time."""

    def now(self) -> float:
        return time.time()


class ManualClock:
    """A clock the caller advances by hand. Used in tests and the adversary."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> float:
        self._t += float(seconds)
        return self._t
