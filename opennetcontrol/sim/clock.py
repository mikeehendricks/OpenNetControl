"""Controllable clock for the simulators' traffic model.

Real time plus an offset, so demos can start "in the past" and fast-forward without sleeping."""
from __future__ import annotations

import threading
import time


class SimClock:
    def __init__(self):
        self._lock = threading.Lock()
        self.offset = 0.0

    def now(self) -> float:
        return time.time() + self.offset

    def advance(self, seconds: float) -> float:
        with self._lock:
            self.offset += max(0.0, float(seconds))
        return self.now()

    def rewind_to(self, ts: float) -> None:
        with self._lock:
            self.offset = float(ts) - time.time()

    def reset(self) -> None:
        with self._lock:
            self.offset = 0.0


CLOCK = SimClock()
