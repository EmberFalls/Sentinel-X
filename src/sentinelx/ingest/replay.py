"""Interruptible timing and progress for passive capture replay."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Iterator

from sentinelx.core.enums import ReplayMode
from sentinelx.ingest.pcap import CaptureReader, PcapFrame


class ReplayController:
    def __init__(
        self, adapter: CaptureReader, *, mode: ReplayMode = ReplayMode.PACED,
        speed_multiplier: float = 1.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if not math.isfinite(speed_multiplier) or speed_multiplier <= 0:
            raise ValueError("speed_multiplier must be finite and positive")
        self.adapter = adapter
        self.mode = ReplayMode(mode)
        self.speed_multiplier = speed_multiplier
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._condition = threading.Condition()
        self._paused = False
        self._stopped = False
        self.processed_bytes = 0
        self.completed = False

    @property
    def paused(self) -> bool:
        with self._condition:
            return self._paused

    @property
    def stopped(self) -> bool:
        with self._condition:
            return self._stopped

    @property
    def progress(self) -> float:
        if self.completed:
            return 1.0
        return min(self.processed_bytes / max(self.adapter.size_bytes, 1), 0.9999)

    def pause(self) -> None:
        with self._condition:
            self._paused = True
            self._condition.notify_all()

    def resume(self) -> None:
        with self._condition:
            self._paused = False
            self._condition.notify_all()

    def stop(self) -> None:
        with self._condition:
            self._stopped = True
            self._condition.notify_all()

    def reset(self) -> None:
        with self._condition:
            self._paused = False
            self._stopped = False
            self.processed_bytes = 0
            self.completed = False
            self._condition.notify_all()

    def _wait(self, delay: float, on_idle: Callable[[], None] | None) -> bool:
        remaining = max(delay, 0.0)
        while True:
            with self._condition:
                while self._paused and not self._stopped:
                    self._condition.wait()
                if self._stopped:
                    return False
                if remaining <= 1e-9:
                    return True
                started = self._monotonic()
                duration = min(remaining, 0.05)
                if self._sleeper is None:
                    self._condition.wait(timeout=duration)
                else:
                    self._sleeper(duration)
                remaining -= max(self._monotonic() - started, 0.0)
            if on_idle and not self.paused and not self.stopped:
                on_idle()

    def frames(self, on_idle: Callable[[], None] | None = None) -> Iterator[PcapFrame]:
        previous_capture_time: float | None = None
        previous_wall_time: float | None = None
        for frame in self.adapter.frames():
            delay = 0.0
            if self.mode is ReplayMode.PACED and previous_capture_time is not None:
                delay = max(frame.timestamp - previous_capture_time, 0) / self.speed_multiplier
                if previous_wall_time is not None:
                    delay -= self._monotonic() - previous_wall_time
            if not self._wait(delay, on_idle):
                return
            previous_wall_time = self._monotonic()
            yield frame
            self.processed_bytes = frame.file_offset
            previous_capture_time = frame.timestamp
        self.completed = not self.stopped
