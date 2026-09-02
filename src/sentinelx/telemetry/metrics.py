"""Bounded stage samples, cached telemetry and real processing-rate measurements."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from threading import RLock
from time import perf_counter, time

import numpy as np
import psutil


class MetricsCollector:
    def __init__(self, sample_limit: int = 2000) -> None:
        self.sample_limit = sample_limit
        self.packet_count = self.flow_updates = self.flow_count = self.byte_count = 0
        self.alert_count = self.parsed_packets = self.skipped_frames = 0
        self.feature_vectors = self.inference_vectors = self.inference_batches = 0
        self.evidence_decisions = self.out_of_order_packets = 0
        self.decisions: Counter = Counter()
        self.protocol_packets: Counter = Counter()
        self._latencies = defaultdict(lambda: deque(maxlen=sample_limit))
        self._lock = RLock()
        self._process = psutil.Process()
        self._process.cpu_percent(None)
        self._started = self._ended = None
        self._cpu_started = 0.0
        self._cpu_seconds = 0.0
        self.running = False
        self.paused = False
        self._paused_at = None
        self._pause_seconds = 0.0
        self._last_sample = perf_counter()
        self._last_counts = (0, 0, 0)
        self._rates = (0.0, 0.0, 0.0)
        self._rate_history = deque(maxlen=720)
        self.telemetry_interval = 0.25
        self._cached = None
        self._cache_at = 0.0
        self.capture_first = self.capture_last = None

    def begin(self) -> None:
        self._started = self._last_sample = perf_counter()
        self._ended = None
        self.running = True
        cpu = self._process.cpu_times()
        self._cpu_started = cpu.user + cpu.system
        self._last_counts = (self.packet_count, self.flow_count, self.byte_count)
        self._cache_at = 0

    def set_paused(self, paused: bool) -> None:
        now = perf_counter()
        if paused and not self.paused:
            self._paused_at = now
        elif not paused and self.paused and self._paused_at is not None:
            self._pause_seconds += now - self._paused_at
            self._paused_at = None
        self.paused = paused
        self._last_sample = now
        self._last_counts = (self.packet_count, self.flow_count, self.byte_count)
        self._cache_at = 0

    def finish(self) -> None:
        if self.paused:
            self.set_paused(False)
        self.sample_rates(force=True)
        self._ended = perf_counter()
        cpu = self._process.cpu_times()
        self._cpu_seconds = max(0, cpu.user + cpu.system - self._cpu_started)
        self.running = False
        self._cache_at = 0

    def sample_rates(self, *, force=False):
        now = perf_counter()
        with self._lock:
            elapsed = now - self._last_sample
            if elapsed <= 0 or (not force and elapsed < self.telemetry_interval):
                return
            counts = (self.packet_count, self.flow_count, self.byte_count)
            self._rates = tuple((current - old) / elapsed
                                for current, old in zip(counts, self._last_counts, strict=True))
            self._last_counts, self._last_sample = counts, now
            self._rate_history.append({
                "observed_at": time() * 1000, "bytes": counts[2], "packets": counts[0],
                "flows": counts[1], "flow_updates": self.flow_updates,
                "packets_per_second": self._rates[0], "flows_per_second": self._rates[1],
                "mbps": self._rates[2] * 8 / 1_000_000,
            })

    def record_packet(self, packet_length: int, capture_timestamp: float | None = None) -> None:
        self.packet_count += 1
        self.byte_count += packet_length
        if capture_timestamp is not None:
            if self.capture_first is None:
                self.capture_first = capture_timestamp
            self.capture_last = max(self.capture_last or capture_timestamp, capture_timestamp)

    def record_flow_update(self, is_new: bool = False) -> None:
        self.flow_updates += 1
        self.flow_count += int(is_new)

    def record_alert(self) -> None:
        self.alert_count += 1

    def record_latency(self, stage: str, milliseconds: float) -> None:
        with self._lock:
            self._latencies[stage].append(milliseconds)

    def snapshot(self, *, interval_seconds: float = 0.25, force: bool = False) -> dict:
        now = perf_counter()
        with self._lock:
            if not force and self._cached is not None and now - self._cache_at < interval_seconds:
                return self._cached
            if self.running and not self.paused:
                self.sample_rates()
            counts = (self.packet_count, self.flow_count, self.byte_count)
            rates = self._rates
            duration = max((self._ended or now) - self._started, 0) if self._started is not None else 0
            active_duration = max(duration - self._pause_seconds -
                                  (now - self._paused_at if self._paused_at is not None else 0), 0)
            observed_duration = max((self.capture_last or 0) - (self.capture_first or 0), 0)
            latencies = {}
            for stage, samples in self._latencies.items():
                if samples:
                    p50, p95 = np.percentile(list(samples), [50, 95])
                    latencies[stage] = {"p50": float(p50), "p95": float(p95), "samples": len(samples)}
            active = self.running and not self.paused
            self._cached = {
                "packets": self.packet_count, "parsed_packets": self.parsed_packets,
                "skipped_frames": self.skipped_frames, "out_of_order_packets": self.out_of_order_packets,
                "flow_updates": self.flow_updates, "flows": self.flow_count, "bytes": self.byte_count,
                "alerts": self.alert_count, "feature_vectors": self.feature_vectors,
                "inference_vectors": self.inference_vectors, "inference_batches": self.inference_batches,
                "evidence_decisions": self.evidence_decisions, "decisions": dict(self.decisions),
                "protocol_packets": dict(self.protocol_packets),
                "cpu_percent": self._process.cpu_percent(None),
                "memory_bytes": self._process.memory_info().rss, "latency_ms": latencies,
                "processing_rates": {"packets_per_second": rates[0] if active else 0,
                                     "flows_per_second": rates[1] if active else 0,
                                     "mbps": rates[2] * 8 / 1_000_000 if active else 0},
                "average_processing_rates": {
                    "packets_per_second": counts[0] / active_duration if active_duration else None,
                    "flows_per_second": counts[1] / active_duration if active_duration else None,
                    "mbps": counts[2] * 8 / 1_000_000 / active_duration if active_duration else None,
                },
                "capture_duration_seconds": observed_duration,
                "observed_average_mbps": counts[2] * 8 / 1_000_000 / observed_duration if observed_duration else None,
                "elapsed_seconds": duration, "active_seconds": active_duration,
                "cpu_seconds": self._cpu_seconds if self._ended is not None else None,
                "sampled_at": time(),
                "rate_samples": list(self._rate_history),
            }
            self._cache_at = now
            return self._cached
