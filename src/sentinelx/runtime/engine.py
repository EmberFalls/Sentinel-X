"""Incremental flow snapshots and short batched inference on one laptop."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter

from sentinelx.alerts.builder import build_alert
from sentinelx.alerts.dedupe import AlertDeduplicator
from sentinelx.config import ConfigBundle
from sentinelx.core.enums import ReplayMode, TransportProtocol
from sentinelx.core.schemas import CapabilityProfile, FeatureVector, FlowRecord
from sentinelx.detection.behaviour import BehaviourDetector
from sentinelx.detection.dns import DNSDetector
from sentinelx.detection.tls_quic import TLSQUICDetector
from sentinelx.evidence.gate import EvidenceGate
from sentinelx.features.behaviour import BehaviourFeatureExtractor
from sentinelx.features.dns import DNSFeatureExtractor
from sentinelx.features.tls_quic import TLSQUICFeatureExtractor
from sentinelx.flow.manager import FlowManager
from sentinelx.ingest.pcap import CaptureReader
from sentinelx.ingest.replay import ReplayController
from sentinelx.models.loader import load_model_package
from sentinelx.observation.capabilities import flow_capabilities
from sentinelx.parsing.packet import PacketParser
from sentinelx.state.manager import TemporalStateManager
from sentinelx.telemetry.metrics import MetricsCollector


@dataclass(slots=True)
class PendingInference:
    vector: FeatureVector
    flow: FlowRecord
    capabilities: CapabilityProfile
    queued_at: float


class SentinelEngine:
    def __init__(self, config: ConfigBundle) -> None:
        self.config = config
        self.parser = PacketParser()
        settings = config.defaults
        self.flows = FlowManager(settings.flow_idle_timeout_seconds,
                                 active_timeout_seconds=settings.flow_active_timeout_seconds,
                                 max_flows=settings.max_active_flows)
        self.state = TemporalStateManager(settings.temporal_windows_seconds,
                                          max_events=settings.max_temporal_events)
        self.behaviour_features = BehaviourFeatureExtractor()
        self.dns_features = DNSFeatureExtractor()
        self.tls_features = TLSQUICFeatureExtractor()
        self.metrics = MetricsCollector()
        self.dedupe = AlertDeduplicator(max_entries=settings.max_alerts * 2)
        self.evidence_gate = EvidenceGate(config.evidence.requirements,
                                          config.evidence.unknown_min_confidence)
        self.alerts = deque(maxlen=settings.max_alerts)
        self.alert_revision = 0
        self._load_errors = {}
        self.detectors = self._load_detectors()
        self._dirty = {}
        self._last_packets = {}
        self._last_snapshot_counts = {}
        self._pending = {family: [] for family in self.detectors}
        self._next_snapshot = None
        self._watermark: datetime | None = None
        self.mode = config.replay.mode

    def _package(self, family: str):
        entry = self.config.models.models[family]
        if not entry.enabled or entry.artifact_path is None:
            return None
        try:
            package = load_model_package(entry.artifact_path)
            if package.feature_schema.get("family") != family:
                raise ValueError("configured model belongs to a different feature family")
            return package
        except Exception as exc:
            # A missing/broken optional artifact must not prevent parser-only replay.
            self._load_errors[family] = str(exc)
            return None

    def _load_detectors(self):
        return {
            "behaviour": BehaviourDetector(self._package("behaviour")),
            "dns": DNSDetector(self._package("dns")),
            "tls_quic": TLSQUICDetector(self._package("tls_quic")),
        }

    def detector_status(self) -> list[dict]:
        statuses = []
        for name, detector in self.detectors.items():
            package = detector.package
            planned = not self.config.models.models[name].enabled
            statuses.append({
                "id": name, "enabled": detector.available,
                "status": "READY" if detector.available else "PLANNED" if planned else "UNAVAILABLE",
                "reason": None if detector.available else self._load_errors.get(
                    name, "Training deferred for the one-model prototype" if planned
                    else "No complete trained model package is available"),
                "model_version": package.model_version if package else None,
                "schema_version": package.feature_schema["schema_version"] if package else f"{name}.v1",
                "classes": list(package.classes) if package else [],
            })
        return statuses

    def _queue_flow(self, flow: FlowRecord, observed_at: datetime) -> list:
        packet_count = flow.packets_a_to_b + flow.packets_b_to_a
        if packet_count == self._last_snapshot_counts.get(flow.flow_id):
            return []
        self._last_snapshot_counts[flow.flow_id] = packet_count
        started = perf_counter()
        source = flow.initiator or flow.endpoint_a
        destination = flow.endpoint_b if source == flow.endpoint_a else flow.endpoint_a
        window = 60 if 60 in self.state.windows_seconds else self.state.windows_seconds[0]
        state = self.state.snapshot(str(source.ip), str(destination.ip), observed_at, window)
        capabilities = flow_capabilities(flow)
        vectors = [("behaviour", self.behaviour_features.extract(flow, state, capabilities))]
        packet = self._last_packets.get(flow.flow_id)
        if self.detectors["dns"].available and packet is not None and flow.dns_metadata:
            vectors.append(("dns", self.dns_features.extract(
                packet.model_copy(update={"dns_metadata": flow.dns_metadata}), state, capabilities)))
        if self.detectors["tls_quic"].available and (flow.tls_metadata or flow.quic_metadata):
            vectors.append(("tls_quic", self.tls_features.extract(flow, state, capabilities)))
        self.metrics.feature_vectors += len(vectors)
        self.metrics.record_latency("features", (perf_counter() - started) * 1000)
        emitted = []
        for family, vector in vectors:
            if not self.detectors[family].available:
                continue
            if family == "behaviour" and flow.protocol not in {TransportProtocol.TCP, TransportProtocol.UDP}:
                continue
            self._pending[family].append(PendingInference(vector, flow, capabilities, started))
            if len(self._pending[family]) >= self.config.defaults.inference_batch_size:
                emitted.extend(self._flush_family(family))
        return emitted

    def _flush_family(self, family: str) -> list:
        pending = self._pending[family]
        if not pending:
            return []
        self._pending[family] = []
        detector = self.detectors[family]
        started = perf_counter()
        verdicts = detector.detect_batch([job.vector for job in pending])
        elapsed_ms = (perf_counter() - started) * 1000
        self.metrics.inference_batches += 1
        self.metrics.inference_vectors += len(pending)
        self.metrics.record_latency("inference_batch", elapsed_ms)
        self.metrics.record_latency("inference", elapsed_ms / len(pending))
        emitted = []
        for job, verdict in zip(pending, verdicts, strict=True):
            started = perf_counter()
            threshold = detector.package.thresholds.get(verdict.threat_class.value)
            gate = self.evidence_gate.evaluate(verdict, job.capabilities, threshold)
            self.metrics.evidence_decisions += 1
            self.metrics.decisions[gate.decision.value if gate.decision else "NO_ALERT"] += 1
            self.metrics.record_latency("evidence", (perf_counter() - started) * 1000)
            started = perf_counter()
            alert = build_alert(
                verdict, gate, job.flow, severity_rules=self.config.severity.rules,
                total_pipeline_latency_ms=(perf_counter() - job.queued_at) * 1000,
                window_id=job.vector.window_id, capabilities=job.capabilities,
                class_threshold=threshold,
            )
            if alert and self.dedupe.accept(alert):
                self.alerts.append(alert)
                self.alert_revision += 1
                emitted.append(alert)
                self.metrics.record_alert()
            self.metrics.record_latency("alert", (perf_counter() - started) * 1000)
            self.metrics.record_latency("total_pipeline", (perf_counter() - job.queued_at) * 1000)
        return emitted

    def flush_due(self, *, force: bool = False) -> list:
        now, emitted = perf_counter(), []
        for family, pending in self._pending.items():
            if pending and (force or (now - pending[0].queued_at) * 1000 >= self.config.defaults.inference_batch_timeout_ms):
                emitted.extend(self._flush_family(family))
        return emitted

    def process_frame(self, timestamp: float, frame: bytes):
        if self.metrics._started is None:
            self.metrics.begin()
        sampled = self.mode is not ReplayMode.BENCHMARK or self.metrics.packet_count % 32 == 0
        started = perf_counter() if sampled else 0
        self.metrics.record_packet(len(frame), timestamp)
        packet = self.parser.parse(timestamp, frame)
        if sampled:
            self.metrics.record_latency("parse", (perf_counter() - started) * 1000)
        if packet is None:
            self.metrics.skipped_frames += 1
            return self.flush_due()
        if self._watermark is not None and packet.timestamp < self._watermark:
            self.metrics.out_of_order_packets += 1
            return self.flush_due()
        self._watermark = packet.timestamp
        self.metrics.parsed_packets += 1
        self.metrics.protocol_packets[packet.protocol.value] += 1
        started = perf_counter() if sampled else 0
        update = self.flows.process(packet, snapshot=False)
        if sampled:
            self.metrics.record_latency("flow", (perf_counter() - started) * 1000)
        self.metrics.record_flow_update(update.is_new_flow)
        started = perf_counter() if sampled else 0
        self.state.observe(packet, update)
        if sampled:
            self.metrics.record_latency("state", (perf_counter() - started) * 1000)
        self._last_packets[update.flow_id] = packet
        self._dirty[update.flow_id] = update.flow
        emitted = []
        for flow in update.expired:
            emitted.extend(self._queue_flow(flow, packet.timestamp))
            self._forget(flow.flow_id)
        current_time = packet.timestamp.timestamp()
        if self._next_snapshot is None:
            self._next_snapshot = current_time + self.config.defaults.snapshot_interval_seconds
        if current_time >= self._next_snapshot:
            for flow_id, flow in list(self._dirty.items()):
                if flow.packet_count >= self.config.defaults.snapshot_min_packets:
                    emitted.extend(self._queue_flow(flow.snapshot(), packet.timestamp))
                    self._dirty.pop(flow_id, None)
            self._next_snapshot = current_time + self.config.defaults.snapshot_interval_seconds
        emitted.extend(self.flush_due())
        if self.metrics.packet_count % 64 == 0:
            self.metrics.sample_rates()
        return emitted

    def _forget(self, flow_id):
        self._dirty.pop(flow_id, None)
        self._last_packets.pop(flow_id, None)
        self._last_snapshot_counts.pop(flow_id, None)

    def finish(self) -> list:
        emitted = []
        for flow in self.flows.flush():
            emitted.extend(self._queue_flow(flow, self._watermark or flow.last_seen))
            self._forget(flow.flow_id)
        emitted.extend(self.flush_due(force=True))
        self.metrics.finish()
        return emitted

    def run_controller(self, controller: ReplayController):
        self.mode = controller.mode
        self.metrics.telemetry_interval = (
            self.config.replay.benchmark_telemetry_interval_ms
            if self.mode is ReplayMode.BENCHMARK else self.config.replay.telemetry_interval_ms
        ) / 1000
        self.metrics.begin()
        idle_emitted = []
        def on_idle():
            idle_emitted.extend(self.flush_due())
        try:
            for frame in controller.frames(on_idle=on_idle):
                yield from idle_emitted
                idle_emitted.clear()
                yield from self.process_frame(frame.timestamp, frame.data)
            yield from idle_emitted
            yield from self.finish()
        except Exception:
            self.metrics.finish()
            raise

    def replay(self, capture: str | Path, *, mode: ReplayMode | None = None,
               speed_multiplier: float | None = None):
        controller = ReplayController(
            CaptureReader(capture), mode=mode or self.config.replay.mode,
            speed_multiplier=speed_multiplier or self.config.replay.speed_multiplier,
        )
        yield from self.run_controller(controller)

    def reset(self) -> None:
        self.flows.reset()
        self.state.reset()
        self.dedupe.reset()
        self.alerts.clear()
        self.alert_revision += 1
        self._dirty.clear()
        self._last_packets.clear()
        self._last_snapshot_counts.clear()
        for pending in self._pending.values():
            pending.clear()
        self._next_snapshot = self._watermark = None
        self.metrics = MetricsCollector()
