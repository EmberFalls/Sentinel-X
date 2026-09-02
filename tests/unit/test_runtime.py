"""Scheduling tests use an explicit test-only detector, never a shipped model."""

import socket
from pathlib import Path
from types import SimpleNamespace

import dpkt

from sentinelx.config import load_config_bundle
from sentinelx.core.enums import AlertDecision, ThreatClass
from sentinelx.core.schemas import DetectorVerdict
from sentinelx.runtime.engine import SentinelEngine


def frame(port=50000):
    tcp = dpkt.tcp.TCP(sport=port, dport=443, flags=dpkt.tcp.TH_ACK, data=b"test")
    tcp.off = 5
    ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.9"), dst=socket.inet_aton("10.0.0.1"),
                    p=6, ttl=64, data=tcp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"a" * 6, dst=b"b" * 6, type=0x800, data=ip))


def config():
    bundle = load_config_bundle(Path(__file__).resolve().parents[2] / "configs")
    for name, entry in bundle.models.models.items():
        bundle.models.models[name] = entry.model_copy(update={"artifact_path": None})
    return bundle


class TestOnlyDetector:
    """Fixed scheduling fixture; not training data, not a runtime fallback."""
    __test__ = False
    available = True
    package = SimpleNamespace(thresholds={"RECON": 0.8})

    def __init__(self):
        self.batches = []

    def detect_batch(self, vectors):
        self.batches.append([v.entity_id for v in vectors])
        return [DetectorVerdict(
            detector_id="TEST_ONLY", threat_class=ThreatClass.RECON,
            raw_score=0.97, calibrated_confidence=0.91,
            evidence={k: value for k, value in v.values.items() if v.availability[k]},
            model_version="TEST_ONLY_NOT_TRAINED", feature_schema_version=v.schema_version,
            inference_latency_ms=0,
        ) for v in vectors]


def test_no_per_packet_features_or_inference():
    engine = SentinelEngine(config())
    for i in range(500):
        engine.process_frame(100 + i / 10000, frame())
    assert engine.metrics.feature_vectors == 0
    assert engine.metrics.inference_vectors == 0
    engine.finish()
    assert engine.metrics.feature_vectors == 1
    assert not engine._last_packets and not engine._dirty


def test_batches_preserve_order_and_alerts_are_incremental():
    settings = config()
    settings = settings.model_copy(update={"defaults": settings.defaults.model_copy(update={
        "snapshot_interval_seconds": 0.1, "inference_batch_size": 2,
    })})
    engine = SentinelEngine(settings)
    detector = TestOnlyDetector()
    engine.detectors["behaviour"] = detector
    accepted_before_eof = False
    for i in range(30):
        for offset in (0, 0.03):
            emitted = engine.process_frame(100 + i / 10 + offset, frame(50000 + i))
            if any(alert.decision is AlertDecision.ACCEPT for alert in emitted) and i < 29:
                accepted_before_eof = True
    engine.finish()
    assert accepted_before_eof
    assert max(map(len, detector.batches)) == 2
    assert engine.metrics.inference_batches < engine.metrics.inference_vectors < 60
    assert all(alert.raw_score == 0.97 and alert.calibrated_confidence == 0.91
               and alert.class_threshold == 0.8 for alert in engine.alerts)
    assert all(str(alert.source.ip) == "10.0.0.9" for alert in engine.alerts)


def test_telemetry_cache_and_reset_are_bounded():
    engine = SentinelEngine(config())
    engine.process_frame(100, frame())
    first = engine.metrics.snapshot()
    assert engine.metrics.snapshot() is first
    assert first["flows"] == 1
    assert first["flow_updates"] == first["packets"] == 1
    assert {"parse", "flow", "state"} <= set(first["latency_ms"])
    engine.reset()
    assert engine.metrics.snapshot()["packets"] == 0
    assert engine.state.event_count == 0
    assert engine.flows.active_flow_count == 0
