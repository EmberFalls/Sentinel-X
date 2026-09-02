"""Tests for capability-aware Evidence Gate decisions and alert construction."""

from sentinelx.alerts.builder import build_alert
from sentinelx.core.enums import AlertDecision, EvidenceQuality, ThreatClass, TransportProtocol
from sentinelx.core.schemas import (
    CapabilityProfile,
    DetectorVerdict,
    Endpoint,
    FlowRecord,
    NumericStats,
)
from sentinelx.evidence.gate import EvidenceGate


def _flow(observed_at) -> FlowRecord:
    return FlowRecord(
        flow_id="flow-test",
        start_time=observed_at,
        last_seen=observed_at,
        endpoint_a=Endpoint(ip="10.0.0.1", port=1),
        endpoint_b=Endpoint(ip="10.0.0.2", port=2),
        protocol=TransportProtocol.TCP,
        packets_a_to_b=1,
        packets_b_to_a=0,
        bytes_a_to_b=64,
        bytes_b_to_a=0,
        packet_size_stats=NumericStats(count=1, minimum=64, maximum=64, mean=64, variance=0),
        inter_arrival_stats=NumericStats(count=0),
    )


def test_gate_abstains_when_lexical_dns_evidence_is_hidden(observed_at) -> None:
    verdict = DetectorVerdict(
        detector_id="dns",
        threat_class=ThreatClass.DGA,
        raw_score=0.9,
        calibrated_confidence=0.9,
        evidence={"domain_length": 20, "character_entropy": 3.1},
        model_version="real-model",
        feature_schema_version="dns.v1",
        inference_latency_ms=1,
    )
    gate = EvidenceGate(
        {
            "DGA": {
                "required_capabilities": ["has_dns_query_name"],
                "required_evidence": ["domain_length"],
            }
        }
    ).evaluate(verdict, CapabilityProfile(), 0.8)

    assert gate.decision is AlertDecision.INSUFFICIENT_EVIDENCE
    assert "has_dns_query_name" in gate.missing_evidence


def test_accepted_gate_builds_valid_alert(observed_at) -> None:
    verdict = DetectorVerdict(
        detector_id="behaviour",
        threat_class=ThreatClass.DDOS,
        raw_score=0.9,
        calibrated_confidence=0.9,
        evidence={"packets_per_second": 100, "target_concentration": 0.9},
        model_version="real-model",
        feature_schema_version="behaviour.v1",
        inference_latency_ms=1,
    )
    result = EvidenceGate(
        {
            "DDOS": {
                "required_capabilities": ["has_packet_timestamps"],
                "required_evidence": ["packets_per_second"],
            }
        }
    ).evaluate(verdict, CapabilityProfile(has_packet_timestamps=True), 0.8)
    alert = build_alert(
        verdict,
        result,
        _flow(observed_at),
        severity_rules={"DDOS": "HIGH"},
        total_pipeline_latency_ms=2,
    )

    assert result.decision is AlertDecision.ACCEPT
    assert result.evidence_quality is EvidenceQuality.ADEQUATE
    assert alert is not None
    assert alert.decision is AlertDecision.ACCEPT


def test_high_confidence_cannot_override_insufficient_temporal_history():
    verdict = DetectorVerdict(
        detector_id="test", threat_class=ThreatClass.BOT_OR_C2_LIKE,
        raw_score=0.99, calibrated_confidence=0.98,
        evidence={"connection_count": 1, "history_complete": True},
        model_version="TEST_ONLY", feature_schema_version="behaviour.v1", inference_latency_ms=0,
    )
    gate = EvidenceGate({"BOT_OR_C2_LIKE": {
        "minimum_evidence": {"connection_count": 3},
        "required_true": ["history_complete"],
    }}).evaluate(verdict, CapabilityProfile(), 0.8)
    assert gate.decision is AlertDecision.INSUFFICIENT_EVIDENCE
    assert "connection_count>=3" in gate.missing_evidence


def test_benign_is_not_an_alert():
    verdict = DetectorVerdict(
        detector_id="test", threat_class=ThreatClass.BENIGN, raw_score=0.99,
        calibrated_confidence=0.98, model_version="TEST_ONLY",
        feature_schema_version="behaviour.v1", inference_latency_ms=0,
    )
    assert EvidenceGate({}).evaluate(verdict, CapabilityProfile(), 0.5).decision is None
