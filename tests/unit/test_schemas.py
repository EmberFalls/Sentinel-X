"""Tests for the six stable Phase 0 contracts."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from sentinelx.core.enums import (
    AlertDecision,
    EvidenceQuality,
    FeatureFamily,
    Severity,
    ThreatClass,
    TransportProtocol,
)
from sentinelx.core.schemas import (
    AlertRecord,
    CapabilityProfile,
    DetectorVerdict,
    FeatureVector,
    FlowRecord,
    NumericStats,
    PacketObservation,
)


def test_packet_observation_requires_ports_for_tcp(observed_at: datetime) -> None:
    with pytest.raises(ValidationError, match="require source and destination ports"):
        PacketObservation(
            timestamp=observed_at,
            src_ip="10.0.0.15",
            dst_ip="10.0.0.20",
            protocol=TransportProtocol.TCP,
            packet_length=60,
        )


def test_flow_record_preserves_directional_counts(
    observed_at: datetime,
    client_endpoint,
    server_endpoint,
) -> None:
    flow = FlowRecord(
        flow_id="flow-test",
        start_time=observed_at,
        last_seen=observed_at,
        endpoint_a=client_endpoint,
        endpoint_b=server_endpoint,
        protocol=TransportProtocol.TCP,
        packets_a_to_b=1,
        packets_b_to_a=0,
        bytes_a_to_b=60,
        bytes_b_to_a=0,
        packet_size_stats=NumericStats(
            count=1,
            minimum=60,
            maximum=60,
            mean=60,
            variance=0,
        ),
        inter_arrival_stats=NumericStats(count=0),
    )

    assert flow.packets_a_to_b == 1
    assert flow.packets_b_to_a == 0


def test_capability_profile_defaults_to_unavailable() -> None:
    profile = CapabilityProfile()

    assert not any(profile.model_dump().values())


def test_feature_vector_distinguishes_unavailable_from_zero() -> None:
    vector = FeatureVector(
        family=FeatureFamily.DNS,
        schema_version="dns.v1",
        entity_id="domain:example",
        window_id="window-test",
        values={"dns_entropy": None, "digit_ratio": 0.0},
        availability={"dns_entropy": False, "digit_ratio": True},
    )

    assert vector.values["dns_entropy"] is None
    assert vector.values["digit_ratio"] == 0.0


def test_feature_vector_rejects_value_for_unavailable_feature() -> None:
    with pytest.raises(ValidationError, match="must be null"):
        FeatureVector(
            family=FeatureFamily.DNS,
            schema_version="dns.v1",
            entity_id="domain:example",
            window_id="window-test",
            values={"dns_entropy": 0.0},
            availability={"dns_entropy": False},
        )


def test_detector_verdict_rejects_unrelated_missing_evidence() -> None:
    with pytest.raises(ValidationError, match="subset"):
        DetectorVerdict(
            detector_id="behaviour",
            threat_class=ThreatClass.C2,
            raw_score=0.9,
            calibrated_confidence=0.85,
            required_evidence=("usable_timing",),
            missing_evidence=("dns_query_name",),
            model_version="test-only",
            feature_schema_version="behaviour.v1",
            inference_latency_ms=0.1,
        )


def test_insufficient_alert_requires_missing_evidence(observed_at: datetime) -> None:
    with pytest.raises(ValidationError, match="must list missing evidence"):
        AlertRecord(
            alert_id="sx-test",
            timestamp=observed_at,
            flow_id="flow-test",
            threat_class=ThreatClass.C2,
            severity=Severity.LOW,
            decision=AlertDecision.INSUFFICIENT_EVIDENCE,
            calibrated_confidence=0.9,
            evidence_quality=EvidenceQuality.INSUFFICIENT,
            detector_id="behaviour",
            model_version="test-only",
            feature_schema_version="behaviour.v1",
            inference_latency_ms=0.1,
            total_pipeline_latency_ms=0.2,
        )
