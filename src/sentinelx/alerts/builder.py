"""Convert evidence-gated detector verdicts into standard AlertRecords."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelx.alerts.severity import select_severity
from sentinelx.core.ids import make_alert_id
from sentinelx.core.schemas import AlertRecord, CapabilityProfile, DetectorVerdict, FlowRecord
from sentinelx.evidence.gate import GateResult


def build_alert(
    verdict: DetectorVerdict,
    gate: GateResult,
    flow: FlowRecord,
    *,
    severity_rules: dict[str, str],
    total_pipeline_latency_ms: float,
    window_id: str | None = None,
    capabilities: CapabilityProfile | None = None,
    class_threshold: float | None = None,
) -> AlertRecord | None:
    """Build an alert only for accepted, unknown, or insufficient-evidence outcomes."""

    if gate.decision is None:
        return None
    return AlertRecord(
        alert_id=make_alert_id(
            verdict.detector_id,
            verdict.threat_class,
            flow.last_seen,
            flow_id=flow.flow_id,
            window_id=window_id,
        ),
        timestamp=flow.last_seen,
        flow_id=flow.flow_id,
        window_id=window_id,
        threat_class=verdict.threat_class,
        severity=select_severity(verdict.threat_class, severity_rules),
        decision=gate.decision,
        calibrated_confidence=verdict.calibrated_confidence,
        raw_score=verdict.raw_score,
        class_threshold=class_threshold,
        emitted_at=datetime.now(UTC),
        evidence_quality=gate.evidence_quality,
        source=flow.initiator or flow.endpoint_a,
        destination=flow.endpoint_b if (flow.initiator or flow.endpoint_a) == flow.endpoint_a else flow.endpoint_a,
        evidence=verdict.evidence,
        missing_evidence=gate.missing_evidence,
        capabilities=capabilities,
        detector_id=verdict.detector_id,
        model_version=verdict.model_version,
        feature_schema_version=verdict.feature_schema_version,
        inference_latency_ms=verdict.inference_latency_ms,
        total_pipeline_latency_ms=total_pipeline_latency_ms,
    )
