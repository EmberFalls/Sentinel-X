"""Capability-aware post-inference Evidence Gate."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelx.core.enums import AlertDecision, EvidenceQuality
from sentinelx.core.schemas import CapabilityProfile, DetectorVerdict


@dataclass(frozen=True, slots=True)
class GateResult:
    decision: AlertDecision | None
    evidence_quality: EvidenceQuality
    missing_evidence: tuple[str, ...]


class EvidenceGate:
    """Reject classifications whose required passive evidence is absent."""

    def __init__(self, requirements: dict[str, dict], unknown_min_confidence: float = 0.50) -> None:
        if not 0 <= unknown_min_confidence <= 1:
            raise ValueError("unknown_min_confidence must be between 0 and 1")
        self.requirements = requirements
        self.unknown_min_confidence = unknown_min_confidence

    def evaluate(
        self,
        verdict: DetectorVerdict,
        capabilities: CapabilityProfile,
        class_threshold: float | None,
    ) -> GateResult:
        if verdict.threat_class.value in {"BENIGN", "BENIGN_DNS", "BENIGN_ENCRYPTED"}:
            return GateResult(None, EvidenceQuality.ADEQUATE, ())
        policy = self.requirements.get(verdict.threat_class.value, {})
        missing = list(verdict.missing_evidence)
        if not policy:
            missing.append("evidence_policy_not_configured")
        if class_threshold is None:
            missing.append("validation_threshold_unavailable")
        for capability in policy.get("required_capabilities", []):
            if not getattr(capabilities, capability, False):
                missing.append(capability)
        any_capabilities = policy.get("any_capabilities", [])
        if any_capabilities and not any(
            getattr(capabilities, name, False) for name in any_capabilities
        ):
            missing.append("one_of:" + ",".join(any_capabilities))
        for name in policy.get("required_evidence", []):
            if verdict.evidence.get(name) is None:
                missing.append(name)
        for name, minimum in policy.get("minimum_evidence", {}).items():
            value = verdict.evidence.get(name)
            if not isinstance(value, (int, float)) or value < minimum:
                missing.append(f"{name}>={minimum}")
        for name in policy.get("required_true", []):
            if verdict.evidence.get(name) is not True:
                missing.append(name)
        unique_missing = tuple(dict.fromkeys(missing))
        if unique_missing:
            return GateResult(
                AlertDecision.INSUFFICIENT_EVIDENCE, EvidenceQuality.INSUFFICIENT, unique_missing
            )
        if class_threshold is not None and verdict.calibrated_confidence >= class_threshold:
            quality = (
                EvidenceQuality.STRONG
                if len(policy.get("required_evidence", [])) >= 3
                else EvidenceQuality.ADEQUATE
            )
            return GateResult(AlertDecision.ACCEPT, quality, ())
        if verdict.calibrated_confidence >= self.unknown_min_confidence:
            return GateResult(AlertDecision.UNKNOWN_SUSPICIOUS, EvidenceQuality.ADEQUATE, ())
        return GateResult(None, EvidenceQuality.WEAK, ())
