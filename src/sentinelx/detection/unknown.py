"""Unknown handling remains Evidence Gate policy, not a fake anomaly model."""

from sentinelx.evidence.gate import GateResult


def is_unknown_suspicious(result: GateResult) -> bool:
    return result.decision is not None and result.decision.value == "UNKNOWN_SUSPICIOUS"
