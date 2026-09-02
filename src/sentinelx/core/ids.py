"""Deterministic, process-independent identifiers for flows and windows."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256

from pydantic import AwareDatetime, TypeAdapter

from sentinelx.core.enums import ThreatClass, TransportProtocol
from sentinelx.core.schemas import Endpoint

_AWARE_DATETIME = TypeAdapter(AwareDatetime)


def _endpoint_sort_key(endpoint: Endpoint) -> tuple[int, bytes, int]:
    address = endpoint.ip
    return (address.version, address.packed, endpoint.port if endpoint.port is not None else -1)


def canonical_endpoint_pair(first: Endpoint, second: Endpoint) -> tuple[Endpoint, Endpoint]:
    """Return endpoints in a deterministic order independent of packet direction."""

    if _endpoint_sort_key(first) <= _endpoint_sort_key(second):
        return first, second
    return second, first


def _require_aware(timestamp: datetime) -> datetime:
    return _AWARE_DATETIME.validate_python(timestamp)


def _digest(prefix: str, *parts: object) -> str:
    canonical = "\x1f".join(str(part) for part in parts).encode("utf-8")
    return f"{prefix}-{sha256(canonical).hexdigest()[:24]}"


def make_flow_id(
    first: Endpoint,
    second: Endpoint,
    protocol: TransportProtocol,
    start_time: datetime,
    *,
    bucket_seconds: int = 60,
    session_discriminator: str = "",
) -> str:
    """Build a stable flow ID from canonical endpoints and a start-time bucket."""

    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")
    timestamp = _require_aware(start_time)
    endpoint_a, endpoint_b = canonical_endpoint_pair(first, second)
    start_bucket = int(timestamp.timestamp()) // bucket_seconds
    return _digest(
        "flow",
        endpoint_a.ip.compressed,
        endpoint_a.port,
        endpoint_b.ip.compressed,
        endpoint_b.port,
        protocol.value,
        start_bucket,
        session_discriminator,
    )


def make_window_id(entity_id: str, window_start: datetime, window_seconds: int) -> str:
    """Build a stable ID for one entity and temporal window."""

    if not entity_id:
        raise ValueError("entity_id must not be empty")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    timestamp = _require_aware(window_start)
    start_bucket = int(timestamp.timestamp()) // window_seconds
    return _digest("window", entity_id, window_seconds, start_bucket)


def make_alert_id(
    detector_id: str,
    threat_class: ThreatClass,
    timestamp: datetime,
    *,
    flow_id: str | None = None,
    window_id: str | None = None,
) -> str:
    """Build a deterministic alert ID for one detector decision context."""

    if not detector_id:
        raise ValueError("detector_id must not be empty")
    if not flow_id and not window_id:
        raise ValueError("an alert ID requires a flow_id or window_id")
    aware_timestamp = _require_aware(timestamp)
    return _digest(
        "sx",
        detector_id,
        threat_class.value,
        flow_id or "",
        window_id or "",
        aware_timestamp.isoformat(),
    )
