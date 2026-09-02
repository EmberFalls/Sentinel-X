"""Tests for process-independent canonical identifiers."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from sentinelx.core.enums import ThreatClass, TransportProtocol
from sentinelx.core.ids import canonical_endpoint_pair, make_alert_id, make_flow_id, make_window_id
from sentinelx.core.schemas import Endpoint


def test_flow_id_is_independent_of_packet_direction(
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    observed_at: datetime,
) -> None:
    forward = make_flow_id(
        client_endpoint,
        server_endpoint,
        TransportProtocol.TCP,
        observed_at,
    )
    reverse = make_flow_id(
        server_endpoint,
        client_endpoint,
        TransportProtocol.TCP,
        observed_at,
    )

    assert forward == reverse
    assert forward.startswith("flow-")


def test_canonical_pair_retains_endpoint_ports() -> None:
    high_port = Endpoint(ip="10.0.0.1", port=60000)
    low_port = Endpoint(ip="10.0.0.1", port=53)

    endpoint_a, endpoint_b = canonical_endpoint_pair(high_port, low_port)

    assert endpoint_a.port == 53
    assert endpoint_b.port == 60000


def test_window_id_changes_between_windows(observed_at: datetime) -> None:
    first = make_window_id("10.0.0.15", observed_at, 60)
    second = make_window_id("10.0.0.15", observed_at.replace(minute=1), 60)

    assert first != second


def test_alert_id_requires_context(observed_at: datetime) -> None:
    with pytest.raises(ValueError, match="flow_id or window_id"):
        make_alert_id("behaviour", ThreatClass.C2, observed_at)


def test_ids_reject_naive_timestamps(
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
) -> None:
    with pytest.raises(ValidationError):
        make_flow_id(
            client_endpoint,
            server_endpoint,
            TransportProtocol.TCP,
            datetime(2026, 9, 1, 10, 0),
        )
