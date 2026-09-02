"""Shared pytest fixtures for Custodian tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinelx.core.schemas import Endpoint


@pytest.fixture
def observed_at() -> datetime:
    return datetime(2026, 9, 1, 10, 0, tzinfo=UTC)


@pytest.fixture
def client_endpoint() -> Endpoint:
    return Endpoint(ip="10.0.0.15", port=49152)


@pytest.fixture
def server_endpoint() -> Endpoint:
    return Endpoint(ip="10.0.0.20", port=443)
