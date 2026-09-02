"""Tests for strict loading of the Phase 0 configuration bundle."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinelx.config import DefaultSettings, load_config_bundle
from sentinelx.core.enums import FeatureFamily, ReplayMode


def test_repository_config_bundle_loads() -> None:
    config_dir = Path(__file__).resolve().parents[2] / "configs"

    bundle = load_config_bundle(config_dir)

    assert bundle.defaults.temporal_windows_seconds == (10, 60, 300)
    assert bundle.replay.mode is ReplayMode.PACED
    assert set(bundle.models.models) == set(FeatureFamily)
    assert bundle.models.models[FeatureFamily.BEHAVIOUR].artifact_path.name == "behaviour-xgb-v1"
    assert not bundle.models.models[FeatureFamily.DNS].enabled
    assert not bundle.models.models[FeatureFamily.TLS_QUIC].enabled


def test_temporal_windows_must_be_sorted_and_unique() -> None:
    with pytest.raises(ValidationError, match="unique and sorted"):
        DefaultSettings(
            project_name="Custodian",
            environment="test",
            log_level="INFO",
            flow_idle_timeout_seconds=60,
            temporal_windows_seconds=(60, 10, 60),
        )
