"""Optional real-artifact gate; skipped explicitly when training is blocked."""

from pathlib import Path

import pytest

from sentinelx.config import load_config_bundle
from sentinelx.core.enums import ReplayMode
from sentinelx.runtime.engine import SentinelEngine


def test_capture_through_real_behaviour_model():
    root = Path(__file__).resolve().parents[2]
    if not (root / "model_artifacts/behaviour-xgb-v1/model.json").is_file():
        pytest.skip("Real Behaviour model absent; training is required. No mock substitutes for this test.")
    engine = SentinelEngine(load_config_bundle(root / "configs"))
    assert engine.detectors["behaviour"].available, engine.detector_status()
    list(engine.replay(root / "data/demo/http.cap", mode=ReplayMode.FAST))
    assert engine.metrics.inference_vectors > 0
    assert engine.metrics.evidence_decisions == engine.metrics.inference_vectors
    assert all(alert.raw_score is not None and alert.class_threshold is not None for alert in engine.alerts)
