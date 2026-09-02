"""Explicit test-only probability stubs verify row/class ordering, not accuracy."""

from pathlib import Path

import numpy as np
import pytest

from sentinelx.core.enums import FeatureFamily
from sentinelx.core.schemas import FeatureVector
from sentinelx.features.behaviour_flow import FLOW_DEFINITION_ID, FLOW_MODEL_FEATURES
from sentinelx.models.calibrator import MulticlassSigmoidCalibrator
from sentinelx.models.loader import LoadedModelPackage


class StubEstimator:
    def predict_proba(self, matrix):
        assert matrix.shape == (2, len(FLOW_MODEL_FEATURES))
        assert matrix[:, 0].tolist() == [12, 34]
        return np.array([[0.1, 0.6, 0.2, 0.1], [0.1, 0.2, 0.6, 0.1]])


class StubCalibrator(MulticlassSigmoidCalibrator):
    def transform(self, raw):
        # Deliberately changes the second predicted class, checking raw-score alignment.
        return np.array([[0.1, 0.7, 0.1, 0.1], [0.1, 0.1, 0.2, 0.6]])


def test_batch_preserves_row_order_and_raw_calibrated_class_alignment():
    vectors = []
    for value in (12, 34):
        values = {name: float(value) for name in reversed(FLOW_MODEL_FEATURES)}
        values["runtime_only_evidence"] = 99
        vectors.append(FeatureVector(
            family=FeatureFamily.BEHAVIOUR, schema_version="behaviour.v1",
            entity_id=str(value), window_id="TEST_ONLY", values=values,
            availability={name: True for name in values},
        ))
    package = LoadedModelPackage(
        Path("TEST_ONLY_NOT_AN_ARTIFACT"), StubEstimator(), StubCalibrator(),
        {"family": "behaviour", "schema_version": "behaviour.v1",
         "definition_id": FLOW_DEFINITION_ID,
         "columns": [f"feature__{name}" for name in FLOW_MODEL_FEATURES]},
        ("BENIGN", "DDOS", "RECON", "BOT_OR_C2_LIKE"), {}, {},
    )
    first, second = package.predict_batch(vectors)
    assert first[:3] == ("DDOS", 0.6, 0.7)
    assert second[:3] == ("BOT_OR_C2_LIKE", 0.1, 0.6)
    assert sum(first[3].values()) == pytest.approx(1)
    assert package.predict_batch([]) == []
