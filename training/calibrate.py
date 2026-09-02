"""Held-out probability calibration for trained classifier pipelines."""

from __future__ import annotations

from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator


def fit_sigmoid_calibrator(estimator, features, labels) -> CalibratedClassifierCV:
    """Fit Platt-style calibration on a distinct calibration split."""

    classes = set(labels)
    if len(classes) < 2:
        raise ValueError("calibration requires at least two classes")
    calibrator = CalibratedClassifierCV(FrozenEstimator(estimator), method="sigmoid")
    calibrator.fit(features, labels)
    return calibrator
