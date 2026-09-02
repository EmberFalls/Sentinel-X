"""Calibrated probability accessors for loaded real model packages."""

from __future__ import annotations

import numpy as np


class MulticlassSigmoidCalibrator:
    """Held-out one-vs-rest sigmoid fits over raw probability logits."""

    def __init__(self):
        self.models = []

    @staticmethod
    def _logits(probabilities):
        values = np.clip(np.asarray(probabilities, dtype=float), 1e-7, 1 - 1e-7)
        return np.log(values / (1 - values))

    def fit(self, probabilities, labels):
        from sklearn.linear_model import LogisticRegression

        logits = self._logits(probabilities)
        self.models = []
        for column in range(logits.shape[1]):
            target = (np.asarray(labels) == column).astype(int)
            if len(np.unique(target)) != 2:
                raise ValueError("held-out calibration requires positive and negative support for each class")
            model = LogisticRegression(C=1e6, solver="lbfgs", random_state=42, max_iter=1000)
            model.fit(logits[:, column:column + 1], target)
            self.models.append(model)
        return self

    def transform(self, probabilities):
        logits = self._logits(probabilities)
        if logits.ndim != 2 or logits.shape[1] != len(self.models):
            raise ValueError("calibrator class count does not match model")
        calibrated = np.column_stack([
            model.predict_proba(logits[:, column:column + 1])[:, 1]
            for column, model in enumerate(self.models)
        ])
        calibrated = np.clip(calibrated, 1e-12, 1)
        return calibrated / calibrated.sum(axis=1, keepdims=True)


def predicted_class_and_scores(calibrator, features, estimator=None) -> tuple[str, float, float, dict[str, float]]:
    """Return class, raw score, calibrated confidence, and all calibrated probabilities."""

    probabilities = calibrator.predict_proba(features)[0]
    index = int(probabilities.argmax())
    class_name = str(calibrator.classes_[index])
    calibrated = float(probabilities[index])
    if estimator is None:
        raise ValueError("the original estimator is required to report a real raw score")
    raw_probabilities = estimator.predict_proba(features)[0]
    raw_index = list(estimator.classes_).index(calibrator.classes_[index])
    scores = {
        str(name): float(value)
        for name, value in zip(calibrator.classes_, probabilities, strict=True)
    }
    return class_name, float(raw_probabilities[raw_index]), calibrated, scores
