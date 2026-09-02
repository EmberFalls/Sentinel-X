"""Validation-derived class thresholds; no threshold is invented by the runtime."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import precision_recall_curve


def derive_class_thresholds(
    labels, probabilities, classes, minimum_precision: float = 0.80
) -> dict[str, float]:
    """Choose the lowest threshold meeting a declared validation precision target."""

    if not 0 < minimum_precision <= 1:
        raise ValueError("minimum_precision must be in (0, 1]")
    thresholds: dict[str, float] = {}
    for column, class_name in enumerate(classes):
        binary_labels = np.asarray(labels) == class_name
        if binary_labels.sum() == 0:
            raise ValueError(f"validation split contains no examples of class {class_name!r}")
        precision, _, values = precision_recall_curve(binary_labels, probabilities[:, column])
        eligible = np.flatnonzero(precision[:-1] >= minimum_precision)
        if not len(eligible):
            raise ValueError(
                f"no validation threshold for {class_name!r} reaches precision {minimum_precision}"
            )
        thresholds[str(class_name)] = float(values[eligible[0]])
    return thresholds
