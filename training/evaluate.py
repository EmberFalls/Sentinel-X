"""Actual classification metrics for held-out labelled data."""

from __future__ import annotations

from typing import Any

from sklearn.metrics import classification_report, confusion_matrix


def classification_metrics(labels, predictions, classes) -> dict[str, Any]:
    """Return JSON-serializable per-class metrics and a confusion matrix."""

    return {
        "classification_report": classification_report(
            labels,
            predictions,
            labels=list(classes),
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(labels, predictions, labels=list(classes)).tolist(),
        "classes": list(classes),
    }
