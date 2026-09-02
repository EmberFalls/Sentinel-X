"""Export real model artifacts with schemas, data split roles, and measured metrics."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib


def export_model_package(
    output_dir: str | Path,
    *,
    estimator: Any,
    calibrator: Any,
    feature_schema: dict[str, Any],
    classes: list[str],
    thresholds: dict[str, float],
    metrics: dict[str, Any],
    manifest: dict[str, Any],
) -> Path:
    """Write an artifact package only after a real fit/evaluation has completed."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    joblib.dump(estimator, destination / "model.joblib")
    joblib.dump(calibrator, destination / "calibrator.joblib")
    files = {
        "feature_schema.json": feature_schema,
        "classes.json": {"classes": classes},
        "thresholds.json": thresholds,
        "metrics.json": metrics,
        "manifest.json": {
            **manifest,
            "exported_at": datetime.now(UTC).isoformat(),
            "artifact_format": "sentinelx.model_package.v1",
        },
    }
    for name, value in files.items():
        (destination / name).write_text(
            json.dumps(value, indent=2, sort_keys=True), encoding="utf-8"
        )
    return destination
