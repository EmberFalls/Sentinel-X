"""Create versioned training tables from shared FeatureVector outputs."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pandas as pd

from sentinelx.core.schemas import FeatureVector


def feature_rows(
    items: Iterable[tuple[FeatureVector, str, str, str]],
) -> pd.DataFrame:
    """Convert shared feature vectors to an auditable, model-family-specific table."""

    rows = []
    for vector, label, group_id, source_name in items:
        row = {
            "label": label,
            "group_id": group_id,
            "source_name": source_name,
            "family": vector.family.value,
            "schema_version": vector.schema_version,
            "entity_id": vector.entity_id,
            "window_id": vector.window_id,
        }
        for name, value in vector.values.items():
            row[f"feature__{name}"] = value
            row[f"available__{name}"] = vector.availability[name]
        rows.append(row)
    if not rows:
        raise ValueError("cannot create a training table with zero feature vectors")
    frame = pd.DataFrame(rows)
    if frame["family"].nunique() != 1 or frame["schema_version"].nunique() != 1:
        raise ValueError("a training table must contain one feature family and schema version")
    if frame["group_id"].isna().any() or frame["label"].isna().any():
        raise ValueError("labels and group IDs are required for every training row")
    return frame


def write_feature_table(frame: pd.DataFrame, output_path: str | Path) -> Path:
    """Persist a prepared table as Parquet without changing feature definitions."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(path, index=False)
    return path
