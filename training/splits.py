"""Group-aware TRAIN/VALIDATION/CALIBRATION/TEST splitting."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit


@dataclass(frozen=True, slots=True)
class DatasetSplits:
    train: pd.DataFrame
    validation: pd.DataFrame
    calibration: pd.DataFrame
    test: pd.DataFrame


def _split(
    frame: pd.DataFrame, test_size: float, random_state: int
) -> tuple[pd.DataFrame, pd.DataFrame]:
    groups = frame["group_id"]
    if groups.nunique() < 2:
        raise ValueError("group-aware splitting requires at least two unique groups")
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    left_index, right_index = next(splitter.split(frame, groups=groups))
    return frame.iloc[left_index].copy(), frame.iloc[right_index].copy()


def grouped_splits(frame: pd.DataFrame, random_state: int = 42) -> DatasetSplits:
    """Create non-overlapping group splits with explicit evaluation roles."""

    if "group_id" not in frame or "label" not in frame:
        raise ValueError("prepared data requires group_id and label columns")
    train, held_out = _split(frame, test_size=0.30, random_state=random_state)
    validation, remaining = _split(held_out, test_size=2 / 3, random_state=random_state + 1)
    calibration, test = _split(remaining, test_size=0.50, random_state=random_state + 2)
    sets = (train, validation, calibration, test)
    group_sets = [set(part["group_id"]) for part in sets]
    if any(
        group_sets[left] & group_sets[right] for left in range(4) for right in range(left + 1, 4)
    ):
        raise RuntimeError("group leakage detected while splitting")
    return DatasetSplits(train=train, validation=validation, calibration=calibration, test=test)


def complete_class_grouped_splits(frame: pd.DataFrame, seed: int = 42):
    """Choose the first seeded group partition with class support in every role.

    Selection examines label support only, never model scores or test performance.
    Row-block independence remains a limitation even when groups are disjoint.
    """
    expected = set(frame["label"])
    for candidate in range(seed, seed + 100):
        parts = grouped_splits(frame, candidate)
        if all(set(part["label"]) == expected
               for part in (parts.train, parts.validation, parts.calibration, parts.test)):
            return parts, candidate
    raise ValueError("No four-role grouped split contains every class; use richer provenance, not row-random splitting.")
