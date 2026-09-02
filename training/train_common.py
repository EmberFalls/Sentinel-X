"""Real shared training path used by all three model families."""

from __future__ import annotations

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from training.calibrate import fit_sigmoid_calibrator
from training.evaluate import classification_metrics
from training.export import export_model_package
from training.splits import grouped_splits
from training.thresholds import derive_class_thresholds


def _feature_columns(frame: pd.DataFrame) -> list[str]:
    columns = sorted(
        column
        for column in frame.columns
        if column.startswith("feature__") or column.startswith("available__")
    )
    if not columns:
        raise ValueError("prepared table contains no shared feature columns")
    return columns


def _matrix(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    matrix = frame.loc[:, columns].copy()
    for column in matrix:
        if column.startswith("available__"):
            matrix[column] = matrix[column].astype(float)
        else:
            matrix[column] = pd.to_numeric(matrix[column], errors="coerce")
    return matrix


def train_family(input_path, output_dir, *, family: str, schema_version: str):
    """Fit, calibrate, evaluate, and export a real Random Forest model family."""

    table = pd.read_parquet(input_path)
    if table.empty:
        raise ValueError("cannot train on an empty prepared table")
    if set(table["family"]) != {family} or set(table["schema_version"]) != {schema_version}:
        raise ValueError("input table family/schema does not match requested model family")
    splits = grouped_splits(table)
    columns = _feature_columns(table)
    training_features = _matrix(splits.train, columns)
    validation_features = _matrix(splits.validation, columns)
    calibration_features = _matrix(splits.calibration, columns)
    test_features = _matrix(splits.test, columns)
    estimator = Pipeline(
        [
            ("impute", SimpleImputer(strategy="median")),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced",
                    n_jobs=-1,
                    random_state=42,
                ),
            ),
        ]
    )
    estimator.fit(training_features, splits.train["label"])
    calibrator = fit_sigmoid_calibrator(
        estimator, calibration_features, splits.calibration["label"]
    )
    classes = [str(label) for label in calibrator.classes_]
    validation_probabilities = calibrator.predict_proba(validation_features)
    thresholds = derive_class_thresholds(
        splits.validation["label"], validation_probabilities, classes
    )
    predictions = calibrator.predict(test_features)
    metrics = classification_metrics(splits.test["label"], predictions, classes)
    feature_schema = {
        "family": family,
        "schema_version": schema_version,
        "columns": columns,
        "preprocessing": "median-imputation plus explicit availability indicators",
    }
    manifest = {
        "family": family,
        "schema_version": schema_version,
        "model_type": "RandomForestClassifier",
        "split_roles": {
            "train_rows": len(splits.train),
            "validation_rows": len(splits.validation),
            "calibration_rows": len(splits.calibration),
            "test_rows": len(splits.test),
        },
        "training_data_sources": sorted(str(name) for name in table["source_name"].unique()),
    }
    return export_model_package(
        output_dir,
        estimator=estimator,
        calibrator=calibrator,
        feature_schema=feature_schema,
        classes=classes,
        thresholds=thresholds,
        metrics=metrics,
        manifest=manifest,
    )
