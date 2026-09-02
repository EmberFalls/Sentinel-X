"""Train the locked, calibrated CICIDS2017 XGBoost prototype reproducibly."""

from __future__ import annotations

import argparse
import json
import os
import platform
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.utils.class_weight import compute_sample_weight

from sentinelx.features.behaviour_flow import FLOW_DEFINITION_ID, FLOW_MODEL_FEATURES
from sentinelx.models.calibrator import MulticlassSigmoidCalibrator
from training.cicids2017 import (
    CLASS_MAPPING,
    CLASSES,
    file_sha256,
    prepare_cicids2017,
    validate_sources,
)
from training.evaluate import classification_metrics
from training.splits import complete_class_grouped_splits
from training.thresholds import derive_class_thresholds


def probability_metrics(labels, probabilities):
    labels = np.asarray(labels, dtype=int)
    predictions = probabilities.argmax(axis=1)
    report = classification_metrics(
        np.asarray(CLASSES)[labels], np.asarray(CLASSES)[predictions], CLASSES,
    )
    report["accuracy"] = float(accuracy_score(labels, predictions))
    for name in ("precision", "recall", "f1-score"):
        report["macro_" + name.replace("-score", "")] = report["classification_report"]["macro avg"][name]
    report["multiclass_brier_score"] = float(np.mean(np.sum(
        (probabilities - np.eye(len(CLASSES))[labels]) ** 2, axis=1,
    )))
    confidence = probabilities.max(axis=1)
    reliability, ece = [], 0.0
    for lower in np.arange(0, 1, 0.1):
        mask = (confidence >= lower) & (confidence < lower + 0.1 if lower < 0.9 else confidence <= 1)
        if mask.any():
            observed_accuracy = float(np.mean(predictions[mask] == labels[mask]))
            mean_confidence = float(confidence[mask].mean())
            ece += float(mask.mean()) * abs(observed_accuracy - mean_confidence)
            reliability.append({"lower": float(lower), "support": int(mask.sum()),
                                "accuracy": observed_accuracy, "mean_confidence": mean_confidence})
    report["expected_calibration_error_10_bins"] = ece
    report["reliability"] = reliability
    return report


def write_json(path, content):
    Path(path).write_text(json.dumps(content, indent=2, sort_keys=True, allow_nan=False),
                          encoding="utf-8")


def train(data_dir, output_dir, *, n_jobs=None, processed_path=None, prepare_only=False):
    if n_jobs is not None and n_jobs < 1:
        raise ValueError("n_jobs must be positive")
    validate_sources(data_dir)  # Missing files fail before creating outputs.
    destination = Path(output_dir)
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError(f"refusing to overwrite existing artifacts: {destination}; use a new output directory")
    started = perf_counter()
    table, provenance = prepare_cicids2017(data_dir)
    splits, split_seed = complete_class_grouped_splits(table)
    roles = {role: getattr(splits, role) for role in ("train", "validation", "calibration", "test")}
    split_counts = {role: {"rows": len(part), "groups": int(part["group_id"].nunique()),
                          "classes": part["label"].value_counts().to_dict()} for role, part in roles.items()}
    print(json.dumps({"preprocessing": provenance, "splits": split_counts}, indent=2), flush=True)
    output_table = Path(processed_path) if processed_path else Path("data/processed") / (destination.name + ".parquet")
    output_table.parent.mkdir(parents=True, exist_ok=True)
    role_map = {group: role for role, part in roles.items() for group in part["group_id"].unique()}
    table["split"] = table["group_id"].map(role_map)
    table.to_parquet(output_table, index=False)
    report_dir = Path("data/manifests")
    report_dir.mkdir(parents=True, exist_ok=True)
    write_json(report_dir / (destination.name + ".json"), {**provenance, "splits": split_counts,
                                                         "split_seed": split_seed,
                                                         "processed_table": str(output_table)})
    if prepare_only:
        print(f"Prepared data only; no model or metrics fabricated. Table: {output_table}", flush=True)
        return output_table
    try:
        from xgboost import XGBClassifier
    except Exception as exc:
        raise RuntimeError(f"XGBoost could not load. Prepared data was saved, but no model was trained. {exc}") from exc
    columns = [f"feature__{name}" for name in FLOW_MODEL_FEATURES]
    matrices = {role: part[columns].to_numpy(dtype=np.float32) for role, part in roles.items()}
    encoded = {role: part["label"].map({name: i for i, name in enumerate(CLASSES)}).to_numpy()
               for role, part in roles.items()}
    parameters = dict(
        objective="multi:softprob", num_class=len(CLASSES), n_estimators=300,
        max_depth=5, learning_rate=0.08, subsample=0.9, colsample_bytree=0.9,
        tree_method="hist", reg_lambda=2.0, random_state=42,
        n_jobs=n_jobs or min(os.cpu_count() or 1, 8), eval_metric="mlogloss",
    )
    estimator = XGBClassifier(**parameters)
    fit_started = perf_counter()
    weights = compute_sample_weight("balanced", encoded["train"])
    estimator.fit(matrices["train"], encoded["train"], sample_weight=weights, verbose=False)
    training_seconds = perf_counter() - fit_started
    validation_raw = estimator.predict_proba(matrices["validation"])
    print("Baseline fit complete. Fitting held-out sigmoid calibration.", flush=True)
    calibrator = MulticlassSigmoidCalibrator().fit(
        estimator.predict_proba(matrices["calibration"]), encoded["calibration"],
    )
    validation_calibrated = calibrator.transform(validation_raw)
    thresholds = derive_class_thresholds(
        roles["validation"]["label"], validation_calibrated, CLASSES, minimum_precision=0.80,
    )
    # Final-test labels are only used below, after model/calibration/thresholds are fixed.
    test_raw = estimator.predict_proba(matrices["test"])
    test_calibrated = calibrator.transform(test_raw)
    metrics = {
        "validation_raw": probability_metrics(encoded["validation"], validation_raw),
        "validation_calibrated": probability_metrics(encoded["validation"], validation_calibrated),
        "final_test_raw": probability_metrics(encoded["test"], test_raw),
        "final_test_calibrated": probability_metrics(encoded["test"], test_calibrated),
        "evaluation_scope": "Unique cleaned CSV flow vectors in disjoint source-row blocks. NOT a leakage-free host/session split or streaming-PCAP accuracy estimate.",
    }
    feature_schema = {
        "family": "behaviour", "schema_version": "behaviour.v1",
        "definition_id": FLOW_DEFINITION_ID, "columns": columns,
        "preprocessing": "Shared flow_model_values; native NaN; payload bytes, seconds, population variances; first-sender direction.",
        "runtime_only_evidence": "Temporal rates, diversity, fan-out, recurrence, history and capability flags; these are not classifier inputs.",
    }
    manifest = {
        "artifact_format": "sentinelx.xgboost_package.v1", "model_version": destination.name,
        "family": "behaviour", "schema_version": "behaviour.v1",
        "trained_at": datetime.now(UTC).isoformat(), "parameters": parameters,
        "library_versions": {name: version(name) for name in ("xgboost", "numpy", "scikit-learn", "pandas", "joblib")},
        "python_version": platform.python_version(), "dataset": provenance,
        "split_strategy": {"method": provenance["grouping"], "seed": split_seed,
                           "roles": split_counts, "group_overlap": False,
                           "seed_selection": "First partition containing every class in each role; no performance-based search.",
                           "leakage_free": False},
        "class_mapping": CLASS_MAPPING,
        "balance_policy": {"method": "Inverse class-frequency training sample weights only; no oversampling/downsampling.",
                           "training_weight_per_class": {name: float(weights[encoded["train"] == i][0])
                                                         for i, name in enumerate(CLASSES)}},
        "calibration": "Independent held-out one-vs-rest sigmoid on raw probability logits, followed by normalization.",
        "threshold_policy": "Lowest per-class validation threshold attaining 0.80 precision; final test never used.",
        "training_seconds": training_seconds, "total_seconds": perf_counter() - started,
        "limitations": provenance["limitations"],
    }
    destination.mkdir(parents=True, exist_ok=True)
    estimator.save_model(destination / "model.json")
    joblib.dump(calibrator, destination / "calibrator.joblib")
    write_json(destination / "feature_schema.json", feature_schema)
    write_json(destination / "class_mapping.json", {"classes": CLASSES, "source_to_class": CLASS_MAPPING})
    write_json(destination / "thresholds.json", thresholds)
    write_json(destination / "metrics.json", metrics)
    manifest["artifact_sha256"] = {
        name: file_sha256(destination / name)
        for name in ("model.json", "calibrator.joblib", "feature_schema.json",
                     "class_mapping.json", "thresholds.json", "metrics.json")
    }
    write_json(destination / "manifest.json", manifest)
    print(json.dumps({"artifacts": str(destination), "training_seconds": training_seconds,
                      "final_test": metrics["final_test_calibrated"]}, indent=2), flush=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("data/raw/cicids2017"))
    parser.add_argument("--output-dir", type=Path, default=Path("model_artifacts/behaviour-xgb-v1"))
    parser.add_argument("--n-jobs", type=int, default=None)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    try:
        train(args.data_dir, args.output_dir, n_jobs=args.n_jobs, prepare_only=args.prepare_only)
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError) as exc:
        parser.exit(2, f"Training stopped: {exc}\n")


if __name__ == "__main__":
    main()
