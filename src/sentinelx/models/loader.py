"""Strict, versioned artifact loading and NumPy batch inference."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np

from sentinelx.core.enums import ThreatClass
from sentinelx.core.schemas import FeatureVector
from sentinelx.features.behaviour_flow import FLOW_DEFINITION_ID, FLOW_MODEL_FEATURES
from sentinelx.models.calibrator import MulticlassSigmoidCalibrator
from sentinelx.models.compatibility import validate_feature_compatibility


@dataclass(frozen=True, slots=True)
class LoadedModelPackage:
    directory: Path
    estimator: object
    calibrator: object
    feature_schema: dict
    classes: tuple[str, ...]
    thresholds: dict[str, float]
    manifest: dict

    @property
    def model_version(self) -> str:
        return str(self.manifest.get("model_version", self.directory.name))

    def predict_batch(self, vectors: list[FeatureVector]) -> list[tuple]:
        if not vectors:
            return []
        started = perf_counter()
        columns = self.feature_schema["columns"]
        rows = []
        for vector in vectors:
            validate_feature_compatibility(vector, self.feature_schema)
            rows.append([
                vector.values.get(column.removeprefix("feature__"))
                if column.startswith("feature__")
                else vector.availability[column.removeprefix("available__")]
                for column in columns
            ])
        matrix = np.asarray(rows, dtype=np.float32)
        if isinstance(self.calibrator, MulticlassSigmoidCalibrator):
            raw = self.estimator.predict_proba(matrix)
            calibrated = self.calibrator.transform(raw)
        else:
            import pandas as pd
            features = pd.DataFrame(matrix, columns=columns)
            raw = self.estimator.predict_proba(features)
            calibrated = self.calibrator.predict_proba(features)
        if raw.shape != calibrated.shape or raw.shape != (len(vectors), len(self.classes)):
            raise ValueError("model/calibrator returned incompatible probability shapes")
        if not np.isfinite(calibrated).all() or not np.isfinite(raw).all():
            raise ValueError("model returned nonfinite probabilities")
        elapsed_per_vector = (perf_counter() - started) * 1000 / len(vectors)
        results = []
        for raw_row, row in zip(raw, calibrated, strict=True):
            index = int(np.argmax(row))
            results.append((self.classes[index], float(raw_row[index]), float(row[index]),
                            dict(zip(self.classes, map(float, row), strict=True)), elapsed_per_vector))
        return results

    def predict(self, vector: FeatureVector) -> tuple:
        return self.predict_batch([vector])[0]


def _read_json(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"required model artifact file is missing: {path}")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError(f"artifact must be a JSON object: {path.name}")
    return result


def load_model_package(path: str | Path) -> LoadedModelPackage:
    directory = Path(path)
    if not directory.is_dir():
        raise FileNotFoundError(f"model artifact directory does not exist: {directory}")
    feature_schema = _read_json(directory / "feature_schema.json")
    thresholds = _read_json(directory / "thresholds.json")
    manifest = _read_json(directory / "manifest.json")
    _read_json(directory / "metrics.json")
    is_xgb = manifest.get("artifact_format") == "sentinelx.xgboost_package.v1"
    if is_xgb:
        expected_files = {"model.json", "calibrator.joblib", "feature_schema.json",
                          "class_mapping.json", "thresholds.json", "metrics.json"}
        hashes = manifest.get("artifact_sha256", {})
        if set(hashes) != expected_files:
            raise ValueError("manifest is missing the complete artifact hash set")
        for name, expected in hashes.items():
            with (directory / name).open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                    raise ValueError(f"artifact integrity mismatch: {name}")
        classes = tuple(_read_json(directory / "class_mapping.json").get("classes", []))
        if classes != ("BENIGN", "DDOS", "RECON", "BOT_OR_C2_LIKE"):
            raise ValueError("Behaviour class mapping must match the approved four-class prototype")
        if (feature_schema.get("definition_id") != FLOW_DEFINITION_ID or
                feature_schema.get("family") != "behaviour" or
                feature_schema.get("schema_version") != "behaviour.v1" or
                feature_schema.get("columns") != [f"feature__{name}" for name in FLOW_MODEL_FEATURES]):
            raise ValueError("incompatible shared behaviour feature definitions")
        from xgboost import XGBClassifier
        estimator = XGBClassifier()
        estimator.load_model(directory / "model.json")
        # Small runtime batches should not start a full laptop-sized thread pool.
        estimator.set_params(n_jobs=1)
        calibrator = joblib.load(directory / "calibrator.joblib")
        if not isinstance(calibrator, MulticlassSigmoidCalibrator) or len(calibrator.models) != len(classes):
            raise ValueError("unsupported or incomplete Behaviour calibrator")
        if estimator.n_features_in_ != len(feature_schema["columns"]):
            raise ValueError("model feature count disagrees with schema")
    else:
        classes = tuple(_read_json(directory / "classes.json").get("classes", []))
        estimator = joblib.load(directory / "model.joblib")
        calibrator = joblib.load(directory / "calibrator.joblib")
        if tuple(map(str, estimator.classes_)) != classes or tuple(map(str, calibrator.classes_)) != classes:
            raise ValueError("model and calibrator class ordering differs from metadata")
    if not classes or len(set(classes)) != len(classes) or set(thresholds) != set(classes):
        raise ValueError("class mapping and thresholds must be complete and consistent")
    for name in classes:
        ThreatClass(name)
        value = float(thresholds[name])
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"invalid class threshold for {name}")
    return LoadedModelPackage(directory, estimator, calibrator, feature_schema, classes,
                              {name: float(value) for name, value in thresholds.items()}, manifest)
