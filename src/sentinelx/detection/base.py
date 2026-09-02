"""Common real-model detector wrapper; no mock predictions are emitted here."""

from __future__ import annotations

from sentinelx.core.enums import ThreatClass
from sentinelx.core.schemas import DetectorVerdict, FeatureVector
from sentinelx.models.loader import LoadedModelPackage


class DetectorUnavailableError(RuntimeError):
    """Raised when a real model package is unavailable or incompatible."""


class ModelDetector:
    """Run one loaded calibrated package and return a common DetectorVerdict."""

    def __init__(self, detector_id: str, package: LoadedModelPackage | None) -> None:
        self.detector_id = detector_id
        self.package = package

    @property
    def available(self) -> bool:
        return self.package is not None

    def detect(self, vector: FeatureVector) -> DetectorVerdict:
        return self.detect_batch([vector])[0]

    def detect_batch(self, vectors: list[FeatureVector]) -> list[DetectorVerdict]:
        if self.package is None:
            raise DetectorUnavailableError(f"{self.detector_id} has no real trained model package")
        predictions = self.package.predict_batch(vectors)
        return [self._verdict(vector, result) for vector, result in zip(vectors, predictions, strict=True)]

    def _verdict(self, vector: FeatureVector, prediction) -> DetectorVerdict:
        class_name, raw_score, calibrated, _, inference_ms = prediction
        try:
            threat_class = ThreatClass(class_name)
        except ValueError as exc:
            raise DetectorUnavailableError(
                f"{self.detector_id} artifact emitted unsupported class {class_name!r}"
            ) from exc
        evidence = {
            name: value for name, value in vector.values.items() if vector.availability[name]
        }
        return DetectorVerdict(
            detector_id=self.detector_id,
            threat_class=threat_class,
            raw_score=raw_score,
            calibrated_confidence=calibrated,
            evidence=evidence,
            required_evidence=(),
            missing_evidence=(),
            model_version=self.package.model_version,
            feature_schema_version=vector.schema_version,
            inference_latency_ms=inference_ms,
        )
