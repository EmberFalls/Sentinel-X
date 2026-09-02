"""Typed loading for the prototype's YAML configuration bundle."""

from __future__ import annotations

from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinelx.core.enums import FeatureFamily, ReplayMode

ConfigType = TypeVar("ConfigType", bound=BaseModel)


class SettingsModel(BaseModel):
    """Strict base class for configuration files."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DefaultSettings(SettingsModel):
    project_name: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    log_level: str = Field(pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    flow_idle_timeout_seconds: int = Field(gt=0)
    temporal_windows_seconds: tuple[int, ...] = Field(min_length=1)
    flow_active_timeout_seconds: int = Field(default=120, gt=0)
    max_active_flows: int = Field(default=50_000, gt=0)
    max_temporal_events: int = Field(default=200_000, gt=0)
    max_alerts: int = Field(default=1000, gt=0)
    snapshot_interval_seconds: float = Field(default=1.0, gt=0)
    snapshot_min_packets: int = Field(default=2, ge=2)
    inference_batch_size: int = Field(default=32, gt=0)
    inference_batch_timeout_ms: int = Field(default=50, gt=0)

    @model_validator(mode="after")
    def validate_windows(self) -> DefaultSettings:
        if any(window <= 0 for window in self.temporal_windows_seconds):
            raise ValueError("temporal windows must be positive")
        if tuple(sorted(set(self.temporal_windows_seconds))) != self.temporal_windows_seconds:
            raise ValueError("temporal windows must be unique and sorted")
        return self


class ReplaySettings(SettingsModel):
    capture_root: Path
    mode: ReplayMode
    speed_multiplier: float = Field(gt=0)
    loop: bool = False
    telemetry_interval_ms: int = Field(default=250, ge=100, le=1000)
    benchmark_telemetry_interval_ms: int = Field(default=1000, ge=250)


class EvidenceSettings(SettingsModel):
    unknown_min_confidence: float = Field(default=0.50, ge=0, le=1)
    requirements: dict[str, dict[str, Any]] = Field(default_factory=dict)


class SeveritySettings(SettingsModel):
    rules: dict[str, str] = Field(default_factory=dict)


class ModelEntry(SettingsModel):
    enabled: bool
    schema_version: str = Field(min_length=1)
    artifact_path: Path | None = None
    calibrator_path: Path | None = None
    thresholds_path: Path | None = None


class ModelsSettings(SettingsModel):
    models: dict[FeatureFamily, ModelEntry]

    @model_validator(mode="after")
    def validate_model_families(self) -> ModelsSettings:
        expected = set(FeatureFamily)
        if set(self.models) != expected:
            missing = sorted(family.value for family in expected - set(self.models))
            extra = sorted(str(family) for family in set(self.models) - expected)
            raise ValueError(f"models must define every family; missing={missing}, extra={extra}")
        for family, entry in self.models.items():
            expected_schema = f"{family.value}.v1"
            if entry.schema_version != expected_schema:
                raise ValueError(f"{family.value} model requires schema {expected_schema}")
        return self


class ConfigBundle(SettingsModel):
    defaults: DefaultSettings
    replay: ReplaySettings
    evidence: EvidenceSettings
    severity: SeveritySettings
    models: ModelsSettings


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"configuration file does not exist: {path}")
    with path.open("r", encoding="utf-8") as stream:
        loaded = yaml.safe_load(stream)
    if not isinstance(loaded, dict):
        raise ValueError(f"configuration must contain a YAML mapping: {path}")
    return loaded


def _validate_file(path: Path, model: type[ConfigType]) -> ConfigType:
    return model.model_validate(_load_yaml(path))


def load_config_bundle(config_dir: str | Path) -> ConfigBundle:
    """Load and validate all prototype configuration files from one directory."""

    directory = Path(config_dir)
    bundle = ConfigBundle(
        defaults=_validate_file(directory / "default.yaml", DefaultSettings),
        replay=_validate_file(directory / "replay.yaml", ReplaySettings),
        evidence=_validate_file(directory / "evidence.yaml", EvidenceSettings),
        severity=_validate_file(directory / "severity.yaml", SeveritySettings),
        models=_validate_file(directory / "models.yaml", ModelsSettings),
    )
    root = directory.resolve().parent
    def resolved(path):
        return (root / path).resolve() if path is not None and not path.is_absolute() else path
    entries = {family: entry.model_copy(update={
        "artifact_path": resolved(entry.artifact_path),
        "calibrator_path": resolved(entry.calibrator_path),
        "thresholds_path": resolved(entry.thresholds_path),
    }) for family, entry in bundle.models.models.items()}
    return bundle.model_copy(update={
        "replay": bundle.replay.model_copy(update={"capture_root": resolved(bundle.replay.capture_root)}),
        "models": bundle.models.model_copy(update={"models": entries}),
    })
