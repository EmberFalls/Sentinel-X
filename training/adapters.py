"""Dataset adapters that normalize source-specific labels without concatenating raw CSVs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd


@dataclass(frozen=True, slots=True)
class DatasetSource:
    """A declared, auditable dataset input selected by the user/team."""

    name: str
    path: Path
    label_column: str
    group_column: str


class TabularDatasetAdapter:
    """Validate a source table before a family-specific shared-feature conversion."""

    required_columns: tuple[str, ...] = ()

    def load(self, source: DatasetSource) -> pd.DataFrame:
        if not source.path.is_file():
            raise FileNotFoundError(f"dataset source does not exist: {source.path}")
        if source.path.suffix.lower() == ".parquet":
            frame = pd.read_parquet(source.path)
        elif source.path.suffix.lower() in {".csv", ".tsv"}:
            separator = "\t" if source.path.suffix.lower() == ".tsv" else ","
            frame = pd.read_csv(source.path, sep=separator)
        else:
            raise ValueError("dataset sources must be CSV, TSV, or Parquet")
        required = {source.label_column, source.group_column, *self.required_columns}
        missing = sorted(required - set(frame.columns))
        if missing:
            raise ValueError(f"{source.name} is missing required columns: {missing}")
        return frame.copy()


class CICAdapter(TabularDatasetAdapter):
    """Adapter boundary for compatible CIC flow data."""


class CTU13Adapter(TabularDatasetAdapter):
    """Adapter boundary for CTU-13 botnet/C2 flow data."""


class DNSDatasetAdapter(TabularDatasetAdapter):
    """Adapter boundary for DGA and labelled DNS-tunnelling sources."""


class TLSQUICDatasetAdapter(TabularDatasetAdapter):
    """Adapter boundary for a selected compatible encrypted-session source."""
