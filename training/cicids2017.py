"""Adapter for exactly the three approved CICIDS2017 labelled-flow CSVs."""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from sentinelx.features.behaviour_flow import (
    FLOW_DEFINITION_ID,
    FLOW_MODEL_FEATURES,
    flow_model_values,
    pooled_payload_variance,
    population_variance,
)

REQUIRED_FILES = (
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
)
CLASS_MAPPING = {"BENIGN": "BENIGN", "DDoS": "DDOS", "PortScan": "RECON", "Bot": "BOT_OR_C2_LIKE"}
CLASSES = ("BENIGN", "DDOS", "RECON", "BOT_OR_C2_LIKE")
COLUMNS = (
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Std", "Bwd Packet Length Std", "Flow IAT Std",
)
CORE_COLUMNS = COLUMNS[:5]


def file_sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_sources(data_dir: str | Path) -> list[Path]:
    paths = [Path(data_dir) / name for name in REQUIRED_FILES]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError("Required CICIDS2017 files missing:\n" + "\n".join(missing))
    return paths


def normalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    frame.columns = [" ".join(str(name).strip().split()) for name in frame.columns]
    missing = sorted({*COLUMNS, "Label"} - set(frame.columns))
    if missing:
        raise ValueError(f"CICIDS2017 columns missing: {missing}")
    return frame


def to_shared_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Column conversion only; every model formula comes from behaviour_flow."""
    n_out = frame["Total Fwd Packets"].to_numpy(dtype=float)
    n_in = frame["Total Backward Packets"].to_numpy(dtype=float)
    b_out = frame["Total Length of Fwd Packets"].to_numpy(dtype=float)
    b_in = frame["Total Length of Bwd Packets"].to_numpy(dtype=float)
    payload_variance = pooled_payload_variance(
        n_out, n_in, b_out, b_in,
        frame["Fwd Packet Length Std"].to_numpy(), frame["Bwd Packet Length Std"].to_numpy(),
    )
    iat_variance = population_variance(frame["Flow IAT Std"].to_numpy() / 1_000_000,
                                       n_out + n_in - 1)
    values = flow_model_values(
        duration=frame["Flow Duration"].to_numpy() / 1_000_000,
        packets_out=n_out, packets_in=n_in, payload_out=b_out, payload_in=b_in,
        payload_variance=payload_variance, iat_variance=iat_variance,
    )
    return pd.DataFrame({f"feature__{name}": values[name] for name in FLOW_MODEL_FEATURES},
                        index=frame.index).replace([np.inf, -np.inf], np.nan)


def prepare_cicids2017(data_dir: str | Path, *, block_rows: int = 512):
    paths = validate_sources(data_dir)
    if block_rows < 2:
        raise ValueError("provenance blocks must contain at least two rows")
    sources, tables = [], []
    raw_counts, mapped_counts = {}, {}
    for path in paths:
        # The selected projection excludes ports, IPs, timestamps and identifiers.
        frame = pd.read_csv(path, usecols=lambda name: name.strip() in {*COLUMNS, "Label"})
        frame = normalize_columns(frame)
        labels = frame["Label"].astype(str).str.strip()
        counts = labels.value_counts().to_dict()
        for label, count in counts.items():
            raw_counts[label] = raw_counts.get(label, 0) + int(count)
        selected = labels.isin(CLASS_MAPPING)
        frame = frame.loc[selected].copy()
        frame["label"] = labels.loc[selected].map(CLASS_MAPPING)
        for label, count in frame["label"].value_counts().items():
            mapped_counts[label] = mapped_counts.get(label, 0) + int(count)
        numeric = frame.loc[:, COLUMNS].apply(pd.to_numeric, errors="coerce")
        nonfinite = int((~np.isfinite(numeric.to_numpy())).sum())
        numeric = numeric.replace([np.inf, -np.inf], np.nan)
        numeric = numeric.mask(numeric < 0)
        valid = numeric.loc[:, CORE_COLUMNS].notna().all(axis=1)
        valid &= (numeric["Total Fwd Packets"] + numeric["Total Backward Packets"]) >= 1
        for name in ("Total Fwd Packets", "Total Backward Packets"):
            valid &= numeric[name].eq(np.floor(numeric[name]))
        clean = numeric.loc[valid]
        table = to_shared_features(clean)
        table["label"] = frame.loc[valid, "label"]
        table["source_name"] = path.name
        table["source_row"] = clean.index + 2  # CSV header occupies line 1.
        table["group_id"] = path.name + ":row-block:" + (clean.index // block_rows).astype(str)
        table["family"] = "behaviour"
        table["schema_version"] = "behaviour.v1"
        tables.append(table)
        sources.append({
            "filename": path.name, "path": str(path.resolve()), "sha256": file_sha256(path),
            "bytes": path.stat().st_size, "source_label_counts": counts,
            "unsupported_label_rows": int((~selected).sum()),
            "invalid_core_rows_removed": int((~valid).sum()),
            "nonfinite_numeric_cells": nonfinite, "clean_rows": len(table),
        })
    table = pd.concat(tables, ignore_index=True)
    columns = [f"feature__{name}" for name in FLOW_MODEL_FEATURES]
    fingerprints = pd.util.hash_pandas_object(table[columns], index=False)
    # Conflicting labels for identical selected inputs cannot be resolved honestly.
    labels_per_vector = table["label"].groupby(fingerprints).transform("nunique")
    conflicting = labels_per_vector > 1
    table = table.loc[~conflicting].copy()
    duplicates = table.duplicated(columns)
    table = table.loc[~duplicates].reset_index(drop=True)
    if set(table["label"]) != set(CLASSES):
        raise ValueError("cleaned approved inputs do not contain all four required classes")
    report = {
        "dataset": "CICIDS2017 / MachineLearningCSV", "sources": sources,
        "source_label_counts": raw_counts, "mapped_label_counts_before_cleaning": mapped_counts,
        "source_to_class": CLASS_MAPPING, "definition_id": FLOW_DEFINITION_ID,
        "invalid_core_rows_removed": sum(s["invalid_core_rows_removed"] for s in sources),
        "conflicting_feature_rows_removed": int(conflicting.sum()),
        "duplicate_feature_rows_removed": int(duplicates.sum()),
        "final_class_counts": table["label"].value_counts().to_dict(),
        "missing_policy": "Drop invalid counts/duration/payload totals; XGBoost native missing values for optional statistics or undefined zero-duration rates.",
        "grouping": f"Contiguous {block_rows}-row blocks within each original source file, retained before cleaning.",
        "limitations": [
            "CSV export has no source IP, destination IP, timestamps or protocol. They are not guessed.",
            "Whole-capture splits cannot cover all four classes: each attack occurs in one file.",
            "Row blocks are provenance proxies, not verified time/host/session groups. Evaluation is NOT leakage-free.",
            "Exact selected-input duplicates and contradictory labels are removed before splitting; test distribution describes unique cleaned vectors.",
            "Only core flow features train the model. Temporal evidence is measured during runtime, not fabricated in CSV training.",
            "Training uses completed CIC flows; partial runtime snapshots and unseen captures have unmeasured domain shift.",
            "Bot maps to BOT_OR_C2_LIKE; it is not a validated C2-beaconing label.",
        ],
        "excluded_features": ["Destination Port", "Protocol (absent)", "TCP flags (export ambiguity)",
                              "CIC global packet-size statistics (duplicate-first-packet issue)",
                              "all temporal host/window features (missing provenance)"],
        "feature_reference": "https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java",
    }
    return table, report
