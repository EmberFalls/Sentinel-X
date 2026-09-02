"""Small arithmetic fixtures only; never exported as datasets or model results."""

from datetime import timedelta
from math import sqrt

import numpy as np
import pandas as pd
import pytest

from sentinelx.core.enums import TransportProtocol
from sentinelx.core.schemas import PacketObservation
from sentinelx.features.behaviour import BehaviourFeatureExtractor
from sentinelx.features.behaviour_flow import FLOW_MODEL_FEATURES
from sentinelx.flow.manager import FlowManager
from sentinelx.models.calibrator import MulticlassSigmoidCalibrator
from sentinelx.observation.capabilities import build_capability_profile
from sentinelx.state.manager import TemporalStateManager
from training.cicids2017 import REQUIRED_FILES, to_shared_features, validate_sources


def test_csv_and_runtime_share_exact_feature_units_and_direction(observed_at):
    manager, state = FlowManager(), TemporalStateManager()
    for i, size in enumerate([10, 20, 30, 40]):
        reverse = i >= 2
        packet = PacketObservation(
            timestamp=observed_at + timedelta(seconds=i),
            src_ip="10.0.0.1" if reverse else "10.0.0.9",
            dst_ip="10.0.0.9" if reverse else "10.0.0.1",
            src_port=443 if reverse else 50000, dst_port=50000 if reverse else 443,
            protocol=TransportProtocol.TCP, packet_length=size + 54, payload_length=size,
            tcp_flags=frozenset({"ACK"}),
        )
        update = manager.process(packet)
        state.observe(packet, update)
    temporal = state.snapshot("10.0.0.9", "10.0.0.1", packet.timestamp, 60)
    vector = BehaviourFeatureExtractor().extract(
        update.snapshot, temporal, build_capability_profile(packet, update.snapshot),
    )
    csv = pd.DataFrame([{
        "Flow Duration": 3_000_000, "Total Fwd Packets": 2, "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 30, "Total Length of Bwd Packets": 70,
        "Fwd Packet Length Std": sqrt(50), "Bwd Packet Length Std": sqrt(50),
        "Flow IAT Std": 0,
    }])
    prepared = to_shared_features(csv).iloc[0]
    for name in FLOW_MODEL_FEATURES:
        assert vector.values[name] == pytest.approx(prepared["feature__" + name])
    assert vector.values["payload_packet_size_variance"] == pytest.approx(125)
    assert vector.values["payload_packet_size_mean"] == 25
    assert vector.values["payload_bytes_outbound"] == 30
    assert vector.values["bytes_outbound"] == 138  # Wire bytes remain distinct.


def test_missing_sources_names_are_explicit(tmp_path):
    with pytest.raises(FileNotFoundError) as error:
        validate_sources(tmp_path)
    assert all(name in str(error.value) for name in REQUIRED_FILES)


def test_sigmoid_outputs_finite_normalized_probabilities():
    raw = np.array([[0.7, 0.1, 0.1, 0.1], [0.1, 0.7, 0.1, 0.1],
                    [0.1, 0.1, 0.7, 0.1], [0.1, 0.1, 0.1, 0.7]] * 4)
    calibration = MulticlassSigmoidCalibrator().fit(raw, [0, 1, 2, 3] * 4)
    result = calibration.transform(raw)
    assert np.isfinite(result).all()
    assert np.allclose(result.sum(axis=1), 1)
    assert not np.allclose(result, raw)
