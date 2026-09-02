"""The exact flow feature math shared by CICIDS2017 preparation and PCAP replay.

Payload lengths exclude Ethernet/IP/TCP/UDP headers. Direction is the first
observed sender. Variances are population variances; timing units are seconds.
NumPy supports the same operations on an offline column or one runtime snapshot.
"""

from __future__ import annotations

import numpy as np

FLOW_DEFINITION_ID = "cicids2017-payload-flow-v1"
FLOW_MODEL_FEATURES = (
    "flow_duration_seconds", "packets_outbound", "packets_inbound", "packet_count",
    "payload_bytes_outbound", "payload_bytes_inbound", "payload_bytes_total",
    "payload_packet_size_mean", "payload_packet_size_variance",
    "inter_arrival_mean", "inter_arrival_variance", "payload_directional_ratio",
    "flow_packets_per_second", "flow_payload_bytes_per_second",
)


def safe_ratio(numerator, denominator):
    numerator, denominator = np.broadcast_arrays(
        np.asarray(numerator, dtype=float), np.asarray(denominator, dtype=float),
    )
    return np.divide(numerator, denominator, out=np.full(numerator.shape, np.nan),
                     where=denominator > 0)


def population_variance(sample_std, count):
    count = np.asarray(count, dtype=float)
    result = np.asarray(sample_std, dtype=float) ** 2 * safe_ratio(np.maximum(count - 1, 0), count)
    return np.where(count == 1, 0.0, result)


def pooled_payload_variance(n_out, n_in, bytes_out, bytes_in, std_out, std_in):
    """Reconstruct unbiased-per-direction CIC summaries as one population.

    Do not use CIC's global packet length mean/variance: its first-packet
    initialization counts that payload twice. Directional summaries do not.
    """
    n_out, n_in = np.asarray(n_out, dtype=float), np.asarray(n_in, dtype=float)
    mean_out, mean_in = safe_ratio(bytes_out, n_out), safe_ratio(bytes_in, n_in)
    mean = safe_ratio(np.asarray(bytes_out) + np.asarray(bytes_in), n_out + n_in)
    out_sum = np.where(n_out > 0, np.maximum(n_out - 1, 0) * np.asarray(std_out) ** 2
                       + n_out * (mean_out - mean) ** 2, 0)
    in_sum = np.where(n_in > 0, np.maximum(n_in - 1, 0) * np.asarray(std_in) ** 2
                      + n_in * (mean_in - mean) ** 2, 0)
    return safe_ratio(out_sum + in_sum, n_out + n_in)


def flow_model_values(*, duration, packets_out, packets_in, payload_out,
                      payload_in, payload_variance, iat_variance):
    duration = np.asarray(duration, dtype=float)
    packets_out, packets_in = np.asarray(packets_out, dtype=float), np.asarray(packets_in, dtype=float)
    payload_out, payload_in = np.asarray(payload_out, dtype=float), np.asarray(payload_in, dtype=float)
    total_packets, total_payload = packets_out + packets_in, payload_out + payload_in
    return {
        "flow_duration_seconds": duration,
        "packets_outbound": packets_out, "packets_inbound": packets_in,
        "packet_count": total_packets,
        "payload_bytes_outbound": payload_out, "payload_bytes_inbound": payload_in,
        "payload_bytes_total": total_payload,
        "payload_packet_size_mean": safe_ratio(total_payload, total_packets),
        "payload_packet_size_variance": np.asarray(payload_variance, dtype=float),
        "inter_arrival_mean": safe_ratio(duration, total_packets - 1),
        "inter_arrival_variance": np.asarray(iat_variance, dtype=float),
        "payload_directional_ratio": payload_out / (payload_in + 1),
        "flow_packets_per_second": safe_ratio(total_packets, duration),
        "flow_payload_bytes_per_second": safe_ratio(total_payload, duration),
    }
