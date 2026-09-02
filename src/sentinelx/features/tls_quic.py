"""TLS/QUIC metadata features that never rely on decrypted payloads."""

from __future__ import annotations

from sentinelx.core.enums import FeatureFamily
from sentinelx.core.ids import make_window_id
from sentinelx.core.schemas import CapabilityProfile, FeatureVector, FlowRecord
from sentinelx.features.schema import TLS_QUIC_SCHEMA_VERSION, stable_bucket
from sentinelx.state.windows import TemporalSnapshot


class TLSQUICFeatureExtractor:
    """Create numeric encrypted-session metadata features from observed headers."""

    def extract(
        self,
        flow: FlowRecord,
        state: TemporalSnapshot,
        capabilities: CapabilityProfile,
    ) -> FeatureVector:
        metadata = flow.tls_metadata or flow.quic_metadata or {}
        duration = max((flow.last_seen - flow.start_time).total_seconds(), 0.0)
        total_packets = flow.packets_a_to_b + flow.packets_b_to_a
        total_bytes = flow.bytes_a_to_b + flow.bytes_b_to_a
        fingerprint = metadata.get("ja3") if flow.tls_metadata else None
        values = {
            "flow_duration_seconds": duration,
            "packet_count": total_packets,
            "total_bytes": total_bytes,
            "packet_size_mean": flow.packet_size_stats.mean,
            "packet_size_variance": flow.packet_size_stats.variance,
            "inter_arrival_mean": flow.inter_arrival_stats.mean,
            "inter_arrival_variance": flow.inter_arrival_stats.variance,
            "packets_a_to_b": flow.packets_a_to_b,
            "packets_b_to_a": flow.packets_b_to_a,
            "bytes_a_to_b": flow.bytes_a_to_b,
            "bytes_b_to_a": flow.bytes_b_to_a,
            "directional_byte_ratio": flow.bytes_a_to_b / (flow.bytes_b_to_a + 1),
            "tls_record_version": metadata.get("record_version") if flow.tls_metadata else None,
            "tls_cipher_suite_count": metadata.get("cipher_suite_count")
            if flow.tls_metadata
            else None,
            "tls_extension_count": metadata.get("extension_count") if flow.tls_metadata else None,
            "tls_fingerprint_bucket": stable_bucket(fingerprint) if fingerprint else None,
            "quic_version": metadata.get("version") if flow.quic_metadata else None,
            "quic_long_header": int(bool(metadata.get("long_header")))
            if flow.quic_metadata
            else None,
            "destination_recurrence": state.destination_counts.get(state.destination_ip, 0)
            / max(state.packet_count, 1),
            "connection_frequency": state.flow_count / state.window_seconds,
        }
        availability = {key: value is not None for key, value in values.items()}
        return FeatureVector(
            family=FeatureFamily.TLS_QUIC,
            schema_version=TLS_QUIC_SCHEMA_VERSION,
            entity_id=flow.flow_id,
            window_id=make_window_id(state.source_ip, state.observed_at, state.window_seconds),
            values=values,
            availability=availability,
        )
