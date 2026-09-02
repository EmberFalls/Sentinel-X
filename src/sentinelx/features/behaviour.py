"""Shared behavioural features for both training and replay inference."""

from __future__ import annotations

from math import isfinite, sqrt

from sentinelx.core.enums import FeatureFamily
from sentinelx.core.ids import make_window_id
from sentinelx.core.schemas import CapabilityProfile, FeatureVector, FlowRecord
from sentinelx.features.behaviour_flow import flow_model_values
from sentinelx.features.schema import BEHAVIOUR_SCHEMA_VERSION, entropy_from_counts
from sentinelx.state.windows import TemporalSnapshot


def periodicity_score(timestamps) -> tuple[float | None, float | None, float | None]:
    """Return mean interval, interval CV, and regularity score when enough samples exist."""

    if len(timestamps) < 3:
        return None, None, None
    intervals = [
        max((current - previous).total_seconds(), 0.0)
        for previous, current in zip(timestamps, timestamps[1:], strict=False)
    ]
    mean_interval = sum(intervals) / len(intervals)
    if mean_interval <= 0:
        return mean_interval, None, 0.0
    variance = sum((interval - mean_interval) ** 2 for interval in intervals) / len(intervals)
    coefficient = sqrt(variance) / mean_interval
    return mean_interval, coefficient, max(0.0, min(1.0, 1.0 - coefficient))


class BehaviourFeatureExtractor:
    """Construct behavioural features from a live FlowRecord and rolling state."""

    def extract(
        self,
        flow: FlowRecord,
        state: TemporalSnapshot,
        capabilities: CapabilityProfile,
    ) -> FeatureVector:
        endpoint_a_is_source = (flow.initiator or flow.endpoint_a) == flow.endpoint_a
        if endpoint_a_is_source:
            outgoing_packets = flow.packets_a_to_b
            incoming_packets = flow.packets_b_to_a
            outgoing_bytes = flow.bytes_a_to_b
            incoming_bytes = flow.bytes_b_to_a
        else:
            outgoing_packets = flow.packets_b_to_a
            incoming_packets = flow.packets_a_to_b
            outgoing_bytes = flow.bytes_b_to_a
            incoming_bytes = flow.bytes_a_to_b
        duration = max((flow.last_seen - flow.start_time).total_seconds(), 0.0)
        rate_window = float(state.window_seconds)
        mean_interval, interval_cv, regularity = periodicity_score(state.connection_timestamps)
        values = {
            "flow_duration_seconds": duration,
            "packets_outbound": outgoing_packets,
            "packets_inbound": incoming_packets,
            "bytes_outbound": outgoing_bytes,
            "bytes_inbound": incoming_bytes,
            "packet_size_mean": flow.packet_size_stats.mean,
            "packet_size_variance": flow.packet_size_stats.variance,
            "inter_arrival_mean": flow.inter_arrival_stats.mean,
            "inter_arrival_variance": flow.inter_arrival_stats.variance,
            "protocol_id": {"TCP": 6, "UDP": 17, "ICMP": 1, "OTHER": 0}[flow.protocol.value],
            "tcp_syn_count": flow.tcp_flag_counts.get("SYN", 0)
            if capabilities.has_tcp_flags
            else None,
            "directional_byte_ratio": outgoing_bytes / (incoming_bytes + 1),
            "flows_per_second": state.flow_count / rate_window,
            "packets_per_second": state.packet_count / rate_window,
            "bytes_per_second": state.byte_count / rate_window,
            "unique_destinations": state.unique_destinations,
            "unique_destination_ports": state.unique_destination_ports,
            "unique_sources_for_destination": state.unique_sources_for_destination,
            "destination_entropy": entropy_from_counts(state.destination_counts),
            "source_entropy_for_destination": entropy_from_counts(state.source_counts_for_destination),
            "target_concentration": state.target_packet_count / max(state.total_window_packets, 1),
            "destination_recurrence": state.destination_counts.get(state.destination_ip, 0)
            / max(state.flow_count, 1),
            "connection_count": len(state.connection_timestamps),
            "mean_connection_interval": mean_interval,
            "connection_interval_cv": interval_cv,
            "periodicity_score": regularity,
            "ports_per_host": state.unique_destination_ports / max(state.unique_destinations, 1),
            "outbound_volume_window": state.outbound_bytes,
            "outbound_inbound_ratio_window": state.outbound_bytes / (state.inbound_bytes + 1),
            "history_seconds": state.history_seconds,
            "history_complete": state.history_complete,
            "short_flow_ratio": state.short_flow_ratio,
            "udp_share": state.udp_share,
            "burstiness": state.burstiness,
            "target_packets_per_second": state.target_packet_count / rate_window,
            "source_window_packets": state.packet_count,
            "source_window_flow_count": state.flow_count,
            "target_window_packets": state.target_packet_count,
        }
        payload_known = bool(flow.payload_size_stats and
                             flow.payload_size_stats.count == outgoing_packets + incoming_packets)
        payload_out = flow.payload_bytes_a_to_b if endpoint_a_is_source else flow.payload_bytes_b_to_a
        payload_in = flow.payload_bytes_b_to_a if endpoint_a_is_source else flow.payload_bytes_a_to_b
        shared = flow_model_values(
            duration=duration, packets_out=outgoing_packets, packets_in=incoming_packets,
            payload_out=payload_out if payload_known else float("nan"),
            payload_in=payload_in if payload_known else float("nan"),
            payload_variance=flow.payload_size_stats.variance if payload_known else float("nan"),
            iat_variance=flow.inter_arrival_stats.variance,
        )
        values.update({name: float(value) if isfinite(float(value)) else None
                       for name, value in shared.items()})
        availability = {key: value is not None for key, value in values.items()}
        return FeatureVector(
            family=FeatureFamily.BEHAVIOUR,
            schema_version=BEHAVIOUR_SCHEMA_VERSION,
            entity_id=flow.flow_id,
            window_id=make_window_id(state.source_ip, state.observed_at, state.window_seconds),
            values=values,
            availability=availability,
        )
