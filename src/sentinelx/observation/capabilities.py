"""Derive evidence capability flags from real observed metadata."""

from __future__ import annotations

from sentinelx.core.enums import TransportProtocol
from sentinelx.core.schemas import CapabilityProfile, FlowRecord, PacketObservation


def build_capability_profile(
    packet: PacketObservation,
    flow: FlowRecord,
) -> CapabilityProfile:
    queries = packet.dns_metadata.get("queries", []) if packet.dns_metadata else []
    has_dns_name = any(isinstance(query, dict) and bool(query.get("name")) for query in queries)
    has_dns_type = any(
        isinstance(query, dict) and query.get("type") is not None for query in queries
    )
    tls_metadata = packet.tls_metadata or flow.tls_metadata
    quic_metadata = packet.quic_metadata or flow.quic_metadata
    return CapabilityProfile(
        has_packet_timestamps=True,
        has_packet_sizes=True,
        has_directionality=True,
        has_tcp_flags=packet.protocol is TransportProtocol.TCP,
        has_dns_query_name=has_dns_name,
        has_dns_query_type=has_dns_type,
        has_tls_metadata=bool(tls_metadata),
        has_tls_fingerprint=bool(tls_metadata and tls_metadata.get("ja3")),
        has_quic_metadata=bool(quic_metadata),
        has_bidirectional_stats=flow.packets_a_to_b > 0 and flow.packets_b_to_a > 0,
    )


def flow_capabilities(flow: FlowRecord) -> CapabilityProfile:
    queries = (flow.dns_metadata or {}).get("queries", [])
    return CapabilityProfile(
        has_packet_timestamps=True, has_packet_sizes=True, has_directionality=True,
        has_tcp_flags=flow.protocol is TransportProtocol.TCP,
        has_dns_query_name=any(isinstance(q, dict) and bool(q.get("name")) for q in queries),
        has_dns_query_type=any(isinstance(q, dict) and q.get("type") is not None for q in queries),
        has_tls_metadata=bool(flow.tls_metadata),
        has_tls_fingerprint=bool(flow.tls_metadata and flow.tls_metadata.get("ja3")),
        has_quic_metadata=bool(flow.quic_metadata),
        has_bidirectional_stats=flow.packets_a_to_b > 0 and flow.packets_b_to_a > 0,
    )
