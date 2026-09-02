"""Window data structures used by temporal aggregation."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from sentinelx.core.enums import TransportProtocol


@dataclass(frozen=True, slots=True)
class TrafficEvent:
    timestamp: datetime
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: TransportProtocol
    packet_length: int
    is_new_flow: bool
    domains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TemporalSnapshot:
    observed_at: datetime
    window_seconds: int
    source_ip: str
    destination_ip: str
    packet_count: int
    byte_count: int
    flow_count: int
    unique_destinations: int
    unique_destination_ports: int
    unique_sources_for_destination: int
    outbound_bytes: int
    inbound_bytes: int
    destination_counts: Counter[str]
    source_counts_for_destination: Counter[str]
    connection_timestamps: tuple[datetime, ...]
    recent_domains: tuple[str, ...]
    target_packet_count: int
    total_window_packets: int
    history_seconds: float = 0.0
    history_complete: bool = True
    short_flow_ratio: float | None = None
    udp_share: float = 0.0
    burstiness: float | None = None
