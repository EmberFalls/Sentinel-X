"""Mutable internal flow accumulator that emits immutable FlowRecord snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sentinelx.core.enums import FlowDirection
from sentinelx.core.schemas import Endpoint, FlowRecord, NumericStats, PacketObservation
from sentinelx.flow.key import FlowKey


@dataclass(slots=True)
class RunningStats:
    count: int = 0
    minimum: float | None = None
    maximum: float | None = None
    mean: float = 0.0
    squared_delta_sum: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        delta = value - self.mean
        self.mean += delta / self.count
        self.squared_delta_sum += delta * (value - self.mean)

    def snapshot(self) -> NumericStats:
        if self.count == 0:
            return NumericStats(count=0)
        variance = self.squared_delta_sum / self.count
        return NumericStats(
            count=self.count,
            minimum=self.minimum,
            maximum=self.maximum,
            mean=self.mean,
            variance=max(variance, 0.0),
        )


@dataclass(slots=True)
class MutableFlow:
    flow_id: str
    key: FlowKey
    start_time: datetime
    last_seen: datetime
    initiator: Endpoint | None = None
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    packet_sizes: RunningStats = field(default_factory=RunningStats)
    inter_arrivals: RunningStats = field(default_factory=RunningStats)
    tcp_flag_counts: dict[str, int] = field(default_factory=dict)
    dns_metadata: dict | None = None
    tls_metadata: dict | None = None
    quic_metadata: dict | None = None
    payload_bytes_a_to_b: int = 0
    payload_bytes_b_to_a: int = 0
    payload_sizes: RunningStats = field(default_factory=RunningStats)

    @property
    def packet_count(self) -> int:
        return self.packets_a_to_b + self.packets_b_to_a

    def add(self, packet: PacketObservation, direction: FlowDirection) -> None:
        if self.packet_sizes.count:
            delta = max((packet.timestamp - self.last_seen).total_seconds(), 0.0)
            self.inter_arrivals.update(delta)
        self.last_seen = max(self.last_seen, packet.timestamp)
        self.packet_sizes.update(float(packet.packet_length))
        if packet.payload_length is not None:
            self.payload_sizes.update(float(packet.payload_length))
            if direction is FlowDirection.A_TO_B:
                self.payload_bytes_a_to_b += packet.payload_length
            else:
                self.payload_bytes_b_to_a += packet.payload_length
        if direction is FlowDirection.A_TO_B:
            self.packets_a_to_b += 1
            self.bytes_a_to_b += packet.packet_length
        else:
            self.packets_b_to_a += 1
            self.bytes_b_to_a += packet.packet_length
        for flag in packet.tcp_flags or ():
            self.tcp_flag_counts[flag] = self.tcp_flag_counts.get(flag, 0) + 1
        if packet.dns_metadata:
            self.dns_metadata = dict(packet.dns_metadata)
        if packet.tls_metadata:
            self.tls_metadata = dict(packet.tls_metadata)
        if packet.quic_metadata:
            self.quic_metadata = dict(packet.quic_metadata)

    def snapshot(self) -> FlowRecord:
        return FlowRecord(
            flow_id=self.flow_id,
            start_time=self.start_time,
            last_seen=self.last_seen,
            endpoint_a=self.key.endpoint_a,
            endpoint_b=self.key.endpoint_b,
            protocol=self.key.protocol,
            initiator=self.initiator,
            payload_bytes_a_to_b=self.payload_bytes_a_to_b,
            payload_bytes_b_to_a=self.payload_bytes_b_to_a,
            payload_size_stats=self.payload_sizes.snapshot(),
            packets_a_to_b=self.packets_a_to_b,
            packets_b_to_a=self.packets_b_to_a,
            bytes_a_to_b=self.bytes_a_to_b,
            bytes_b_to_a=self.bytes_b_to_a,
            packet_size_stats=self.packet_sizes.snapshot(),
            inter_arrival_stats=self.inter_arrivals.snapshot(),
            tcp_flag_counts=dict(self.tcp_flag_counts),
            dns_metadata=self.dns_metadata,
            tls_metadata=self.tls_metadata,
            quic_metadata=self.quic_metadata,
        )
