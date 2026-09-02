"""Canonical keys used by the in-memory flow manager."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelx.core.enums import FlowDirection, TransportProtocol
from sentinelx.core.ids import canonical_endpoint_pair
from sentinelx.core.schemas import Endpoint, PacketObservation


@dataclass(frozen=True, slots=True)
class FlowKey:
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: TransportProtocol

    @classmethod
    def from_packet(cls, packet: PacketObservation) -> FlowKey:
        first = Endpoint(ip=packet.src_ip, port=packet.src_port)
        second = Endpoint(ip=packet.dst_ip, port=packet.dst_port)
        endpoint_a, endpoint_b = canonical_endpoint_pair(first, second)
        return cls(endpoint_a=endpoint_a, endpoint_b=endpoint_b, protocol=packet.protocol)

    def direction_for(self, packet: PacketObservation) -> FlowDirection:
        source = Endpoint(ip=packet.src_ip, port=packet.src_port)
        destination = Endpoint(ip=packet.dst_ip, port=packet.dst_port)
        if source == self.endpoint_a and destination == self.endpoint_b:
            return FlowDirection.A_TO_B
        if source == self.endpoint_b and destination == self.endpoint_a:
            return FlowDirection.B_TO_A
        raise ValueError("packet endpoints do not belong to this flow key")
