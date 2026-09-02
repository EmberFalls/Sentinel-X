"""Bounded flow lifecycle with O(1) updates and ordered idle expiration."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta

from sentinelx.core.enums import FlowDirection
from sentinelx.core.ids import make_flow_id
from sentinelx.core.schemas import Endpoint, FlowRecord, PacketObservation
from sentinelx.flow.key import FlowKey
from sentinelx.flow.record import MutableFlow


@dataclass(slots=True)
class FlowUpdate:
    flow: MutableFlow
    direction: FlowDirection
    is_new_flow: bool
    expired: tuple[FlowRecord, ...] = ()
    _snapshot: FlowRecord | None = None

    @property
    def flow_id(self) -> str:
        return self.flow.flow_id

    @property
    def snapshot(self) -> FlowRecord:
        if self._snapshot is None:
            self._snapshot = self.flow.snapshot()
        return self._snapshot


class FlowManager:
    def __init__(self, idle_timeout_seconds: int = 60, *,
                 active_timeout_seconds: int = 120, max_flows: int = 50_000) -> None:
        if min(idle_timeout_seconds, active_timeout_seconds, max_flows) <= 0:
            raise ValueError("flow limits must be positive")
        self.idle_timeout = timedelta(seconds=idle_timeout_seconds)
        self.active_timeout = timedelta(seconds=active_timeout_seconds)
        self.max_flows = max_flows
        self._flows: OrderedDict[FlowKey, MutableFlow] = OrderedDict()
        self._generation = 0
        self.evicted_count = 0

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    def expire(self, observed_at: datetime) -> tuple[FlowRecord, ...]:
        expired = []
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            if observed_at - flow.last_seen < self.idle_timeout:
                break
            del self._flows[key]
            expired.append(flow.snapshot())
        return tuple(expired)

    def process(self, packet: PacketObservation, *, snapshot: bool = True) -> FlowUpdate:
        expired = list(self.expire(packet.timestamp))
        key = FlowKey.from_packet(packet)
        flow = self._flows.get(key)
        if flow and packet.timestamp - flow.start_time >= self.active_timeout:
            expired.append(self._flows.pop(key).snapshot())
            flow = None
        is_new = flow is None
        if flow is None:
            if len(self._flows) >= self.max_flows:
                _, evicted = self._flows.popitem(last=False)
                expired.append(evicted.snapshot())
                self.evicted_count += 1
            flow = MutableFlow(
                flow_id=make_flow_id(key.endpoint_a, key.endpoint_b, key.protocol,
                                    packet.timestamp, session_discriminator=str(self._generation)),
                key=key, start_time=packet.timestamp, last_seen=packet.timestamp,
                initiator=Endpoint(ip=packet.src_ip, port=packet.src_port),
            )
            self._generation += 1
            self._flows[key] = flow
        direction = key.direction_for(packet)
        flow.add(packet, direction)
        self._flows.move_to_end(key)
        return FlowUpdate(flow, direction, is_new, tuple(expired),
                          flow.snapshot() if snapshot else None)

    def flush(self) -> tuple[FlowRecord, ...]:
        snapshots = tuple(flow.snapshot() for flow in self._flows.values())
        self._flows.clear()
        return snapshots

    def reset(self) -> None:
        self._flows.clear()
        self._generation = 0
        self.evicted_count = 0
