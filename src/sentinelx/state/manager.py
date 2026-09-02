"""Bounded temporal observations indexed by endpoint, queried only at snapshots."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from math import sqrt

from sentinelx.core.schemas import PacketObservation
from sentinelx.flow.manager import FlowUpdate
from sentinelx.state.windows import TemporalSnapshot, TrafficEvent


class TemporalStateManager:
    def __init__(self, windows_seconds: tuple[int, ...] = (10, 60, 300),
                 max_events: int = 200_000) -> None:
        if not windows_seconds or min(windows_seconds) <= 0 or max_events <= 0:
            raise ValueError("window sizes and event limits must be positive")
        self.windows_seconds = tuple(sorted(set(windows_seconds)))
        self.max_events = max_events
        self._events: deque[TrafficEvent] = deque()
        self._outgoing: dict[str, deque] = defaultdict(deque)
        self._incoming: dict[str, deque] = defaultdict(deque)
        self._windows = {seconds: deque() for seconds in self.windows_seconds}
        self._watermark: datetime | None = None
        self._dropped_until: datetime | None = None

    @property
    def event_count(self) -> int:
        return len(self._events)

    @staticmethod
    def _domains(packet: PacketObservation) -> tuple[str, ...]:
        if not packet.dns_metadata:
            return ()
        return tuple(query["name"] for query in packet.dns_metadata.get("queries", [])
                     if isinstance(query, dict) and isinstance(query.get("name"), str))

    def _remove_oldest(self) -> TrafficEvent:
        event = self._events.popleft()
        for index, key in ((self._outgoing, event.src_ip), (self._incoming, event.dst_ip)):
            index[key].popleft()
            if not index[key]:
                del index[key]
        return event

    def expire(self, observed_at: datetime) -> None:
        self._watermark = max(self._watermark or observed_at, observed_at)
        cutoff = self._watermark - timedelta(seconds=self.windows_seconds[-1])
        while self._events and self._events[0].timestamp < cutoff:
            self._remove_oldest()
        for seconds, events in self._windows.items():
            cutoff = self._watermark - timedelta(seconds=seconds)
            while events and events[0].timestamp < cutoff:
                events.popleft()

    def observe(self, packet: PacketObservation, update: FlowUpdate) -> None:
        # The engine rejects out-of-order packets; this keeps age eviction ordered.
        if self._watermark and packet.timestamp < self._watermark:
            return
        self.expire(packet.timestamp)
        event = TrafficEvent(
            timestamp=packet.timestamp, flow_id=update.flow_id,
            src_ip=str(packet.src_ip), dst_ip=str(packet.dst_ip), dst_port=packet.dst_port,
            protocol=packet.protocol, packet_length=packet.packet_length,
            is_new_flow=update.is_new_flow, domains=self._domains(packet),
        )
        self._events.append(event)
        self._outgoing[event.src_ip].append(event)
        self._incoming[event.dst_ip].append(event)
        for events in self._windows.values():
            events.append(event)
            while len(events) > self.max_events:
                events.popleft()
        while len(self._events) > self.max_events:
            self._dropped_until = self._remove_oldest().timestamp

    def snapshot(self, source_ip: str, destination_ip: str,
                 observed_at: datetime, window_seconds: int) -> TemporalSnapshot:
        if window_seconds not in self.windows_seconds:
            raise ValueError(f"window {window_seconds} is not configured")
        self.expire(observed_at)
        cutoff = observed_at - timedelta(seconds=window_seconds)
        def recent(events):
            return [event for event in events if cutoff <= event.timestamp <= observed_at]
        outgoing = recent(self._outgoing.get(source_ip, ()))
        incoming = recent(self._incoming.get(source_ip, ()))
        target_events = recent(self._incoming.get(destination_ip, ()))
        new_flows = [event for event in outgoing if event.is_new_flow]
        destinations = Counter(event.dst_ip for event in new_flows)
        sources_for_target = Counter(event.src_ip for event in target_events)
        connection_times = tuple(event.timestamp for event in new_flows
                                 if event.dst_ip == destination_ip)
        flow_times: dict[str, list[datetime]] = {}
        for event in outgoing:
            if event.flow_id not in flow_times:
                flow_times[event.flow_id] = [event.timestamp, event.timestamp]
            flow_times[event.flow_id][1] = event.timestamp
        short = (sum((end - start).total_seconds() <= 2 for start, end in flow_times.values())
                 / len(flow_times)) if flow_times else None
        bins = Counter(int(event.timestamp.timestamp()) for event in target_events)
        burstiness = None
        if len(bins) >= 2:
            mean = sum(bins.values()) / len(bins)
            burstiness = sqrt(sum((value - mean) ** 2 for value in bins.values()) / len(bins)) / mean
        total_events = self._windows[window_seconds]
        total = len(total_events) if observed_at == self._watermark else len(recent(total_events))
        return TemporalSnapshot(
            observed_at=observed_at, window_seconds=window_seconds,
            source_ip=source_ip, destination_ip=destination_ip,
            packet_count=len(outgoing), byte_count=sum(e.packet_length for e in outgoing),
            flow_count=len(new_flows), unique_destinations=len({e.dst_ip for e in outgoing}),
            unique_destination_ports=len({e.dst_port for e in outgoing if e.dst_port is not None}),
            unique_sources_for_destination=len(sources_for_target),
            outbound_bytes=sum(e.packet_length for e in outgoing),
            inbound_bytes=sum(e.packet_length for e in incoming),
            destination_counts=destinations, source_counts_for_destination=sources_for_target,
            connection_timestamps=connection_times,
            recent_domains=tuple(domain for e in outgoing for domain in e.domains),
            target_packet_count=len(target_events), total_window_packets=total,
            history_seconds=(observed_at - outgoing[0].timestamp).total_seconds() if outgoing else 0,
            history_complete=self._dropped_until is None or self._dropped_until < cutoff,
            short_flow_ratio=short,
            udp_share=sum(e.protocol.value == "UDP" for e in target_events) / max(len(target_events), 1),
            burstiness=burstiness,
        )

    def reset(self) -> None:
        self._events.clear()
        self._outgoing.clear()
        self._incoming.clear()
        for events in self._windows.values():
            events.clear()
        self._watermark = None
        self._dropped_until = None
