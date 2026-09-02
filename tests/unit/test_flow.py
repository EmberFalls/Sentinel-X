"""Tests for canonical flow direction and timeout behavior."""

from datetime import timedelta

from sentinelx.core.enums import FlowDirection, TransportProtocol
from sentinelx.core.schemas import PacketObservation
from sentinelx.flow.manager import FlowManager


def _packet(observed_at, src: str, dst: str, sport: int, dport: int) -> PacketObservation:
    return PacketObservation(
        timestamp=observed_at,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol=TransportProtocol.TCP,
        packet_length=60,
        tcp_flags=frozenset({"ACK"}),
    )


def test_reverse_packets_update_one_flow(observed_at) -> None:
    manager = FlowManager(idle_timeout_seconds=60)
    first = manager.process(_packet(observed_at, "10.0.0.1", "10.0.0.2", 50000, 443))
    second = manager.process(
        _packet(observed_at + timedelta(milliseconds=10), "10.0.0.2", "10.0.0.1", 443, 50000)
    )

    assert first.direction is FlowDirection.A_TO_B
    assert second.direction is FlowDirection.B_TO_A
    assert first.snapshot.flow_id == second.snapshot.flow_id
    assert second.snapshot.packets_a_to_b == 1
    assert second.snapshot.packets_b_to_a == 1
    assert second.snapshot.inter_arrival_stats.count == 1


def test_idle_timeout_emits_completed_flow(observed_at) -> None:
    manager = FlowManager(idle_timeout_seconds=10)
    first = manager.process(_packet(observed_at, "10.0.0.1", "10.0.0.2", 50000, 443))
    later = manager.process(
        _packet(observed_at + timedelta(seconds=11), "10.0.0.3", "10.0.0.4", 51000, 443)
    )

    assert later.expired[0].flow_id == first.snapshot.flow_id
    assert manager.active_flow_count == 1


def test_capacity_and_lazy_update_are_bounded(observed_at):
    manager = FlowManager(max_flows=2)
    for port in range(10):
        update = manager.process(_packet(observed_at, "10.0.0.1", "10.0.0.2", 50000 + port, 443), snapshot=False)
        assert update._snapshot is None
    assert manager.active_flow_count == 2
    assert manager.evicted_count == 8


def test_temporal_expiry_clears_endpoint_indexes(observed_at):
    from sentinelx.state.manager import TemporalStateManager
    state = TemporalStateManager((10, 60), max_events=3)
    manager = FlowManager()
    for offset in range(5):
        packet = _packet(observed_at + timedelta(seconds=offset), "10.0.0.1", "10.0.0.2", 50000 + offset, 443)
        state.observe(packet, manager.process(packet, snapshot=False))
    assert state.event_count == 3
    snapshot = state.snapshot("10.0.0.1", "10.0.0.2", observed_at + timedelta(seconds=5), 10)
    assert not snapshot.history_complete
    state.expire(observed_at + timedelta(seconds=100))
    assert state.event_count == 0
    assert not state._outgoing and not state._incoming
