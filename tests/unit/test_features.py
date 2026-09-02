"""Tests for shared temporal, Behaviour, DNS, and TLS/QUIC feature extraction."""

from datetime import timedelta

from sentinelx.core.enums import TransportProtocol
from sentinelx.core.schemas import CapabilityProfile, PacketObservation
from sentinelx.features.behaviour import BehaviourFeatureExtractor, periodicity_score
from sentinelx.features.dns import DNSFeatureExtractor
from sentinelx.features.tls_quic import TLSQUICFeatureExtractor
from sentinelx.flow.manager import FlowManager
from sentinelx.observation.capabilities import build_capability_profile
from sentinelx.state.manager import TemporalStateManager


def _packet(observed_at, *, dns_metadata=None, tls_metadata=None) -> PacketObservation:
    return PacketObservation(
        timestamp=observed_at,
        src_ip="10.0.0.15",
        dst_ip="10.0.0.20",
        src_port=50000,
        dst_port=443,
        protocol=TransportProtocol.TCP,
        packet_length=100,
        tcp_flags=frozenset({"ACK"}),
        dns_metadata=dns_metadata,
        tls_metadata=tls_metadata,
    )


def test_periodicity_is_unavailable_with_too_few_observations(observed_at) -> None:
    assert periodicity_score((observed_at, observed_at + timedelta(seconds=10))) == (
        None,
        None,
        None,
    )


def test_behaviour_features_use_bounded_temporal_state(observed_at) -> None:
    manager = FlowManager()
    state = TemporalStateManager()
    for offset in (0, 10, 20):
        packet = _packet(observed_at + timedelta(seconds=offset))
        update = manager.process(packet)
        state.observe(packet, update)
    snapshot = state.snapshot("10.0.0.15", "10.0.0.20", observed_at + timedelta(seconds=20), 60)
    capabilities = build_capability_profile(packet, update.snapshot)

    vector = BehaviourFeatureExtractor().extract(update.snapshot, snapshot, capabilities)

    assert vector.values["connection_count"] == 1
    assert vector.values["packets_per_second"] == 3 / 60
    assert vector.values["tcp_syn_count"] == 0


def test_dns_features_keep_hidden_query_text_unavailable(observed_at) -> None:
    manager = FlowManager()
    state = TemporalStateManager()
    packet = _packet(
        observed_at,
        dns_metadata={"queries": [{"name": "abc-123.example", "type": 1}]},
    )
    update = manager.process(packet)
    state.observe(packet, update)
    snapshot = state.snapshot("10.0.0.15", "10.0.0.20", observed_at, 10)
    visible = CapabilityProfile(has_dns_query_name=True, has_dns_query_type=True)

    vector = DNSFeatureExtractor().extract(packet, snapshot, visible)
    assert vector.values["domain_length"] == 15
    assert vector.values["digit_ratio"] > 0

    hidden = DNSFeatureExtractor().extract(packet, snapshot, CapabilityProfile())
    assert hidden.values["domain_length"] is None
    assert not hidden.availability["domain_length"]


def test_tls_features_do_not_require_decrypted_payload(observed_at) -> None:
    manager = FlowManager()
    packet = _packet(observed_at, tls_metadata={"record_version": 771, "ja3": "abc"})
    update = manager.process(packet)
    state = TemporalStateManager()
    state.observe(packet, update)
    snapshot = state.snapshot("10.0.0.15", "10.0.0.20", observed_at, 10)

    vector = TLSQUICFeatureExtractor().extract(
        update.snapshot,
        snapshot,
        CapabilityProfile(has_tls_metadata=True, has_tls_fingerprint=True),
    )
    assert vector.values["tls_record_version"] == 771
    assert vector.values["tls_fingerprint_bucket"] is not None
