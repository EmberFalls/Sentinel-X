"""Integration test for incremental PCAP parsing and flow reconstruction."""

import socket

import dpkt

from sentinelx.flow.manager import FlowManager
from sentinelx.ingest.pcap import PcapAdapter
from sentinelx.parsing.packet import PacketParser


def _ethernet_tcp(src: str, dst: str, sport: int, dport: int, flags: int) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1)
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src),
        dst=socket.inet_aton(dst),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=tcp,
    )
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\x66\x77\x88\x99\xaa\xbb",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(ethernet)


def test_pcap_stream_produces_bidirectional_flow(tmp_path) -> None:
    capture = tmp_path / "tiny.cap"
    with capture.open("wb") as stream:
        writer = dpkt.pcap.Writer(stream)
        writer.writepkt(_ethernet_tcp("10.0.0.1", "10.0.0.2", 50000, 443, dpkt.tcp.TH_SYN), ts=1.0)
        writer.writepkt(
            _ethernet_tcp("10.0.0.2", "10.0.0.1", 443, 50000, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK),
            ts=1.1,
        )
        writer.close()

    parser = PacketParser()
    manager = FlowManager()
    snapshots = []
    for frame in PcapAdapter(capture).frames():
        packet = parser.parse(frame.timestamp, frame.data)
        assert packet is not None
        snapshots.append(manager.process(packet).snapshot)

    assert len(snapshots) == 2
    assert snapshots[-1].packets_a_to_b == 1
    assert snapshots[-1].packets_b_to_a == 1
    assert snapshots[-1].tcp_flag_counts == {"SYN": 2, "ACK": 1}


def test_pcap_adapter_reports_ethernet_link_type(tmp_path) -> None:
    capture = tmp_path / "tiny.pcap"
    with capture.open("wb") as stream:
        writer = dpkt.pcap.Writer(stream)
        writer.writepkt(_ethernet_tcp("10.0.0.1", "10.0.0.2", 50000, 443, dpkt.tcp.TH_SYN))
        writer.close()

    assert PcapAdapter(capture).datalink() == dpkt.pcap.DLT_EN10MB
