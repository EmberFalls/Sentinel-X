"""Create a clearly marked, offline-only UI/integration PCAP fixture.

This writes static Ethernet frames to a local file. It opens no sockets, sends
no traffic, performs no scan, and is not a real attack capture or dataset.
"""

from __future__ import annotations

import argparse
import socket
from pathlib import Path

import dpkt


def tcp_frame(source: str, destination: str, destination_port: int, payload: bytes, *, reverse: bool) -> bytes:
    sender, receiver = (destination, source) if reverse else (source, destination)
    source_port, target_port = (destination_port, 49152) if reverse else (49152, destination_port)
    tcp = dpkt.tcp.TCP(sport=source_port, dport=target_port, flags=dpkt.tcp.TH_ACK, data=payload)
    tcp.off = 5
    ip = dpkt.ip.IP(
        src=socket.inet_aton(sender), dst=socket.inet_aton(receiver),
        p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp,
    )
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(
        src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02",
        type=dpkt.ethernet.ETH_TYPE_IP, data=ip,
    ))


def create_capture(output: Path, *, flow_count: int = 4, replace: bool = False) -> None:
    """Emit offline short, diverse synthetic flows for UI/gate integration only."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not replace:
        raise FileExistsError(f"refusing to overwrite fixture: {output}")
    source, started = "198.51.100.10", 1_700_000_000.0
    mode = "wb" if replace else "xb"
    with output.open(mode) as stream:
        writer = dpkt.pcap.Writer(stream)
        for index in range(flow_count):
            destination = f"203.0.113.{index + 1}"
            port = 2000 + index
            # One second between static flows lets the runtime's real evidence
            # windows mature without creating a long or noisy dashboard demo.
            at = started + index * 1.0
            # This three-packet static pattern mirrors a real training-feature
            # shape selected from the retained RECON rows. It is a mock only.
            writer.writepkt(tcp_frame(source, destination, port, b"ab", reverse=False), ts=at)
            writer.writepkt(tcp_frame(source, destination, port, b"xy", reverse=True), ts=at + 0.0003)
            writer.writepkt(tcp_frame(source, destination, port, b"123456", reverse=False), ts=at + 0.0006)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--flow-count", type=int, default=4)
    parser.add_argument("--replace", action="store_true", help="replace this generated mock fixture only")
    args = parser.parse_args()
    if args.flow_count < 3 or args.flow_count > 100:
        parser.error("flow-count must be between 3 and 100 for this local UI fixture")
    create_capture(args.output, flow_count=args.flow_count, replace=args.replace)
    print(f"Created offline mock fixture: {args.output}")


if __name__ == "__main__":
    main()
