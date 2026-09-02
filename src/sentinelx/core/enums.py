"""Enumerations shared across the prototype pipeline."""

from enum import StrEnum


class TransportProtocol(StrEnum):
    """Transport or network-layer protocol visible to the passive parser."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class FlowDirection(StrEnum):
    """Direction relative to the canonical endpoint ordering."""

    A_TO_B = "A_TO_B"
    B_TO_A = "B_TO_A"


class FeatureFamily(StrEnum):
    """The three feature and model families used by Custodian."""

    BEHAVIOUR = "behaviour"
    DNS = "dns"
    TLS_QUIC = "tls_quic"


class ThreatClass(StrEnum):
    """Known detector outputs retained by the presentation prototype."""

    BENIGN = "BENIGN"
    DDOS = "DDOS"
    C2 = "C2"
    BOT_OR_C2_LIKE = "BOT_OR_C2_LIKE"
    RECON = "RECON"
    EXFILTRATION = "EXFILTRATION"
    BENIGN_DNS = "BENIGN_DNS"
    DGA = "DGA"
    DNS_TUNNEL = "DNS_TUNNEL"
    BENIGN_ENCRYPTED = "BENIGN_ENCRYPTED"
    SUSPICIOUS_ENCRYPTED = "SUSPICIOUS_ENCRYPTED"
    UNKNOWN = "UNKNOWN"


class AlertDecision(StrEnum):
    """Non-benign outcomes allowed by the stable AlertRecord contract."""

    ACCEPT = "ACCEPT"
    UNKNOWN_SUSPICIOUS = "UNKNOWN_SUSPICIOUS"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class EvidenceQuality(StrEnum):
    """Deterministic quality assigned by the future Evidence Gate."""

    STRONG = "STRONG"
    ADEQUATE = "ADEQUATE"
    WEAK = "WEAK"
    INSUFFICIENT = "INSUFFICIENT"


class Severity(StrEnum):
    """Operational severity assigned after evidence validation."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReplayMode(StrEnum):
    """Supported read-only replay modes."""

    PACED = "paced"
    FAST = "fast"
    BENCHMARK = "benchmark"
