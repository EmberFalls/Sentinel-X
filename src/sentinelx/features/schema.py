"""Stable feature schema names and lightweight feature helpers."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import blake2b
from math import log2

BEHAVIOUR_SCHEMA_VERSION = "behaviour.v1"
DNS_SCHEMA_VERSION = "dns.v1"
TLS_QUIC_SCHEMA_VERSION = "tls_quic.v1"


def shannon_entropy(items: Iterable[object]) -> float:
    """Calculate Shannon entropy for a finite collection."""

    values = list(items)
    if not values:
        return 0.0
    counts: dict[object, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    size = len(values)
    return -sum((count / size) * log2(count / size) for count in counts.values())


def stable_bucket(value: str, buckets: int = 256) -> int:
    """Map a value to a deterministic non-security feature bucket."""

    if buckets <= 0:
        raise ValueError("buckets must be positive")
    digest = blake2b(value.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % buckets


def entropy_from_counts(counts) -> float:
    total = sum(counts.values())
    return -sum((n / total) * log2(n / total) for n in counts.values() if n > 0) if total else 0.0
