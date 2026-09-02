"""Passive DNS metadata parsing; query payloads are never retained."""

from __future__ import annotations

from typing import Any

import dpkt


def parse_dns_message(payload: bytes) -> dict[str, Any] | None:
    """Return observable DNS metadata or ``None`` for malformed/non-DNS data."""

    try:
        message = dpkt.dns.DNS(payload)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None

    queries = []
    for query in message.qd or ():
        name = query.name.rstrip(".").lower() if query.name else None
        queries.append({"name": name, "type": int(query.type), "class": int(query.cls)})

    return {
        "transaction_id": int(message.id),
        "is_response": bool(message.qr),
        "rcode": int(message.rcode),
        "query_count": len(message.qd or ()),
        "answer_count": len(message.an or ()),
        "queries": queries,
    }
