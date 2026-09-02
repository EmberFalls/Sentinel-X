"""Best-effort TLS and QUIC metadata parsing without payload decryption."""

from __future__ import annotations

from hashlib import md5
from typing import Any


def _read_u16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated uint16")
    return int.from_bytes(data[offset : offset + 2], "big"), offset + 2


def _parse_client_hello(body: bytes) -> dict[str, Any]:
    if len(body) < 35:
        raise ValueError("truncated client hello")
    legacy_version = int.from_bytes(body[0:2], "big")
    offset = 34
    session_length = body[offset]
    offset += 1 + session_length
    cipher_bytes, offset = _read_u16(body, offset)
    if cipher_bytes % 2 or offset + cipher_bytes > len(body):
        raise ValueError("invalid cipher suite vector")
    ciphers = [
        int.from_bytes(body[index : index + 2], "big")
        for index in range(offset, offset + cipher_bytes, 2)
    ]
    offset += cipher_bytes
    if offset >= len(body):
        raise ValueError("missing compression methods")
    compression_length = body[offset]
    offset += 1 + compression_length

    extensions: list[int] = []
    server_name: str | None = None
    alpn: list[str] = []
    if offset + 2 <= len(body):
        extension_bytes, offset = _read_u16(body, offset)
        extension_end = min(offset + extension_bytes, len(body))
        while offset + 4 <= extension_end:
            extension_type, offset = _read_u16(body, offset)
            extension_length, offset = _read_u16(body, offset)
            extension_data = body[offset : offset + extension_length]
            offset += extension_length
            extensions.append(extension_type)
            if extension_type == 0 and len(extension_data) >= 5:
                name_length = int.from_bytes(extension_data[3:5], "big")
                raw_name = extension_data[5 : 5 + name_length]
                try:
                    server_name = raw_name.decode("idna").lower()
                except UnicodeError:
                    server_name = None
            elif extension_type == 16 and len(extension_data) >= 3:
                cursor = 2
                while cursor < len(extension_data):
                    item_length = extension_data[cursor]
                    cursor += 1
                    item = extension_data[cursor : cursor + item_length]
                    cursor += item_length
                    try:
                        alpn.append(item.decode("ascii"))
                    except UnicodeError:
                        continue

    ja3_source = ",".join(
        [
            str(legacy_version),
            "-".join(str(cipher) for cipher in ciphers),
            "-".join(str(extension) for extension in extensions),
            "",
            "",
        ]
    )
    return {
        "handshake_type": "client_hello",
        "client_version": legacy_version,
        "cipher_suite_count": len(ciphers),
        "extension_count": len(extensions),
        "server_name": server_name,
        "alpn": alpn,
        "ja3": md5(ja3_source.encode("ascii"), usedforsecurity=False).hexdigest(),
    }


def parse_tls_metadata(payload: bytes) -> dict[str, Any] | None:
    """Parse TLS record/ClientHello metadata without decrypting application data."""

    if len(payload) < 5 or payload[0] not in {20, 21, 22, 23}:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    if record_length <= 0:
        return None
    metadata: dict[str, Any] = {
        "record_type": int(payload[0]),
        "record_version": int.from_bytes(payload[1:3], "big"),
        "record_length": record_length,
    }
    if payload[0] == 22 and len(payload) >= 9 and payload[5] == 1:
        handshake_length = int.from_bytes(payload[6:9], "big")
        body = payload[9 : 9 + handshake_length]
        try:
            metadata.update(_parse_client_hello(body))
        except ValueError:
            metadata["handshake_type"] = "client_hello_truncated"
    return metadata


def parse_quic_metadata(payload: bytes) -> dict[str, Any] | None:
    """Parse fields exposed by the QUIC public header."""

    if len(payload) < 1:
        return None
    first_byte = payload[0]
    fixed_bit = bool(first_byte & 0x40)
    if not fixed_bit:
        return None
    long_header = bool(first_byte & 0x80)
    metadata: dict[str, Any] = {
        "long_header": long_header,
        "fixed_bit": fixed_bit,
        "packet_number_length": (first_byte & 0x03) + 1,
    }
    if long_header and len(payload) >= 6:
        metadata["version"] = int.from_bytes(payload[1:5], "big")
        metadata["packet_type"] = (first_byte >> 4) & 0x03
        metadata["destination_connection_id_length"] = int(payload[5])
    return metadata
