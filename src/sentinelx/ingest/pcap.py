"""Incremental, read-only PCAP/PCAPNG adapter."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import dpkt


@dataclass(frozen=True, slots=True)
class PcapFrame:
    """One raw frame yielded incrementally from a capture file."""

    timestamp: float
    data: bytes
    file_offset: int = 0


class CaptureReader:
    """Read an approved capture without loading it fully into memory."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @property
    def size_bytes(self) -> int:
        return self.path.stat().st_size

    def datalink(self) -> int:
        """Return the capture link-layer type without replaying any frames."""

        if not self.path.is_file():
            raise FileNotFoundError(f"capture file does not exist: {self.path}")
        try:
            with self.path.open("rb") as stream:
                return int(self._reader(stream).datalink())
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError) as exc:
            raise ValueError(f"invalid or corrupt capture: {self.path}") from exc

    @staticmethod
    def _reader(stream: BinaryIO):
        magic = stream.read(4)
        stream.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            return dpkt.pcapng.Reader(stream)
        if magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}:
            return dpkt.pcap.Reader(stream)
        raise ValueError("capture header is neither PCAP nor PCAPNG")

    def frames(self) -> Iterator[PcapFrame]:
        if not self.path.is_file():
            raise FileNotFoundError(f"capture file does not exist: {self.path}")
        if self.path.suffix.lower() not in {".cap", ".pcap", ".pcapng"}:
            raise ValueError("capture must use a .cap, .pcap, or .pcapng extension")
        with self.path.open("rb") as stream:
            try:
                reader = self._reader(stream)
                if reader.datalink() != dpkt.pcap.DLT_EN10MB:
                    raise ValueError("only Ethernet/IP captures are supported")
                for timestamp, data in reader:
                    yield PcapFrame(timestamp=float(timestamp), data=bytes(data), file_offset=stream.tell())
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError) as exc:
                raise ValueError(f"invalid or corrupt capture: {self.path}") from exc


# Existing integrations keep the same streaming adapter API.
PcapAdapter = CaptureReader
