"""Capture formats and replay control; fixtures never transmit network traffic."""

import threading
import time

import dpkt
import pytest

from sentinelx.core.enums import ReplayMode
from sentinelx.ingest.pcap import CaptureReader
from sentinelx.ingest.replay import ReplayController


def capture(tmp_path, suffix=".cap", gap=1.0):
    path = tmp_path / ("fixture" + suffix)
    with path.open("wb") as stream:
        writer = dpkt.pcapng.Writer(stream) if suffix == ".pcapng" else dpkt.pcap.Writer(stream)
        writer.writepkt(b"first", ts=100)
        writer.writepkt(b"second", ts=100 + gap)
    return path


@pytest.mark.parametrize("suffix", [".cap", ".pcap", ".pcapng"])
def test_format_detection_and_incremental_progress(tmp_path, suffix):
    reader = CaptureReader(capture(tmp_path, suffix))
    assert reader.datalink() == 1
    frames = reader.frames()
    assert next(frames).data == b"first"
    assert next(frames).file_offset <= reader.size_bytes


def test_invalid_capture_fails(tmp_path):
    path = tmp_path / "invalid.cap"
    path.write_bytes(b"not a capture")
    with pytest.raises(ValueError, match="invalid or corrupt"):
        list(CaptureReader(path).frames())


@pytest.mark.parametrize("mode", [ReplayMode.FAST, ReplayMode.BENCHMARK])
def test_accelerated_modes_never_sleep(tmp_path, mode):
    def forbidden(_):
        pytest.fail("accelerated replay slept")
    controller = ReplayController(CaptureReader(capture(tmp_path, gap=3600)), mode=mode, sleeper=forbidden)
    assert len(list(controller.frames())) == 2
    assert controller.progress == 1


def test_paced_speed_and_processing_time(tmp_path):
    clock = [0.0]
    def sleep(seconds):
        clock[0] += seconds
    controller = ReplayController(CaptureReader(capture(tmp_path)), speed_multiplier=2,
                                  monotonic=lambda: clock[0], sleeper=sleep)
    frames = controller.frames()
    next(frames)
    clock[0] += 0.1
    next(frames)
    assert clock[0] == pytest.approx(0.5)


def test_stop_interrupts_long_delay_and_pause(tmp_path):
    controller = ReplayController(CaptureReader(capture(tmp_path, gap=3600)))
    seen = threading.Event()
    def run():
        for _ in controller.frames():
            seen.set()
    thread = threading.Thread(target=run)
    thread.start()
    assert seen.wait(1)
    controller.pause()
    started = time.monotonic()
    controller.stop()
    thread.join(1)
    assert not thread.is_alive()
    assert time.monotonic() - started < 1
    controller.reset()
    assert not controller.stopped and not controller.paused
    assert controller.progress == 0


def test_pause_blocks_until_resumed(tmp_path):
    controller = ReplayController(CaptureReader(capture(tmp_path)), mode=ReplayMode.FAST)
    controller.pause()
    seen = []
    thread = threading.Thread(target=lambda: seen.extend(controller.frames()))
    thread.start()
    assert not seen
    controller.resume()
    thread.join(1)
    assert len(seen) == 2
