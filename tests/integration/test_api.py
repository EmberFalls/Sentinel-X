"""API integration tests that do not rely on a model mock or demo capture."""

from pathlib import Path

from fastapi.testclient import TestClient

from sentinelx.api.app import create_app
from sentinelx.config import load_config_bundle


def config_without_artifacts():
    root = Path(__file__).resolve().parents[2]
    config = load_config_bundle(root / "configs")
    for name, entry in config.models.models.items():
        config.models.models[name] = entry.model_copy(update={"artifact_path": None})
    return config


def test_health_and_detector_status_are_honest_about_missing_artifacts() -> None:
    app = create_app(config_without_artifacts())
    client = TestClient(app)

    assert client.get("/health").json() == {"status": "ok", "return_path": "NONE"}
    status = client.get("/api/v1/status").json()
    assert status["source_type"] == "PCAP_REPLAY"
    assert status["mode"] == "paced"
    assert status["replay_paused"] is False
    detector_status = client.get("/api/v1/detectors").json()
    assert all(not detector["enabled"] for detector in detector_status)


def test_replay_modes_progress_and_reset(tmp_path):
    import dpkt

    from sentinelx.ingest.pcap import CaptureReader

    config = config_without_artifacts()
    config = config.model_copy(update={"replay": config.replay.model_copy(update={"capture_root": tmp_path})})
    path = tmp_path / "api-test.cap"
    with path.open("wb") as stream:
        writer = dpkt.pcap.Writer(stream)
        writer.writepkt(b"unsupported fixture frame", ts=1)
        writer.writepkt(b"unsupported fixture frame", ts=3601)
    app = create_app(config)
    with TestClient(app) as client:
        for mode in ("fast", "benchmark"):
            response = client.post("/api/v1/replay/start", json={"capture": path.name, "mode": mode, "speed_multiplier": 2})
            assert response.status_code == 200
            app.state.session.thread.join(2)
            status = client.get("/api/v1/status").json()
            assert status["mode"] == mode and status["replay_state"] == "COMPLETED"
            assert status["progress"] == 1
            assert status["processed_capture_bytes"] == CaptureReader(path).size_bytes
            metrics = client.get("/api/v1/telemetry").json()["metrics"]
            assert metrics["packets"] == 2 and metrics["flow_updates"] == 0
            assert client.post("/api/v1/replay/reset").status_code == 200
            assert client.get("/api/v1/metrics").json()["packets"] == 0
        assert client.post("/api/v1/replay/start", json={"capture": "../outside.cap"}).status_code == 400
        assert client.post("/api/v1/replay/start", json={"capture": path.name, "mode": "bad"}).status_code == 422
        with client.websocket_connect("/api/v1/stream/telemetry") as ws:
            assert {"status", "metrics", "detectors"} == set(ws.receive_json())
