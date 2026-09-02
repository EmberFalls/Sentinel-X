"""Local API for bounded passive replay, controls and aggregated telemetry."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from threading import RLock, Thread
from typing import Literal

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from sentinelx.config import ConfigBundle, load_config_bundle
from sentinelx.core.enums import ReplayMode
from sentinelx.ingest.pcap import CaptureReader
from sentinelx.ingest.replay import ReplayController
from sentinelx.runtime.engine import SentinelEngine


class ReplayStartRequest(BaseModel):
    capture: str = Field(min_length=1)
    mode: ReplayMode | None = None
    speed_multiplier: Literal[1, 2, 5, 10] | None = None


class ReplaySession:
    def __init__(self, engine: SentinelEngine, config: ConfigBundle) -> None:
        self.engine, self.config = engine, config
        self.capture_root = config.replay.capture_root.resolve()
        self.thread: Thread | None = None
        self.controller: ReplayController | None = None
        self.running = False
        self.capture: str | None = None
        self.error: str | None = None
        self.state = "IDLE"
        self.run_id = 0
        self.capture_size_bytes = 0
        self._lock = RLock()

    @property
    def telemetry_interval(self):
        benchmark = self.controller and self.controller.mode is ReplayMode.BENCHMARK
        return (self.config.replay.benchmark_telemetry_interval_ms if benchmark
                else self.config.replay.telemetry_interval_ms) / 1000

    def start(self, capture: str, mode: ReplayMode | None = None, speed_multiplier: float | None = None) -> None:
        with self._lock:
            if self.running:
                raise RuntimeError("a replay is already running")
            candidate = (self.capture_root / capture).resolve()
            if self.capture_root not in candidate.parents or candidate.suffix.lower() not in {".cap", ".pcap", ".pcapng"}:
                raise ValueError("capture must be a local .cap, .pcap, or .pcapng inside the approved demo directory")
            if not candidate.is_file():
                raise FileNotFoundError("selected demo capture does not exist")
            reader = CaptureReader(candidate)
            datalink = reader.datalink()
            if datalink != 1:
                raise ValueError(f"unsupported link-layer type {datalink}; choose an Ethernet/IP capture")
            self.controller = ReplayController(
                reader, mode=mode or self.config.replay.mode,
                speed_multiplier=speed_multiplier or self.config.replay.speed_multiplier,
            )
            self.engine.reset()
            self.capture, self.error = capture, None
            self.capture_size_bytes = reader.size_bytes
            self.state, self.running = "RUNNING", True
            self.run_id += 1
            controller = self.controller

            def run():
                try:
                    for _ in self.engine.run_controller(controller):
                        pass
                    with self._lock:
                        self.state = "COMPLETED" if controller.completed else "STOPPED"
                except Exception as exc:
                    with self._lock:
                        self.error = str(exc)
                        self.state = "ERROR"
                finally:
                    with self._lock:
                        self.running = False
            self.thread = Thread(target=run, name="sentinel-passive-replay", daemon=True)
            self.thread.start()

    def pause(self):
        with self._lock:
            if not self.running or self.controller is None:
                raise RuntimeError("no replay is running")
            self.controller.pause()
            self.engine.metrics.set_paused(True)
            self.state = "PAUSED"

    def resume(self):
        with self._lock:
            if not self.running or self.controller is None:
                raise RuntimeError("no replay is running")
            self.engine.metrics.set_paused(False)
            self.controller.resume()
            self.state = "RUNNING"

    def stop(self):
        with self._lock:
            if not self.running or self.controller is None:
                raise RuntimeError("no replay is running")
            self.state = "STOPPING"
            self.controller.stop()

    def reset(self):
        with self._lock:
            if self.running:
                raise RuntimeError("stop replay before resetting runtime state")
            self.engine.reset()
            self.capture = self.controller = self.error = None
            self.state = "IDLE"
            self.run_id += 1
            self.capture_size_bytes = 0

    def status(self):
        controller = self.controller
        return {
            "passive_monitor": True, "return_path": "NONE",
            "replay_running": self.running, "replay_paused": bool(self.running and controller and controller.paused),
            "replay_state": self.state, "capture": self.capture,
            "active_flows": self.engine.flows.active_flow_count,
            "source_type": "PCAP_REPLAY", "source_name": self.capture,
            "mode": (controller.mode if controller else self.config.replay.mode).value,
            "speed_multiplier": controller.speed_multiplier if controller else self.config.replay.speed_multiplier,
            "progress": controller.progress if controller else None,
            "progress_basis": "capture_file_bytes", "capture_size_bytes": self.capture_size_bytes,
            "processed_capture_bytes": controller.processed_bytes if controller else 0,
            "error": self.error, "run_id": self.run_id,
            "telemetry_interval_ms": round(self.telemetry_interval * 1000),
        }


def create_app(config: ConfigBundle) -> FastAPI:
    engine = SentinelEngine(config)
    session = ReplaySession(engine, config)

    @asynccontextmanager
    async def lifespan(app):
        yield
        if session.running and session.controller:
            session.controller.stop()
        if session.thread:
            await asyncio.to_thread(session.thread.join, 2)

    app = FastAPI(title="Custodian Prototype", version="0.2.0", lifespan=lifespan)
    app.state.engine, app.state.session = engine, session

    @app.get("/health")
    def health():
        return {"status": "ok", "return_path": "NONE"}

    @app.get("/api/v1/status")
    def status():
        return session.status()

    @app.get("/api/v1/alerts")
    def alerts():
        return [alert.model_dump(mode="json") for alert in list(engine.alerts)]

    @app.get("/api/v1/alerts/{alert_id}")
    def alert_detail(alert_id: str):
        for alert in list(engine.alerts):
            if alert.alert_id == alert_id:
                return alert.model_dump(mode="json")
        raise HTTPException(status_code=404, detail="alert not found or no longer retained")

    @app.get("/api/v1/metrics")
    def metrics():
        return engine.metrics.snapshot(interval_seconds=session.telemetry_interval)

    @app.get("/api/v1/detectors")
    def detectors():
        return engine.detector_status()

    @app.get("/api/v1/telemetry")
    def telemetry():
        return {"status": status(), "metrics": metrics(), "detectors": detectors()}

    @app.post("/api/v1/replay/start")
    def start_replay(request: ReplayStartRequest):
        try:
            session.start(request.capture, request.mode, request.speed_multiplier)
        except (ValueError, FileNotFoundError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "started", "capture": request.capture}

    def control(action, result):
        try:
            action()
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": result}

    @app.post("/api/v1/replay/pause")
    def pause_replay():
        return control(session.pause, "paused")

    @app.post("/api/v1/replay/resume")
    def resume_replay():
        return control(session.resume, "running")

    @app.post("/api/v1/replay/stop")
    def stop_replay():
        return control(session.stop, "stopping")

    @app.post("/api/v1/replay/reset")
    def reset_replay():
        return control(session.reset, "reset")

    @app.websocket("/api/v1/stream/telemetry")
    async def stream_telemetry(websocket: WebSocket):
        await websocket.accept()
        try:
            while True:
                await websocket.send_json(telemetry())
                await asyncio.sleep(session.telemetry_interval)
        except (WebSocketDisconnect, RuntimeError):
            return

    @app.websocket("/api/v1/stream/alerts")
    async def stream_alerts(websocket: WebSocket):
        await websocket.accept()
        revision = -1
        try:
            while True:
                if engine.alert_revision != revision:
                    await websocket.send_json({"run_id": session.run_id, "alerts": alerts()})
                    revision = engine.alert_revision
                await asyncio.sleep(session.telemetry_interval)
        except (WebSocketDisconnect, RuntimeError):
            return

    @app.websocket("/api/v1/stream/metrics")
    async def stream_metrics(websocket: WebSocket):
        await websocket.accept()
        try:
            while True:
                await websocket.send_json(metrics())
                await asyncio.sleep(session.telemetry_interval)
        except (WebSocketDisconnect, RuntimeError):
            return

    return app


def create_default_app() -> FastAPI:
    config_dir = Path(__file__).resolve().parents[3] / "configs"
    return create_app(load_config_bundle(config_dir))


app = create_default_app()
