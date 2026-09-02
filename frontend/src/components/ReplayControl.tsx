import { useState } from "react";

import { api } from "../runtime";
import type { RuntimeStatus } from "../types";
import { StatusBadge } from "./Visuals";

export function ReplayControl({ status, onComplete }: { status: RuntimeStatus | null; onComplete: () => Promise<void> }) {
  const [capture, setCapture] = useState("");
  const [mode, setMode] = useState("fast");
  const [speed, setSpeed] = useState(2);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const control = async (path: string, body?: object) => {
    setBusy(true);
    try {
      const result = await api<{ status: string }>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
      setMessage(result.status.toUpperCase());
      await onComplete();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Replay control failed");
    } finally {
      setBusy(false);
    }
  };
  const replayState = status?.replay_state ?? "IDLE";
  const displayedMode = status?.replay_running ? status.mode : mode;
  const displayedSpeed = status?.replay_running ? status.speed_multiplier : speed;
  return <section className="panel replay-control">
    <div className="panel__heading"><div><div className="eyebrow">APPROVED LOCAL SOURCE</div><h2>Replay control center</h2></div><StatusBadge label={replayState} tone={replayState === "RUNNING" ? "good" : replayState === "PAUSED" ? "warning" : "neutral"} /></div>
    <div className="replay-source"><span>SOURCE</span><strong>{status?.capture ?? "Select a .cap, .pcap, or .pcapng file"}</strong><span>MODE</span><strong>{status?.mode?.toUpperCase() ?? "—"}</strong></div>
    <label className="capture-input">Capture filename<input value={capture} onChange={(event) => setCapture(event.target.value)} placeholder="http.cap" disabled={busy || Boolean(status?.replay_running)} /></label>
    <div className="replay-options">
      <label>Replay mode<select aria-label="Replay mode" value={displayedMode} onChange={(event) => setMode(event.target.value)} disabled={busy || Boolean(status?.replay_running)}>
        <option value="paced">PACED · presentation</option><option value="fast">FAST · no capture delay</option><option value="benchmark">BENCHMARK · minimal updates</option>
      </select></label>
      {displayedMode === "paced" ? <label>Replay speed<select aria-label="Replay speed" value={displayedSpeed} onChange={(event) => setSpeed(Number(event.target.value))} disabled={busy || Boolean(status?.replay_running)}>
        {[1, 2, 5, 10].map((value) => <option key={value} value={value}>{value}×</option>)}
      </select></label> : null}
    </div>
    {status?.progress != null ? <div className="replay-progress"><progress value={status.progress} max={1} aria-label="Capture processing progress" /><span>{(status.progress * 100).toFixed(1)}% of capture file processed · {status.mode.toUpperCase()}{status.mode === "paced" ? ` · ${status.speed_multiplier}×` : ""}</span></div> : null}
    <div className="control-row"><button className="button button--primary" onClick={() => void control("/api/v1/replay/start", { capture: capture.trim(), mode, speed_multiplier: speed })} disabled={busy || !capture.trim() || !status || Boolean(status?.replay_running)}>Start replay</button>
      {status?.replay_running && !status.replay_paused ? <button className="button" onClick={() => void control("/api/v1/replay/pause")} disabled={busy}>Pause</button> : null}
      {status?.replay_running && status.replay_paused ? <button className="button" onClick={() => void control("/api/v1/replay/resume")} disabled={busy}>Resume</button> : null}
      <button className="button" onClick={() => void control("/api/v1/replay/stop")} disabled={busy || !status?.replay_running}>Stop</button>
      <button className="button button--quiet" onClick={() => void control("/api/v1/replay/reset")} disabled={busy || Boolean(status?.replay_running)}>Reset telemetry</button></div>
    <p className="control-message" role="status">{status?.error || message || "Each replay starts a fresh session. Processing throughput measures this laptop; it is separate from the capture's original traffic rate."}</p>
  </section>;
}
