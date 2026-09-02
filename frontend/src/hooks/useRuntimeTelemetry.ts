import { useCallback, useEffect, useRef, useState } from "react";

import { api, makeTimelinePoint } from "../runtime";
import type { AlertRecord, RuntimeSnapshot, TelemetryEnvelope, TimelinePoint } from "../types";

const HISTORY_LIMIT = 720;
const initialSnapshot: RuntimeSnapshot = {
  status: null, metrics: null, detectors: [], alerts: [], history: [], connected: false, error: null,
};

export function useRuntimeTelemetry(): RuntimeSnapshot & { refresh: () => Promise<void> } {
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot>(initialSnapshot);
  const alertRef = useRef<{ run_id: number; alerts: AlertRecord[] } | null>(null);
  const alive = useRef(true);

  const applyTelemetry = useCallback(({ status, metrics, detectors }: TelemetryEnvelope) => {
    if (!alive.current) return;
    setSnapshot((previous) => {
      const sameRun = previous.status?.run_id === status.run_id;
      const retained = sameRun ? previous.history : [];
      const byTime = new Map(retained.map((point) => [point.observedAt, point]));
      const history: TimelinePoint[] = metrics.rate_samples.slice(-HISTORY_LIMIT).map((sample) => {
        const existing = byTime.get(sample.observed_at);
        if (existing) return existing;
        const point = makeTimelinePoint(metrics, status, undefined, sample.observed_at);
        return {
          ...point, bytes: sample.bytes, packets: sample.packets, flows: sample.flows,
          flowUpdates: sample.flow_updates, mbps: sample.mbps,
          packetsPerSecond: sample.packets_per_second, flowsPerSecond: sample.flows_per_second,
        };
      });
      const alerts = alertRef.current?.run_id === status.run_id ? alertRef.current.alerts : sameRun ? previous.alerts : [];
      return { status, metrics, detectors, alerts, history, connected: true, error: status.error };
    });
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [telemetry, alerts] = await Promise.all([
        api<TelemetryEnvelope>("/api/v1/telemetry"),
        api<AlertRecord[]>("/api/v1/alerts"),
      ]);
      alertRef.current = { run_id: telemetry.status.run_id, alerts };
      applyTelemetry(telemetry);
    } catch (error) {
      if (alive.current) setSnapshot((previous) => ({
        ...previous, connected: false,
        error: error instanceof Error ? error.message : "Unable to reach the local runtime",
      }));
    }
  }, [applyTelemetry]);

  useEffect(() => {
    alive.current = true;
    let stopped = false;
    const sockets = new Set<WebSocket>();
    const retries = new Set<number>();
    const connect = (kind: "telemetry" | "alerts") => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const socket = new WebSocket(`${protocol}//${window.location.host}/api/v1/stream/${kind}`);
      sockets.add(socket);
      socket.onmessage = (event) => {
        if (stopped) return;
        try {
          const payload = JSON.parse(event.data);
          if (kind === "telemetry") applyTelemetry(payload as TelemetryEnvelope);
          else {
            alertRef.current = payload;
            setSnapshot((previous) => previous.status?.run_id === payload.run_id
              ? { ...previous, alerts: payload.alerts } : previous);
          }
        } catch {
          setSnapshot((previous) => ({ ...previous, error: "Received invalid runtime telemetry." }));
        }
      };
      socket.onclose = () => {
        sockets.delete(socket);
        if (stopped) return;
        if (kind === "telemetry") setSnapshot((previous) => ({
          ...previous, connected: false, error: "Telemetry connection lost. Reconnecting to the local API…",
        }));
        const timer = window.setTimeout(() => { retries.delete(timer); connect(kind); }, 1000);
        retries.add(timer);
      };
      socket.onerror = () => socket.close();
    };
    void refresh();
    connect("telemetry");
    connect("alerts");
    return () => {
      stopped = true;
      alive.current = false;
      retries.forEach(window.clearTimeout);
      sockets.forEach((socket) => socket.close());
    };
  }, [applyTelemetry, refresh]);

  return { ...snapshot, refresh };
}
