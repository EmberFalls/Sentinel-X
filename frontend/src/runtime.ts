import type { AlertRecord, RuntimeMetrics, RuntimeStatus, TimelinePoint } from "./types";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  const text = await response.text();
  let payload: unknown;
  try { payload = JSON.parse(text); }
  catch { throw new Error("The local API is unavailable. Start the Custodian backend on port 8000."); }
  if (!response.ok) {
    const detail = typeof payload === "object" && payload !== null && "detail" in payload
      ? String(payload.detail)
      : `Request failed (${response.status})`;
    throw new Error(detail);
  }
  return payload as T;
}

export function makeTimelinePoint(
  metrics: RuntimeMetrics,
  status: RuntimeStatus,
  previous: TimelinePoint | undefined,
  observedAt: number,
): TimelinePoint {
  const elapsedSeconds = previous ? Math.max((observedAt - previous.observedAt) / 1000, 0.001) : 1;
  const bytesDelta = previous ? Math.max(metrics.bytes - previous.bytes, 0) : 0;
  const packetsDelta = previous ? Math.max(metrics.packets - previous.packets, 0) : 0;
  const flowsDelta = previous ? Math.max(metrics.flows - previous.flows, 0) : 0;
  const latency = metrics.latency_ms.total_pipeline;
  return {
    observedAt,
    bytes: metrics.bytes,
    packets: metrics.packets,
    flowUpdates: metrics.flow_updates,
    flows: metrics.flows,
    featureVectors: metrics.feature_vectors,
    inferenceVectors: metrics.inference_vectors,
    evidenceDecisions: metrics.evidence_decisions,
    activeFlows: status.active_flows,
    mbps: metrics.processing_rates?.mbps ?? (bytesDelta * 8) / elapsedSeconds / 1_000_000,
    packetsPerSecond: metrics.processing_rates?.packets_per_second ?? packetsDelta / elapsedSeconds,
    flowsPerSecond: metrics.processing_rates?.flows_per_second ?? flowsDelta / elapsedSeconds,
    cpuPercent: metrics.cpu_percent,
    memoryBytes: metrics.memory_bytes,
    p50LatencyMs: latency?.p50 ?? null,
    p95LatencyMs: latency?.p95 ?? null,
  };
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 }).format(value);
}

export function formatDecimal(value: number, digits = 2): string {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: digits }).format(value);
}

export function formatBytes(value: number): string {
  if (value < 1024) return `${formatNumber(value)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${formatDecimal(size)} ${units[unit]}`;
}

export function formatEndpoint(endpoint?: { ip: string; port?: number | null } | null): string {
  if (!endpoint) return "—";
  return endpoint.port === undefined || endpoint.port === null ? endpoint.ip : `${endpoint.ip}:${endpoint.port}`;
}

export function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleTimeString();
}

export function alertDecisionCounts(alerts: AlertRecord[]): Record<string, number> {
  return alerts.reduce<Record<string, number>>((counts, alert) => {
    counts[alert.decision] = (counts[alert.decision] ?? 0) + 1;
    return counts;
  }, {});
}
