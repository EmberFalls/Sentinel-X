export type Decision = "ACCEPT" | "UNKNOWN_SUSPICIOUS" | "INSUFFICIENT_EVIDENCE";

export interface Endpoint {
  ip: string;
  port?: number | null;
}

export interface AlertRecord {
  alert_id: string;
  timestamp: string;
  flow_id?: string | null;
  window_id?: string | null;
  threat_class: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  decision: Decision;
  calibrated_confidence: number;
  raw_score?: number | null;
  class_threshold?: number | null;
  emitted_at?: string | null;
  evidence_quality: "STRONG" | "ADEQUATE" | "WEAK" | "INSUFFICIENT";
  source?: Endpoint | null;
  destination?: Endpoint | null;
  evidence: Record<string, unknown>;
  missing_evidence: string[];
  capabilities?: Record<string, boolean> | null;
  detector_id: string;
  model_version: string;
  feature_schema_version: string;
  inference_latency_ms: number;
  total_pipeline_latency_ms: number;
}

export interface DetectorStatus {
  id: "behaviour" | "dns" | "tls_quic";
  enabled: boolean;
  reason: string | null;
  status: "READY" | "PLANNED" | "UNAVAILABLE";
  model_version: string | null;
  schema_version: string;
  classes: string[];
}

export interface RuntimeStatus {
  passive_monitor: boolean;
  return_path: string;
  replay_running: boolean;
  replay_paused: boolean;
  capture: string | null;
  active_flows: number;
  source_type: string;
  mode: string;
  speed_multiplier: number;
  replay_state: string;
  progress: number | null;
  progress_basis: string;
  error: string | null;
  run_id: number;
  telemetry_interval_ms: number;
}

export interface LatencyPercentiles {
  p50: number;
  p95: number;
}

export interface RuntimeMetrics {
  packets: number;
  flow_updates: number;
  flows: number;
  parsed_packets: number;
  skipped_frames: number;
  feature_vectors: number;
  inference_vectors: number;
  inference_batches: number;
  evidence_decisions: number;
  decisions: Record<string, number>;
  bytes: number;
  alerts: number;
  cpu_percent: number;
  memory_bytes: number;
  latency_ms: Record<string, LatencyPercentiles | null>;
  processing_rates: { mbps: number; packets_per_second: number; flows_per_second: number };
  average_processing_rates: { mbps: number | null; packets_per_second: number | null; flows_per_second: number | null };
  elapsed_seconds: number;
  active_seconds: number;
  observed_average_mbps: number | null;
  sampled_at: number;
  rate_samples: Array<{ observed_at: number; bytes: number; packets: number; flows: number; flow_updates: number; mbps: number; packets_per_second: number; flows_per_second: number }>;
}

export interface TimelinePoint {
  observedAt: number;
  bytes: number;
  packets: number;
  flowUpdates: number;
  flows: number;
  featureVectors: number;
  inferenceVectors: number;
  evidenceDecisions: number;
  activeFlows: number;
  mbps: number;
  packetsPerSecond: number;
  flowsPerSecond: number;
  cpuPercent: number;
  memoryBytes: number;
  p50LatencyMs: number | null;
  p95LatencyMs: number | null;
}

export interface RuntimeSnapshot {
  status: RuntimeStatus | null;
  metrics: RuntimeMetrics | null;
  detectors: DetectorStatus[];
  alerts: AlertRecord[];
  history: TimelinePoint[];
  connected: boolean;
  error: string | null;
}

export interface TelemetryEnvelope {
  status: RuntimeStatus;
  metrics: RuntimeMetrics;
  detectors: DetectorStatus[];
}
