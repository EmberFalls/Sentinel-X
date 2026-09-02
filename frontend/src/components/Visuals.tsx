import type { ReactNode } from "react";

import { formatDecimal, formatNumber } from "../runtime";
import type { AlertRecord, DetectorStatus, RuntimeMetrics, TimelinePoint } from "../types";

export function StatusBadge({ label, tone = "neutral" }: { label: string; tone?: "good" | "warning" | "danger" | "unknown" | "neutral" }) {
  return <span className={`status-badge status-badge--${tone}`}><span aria-hidden="true">●</span>{label}</span>;
}

export function MetricCard({ label, value, detail, history, unit }: { label: string; value: string; detail: string; history?: number[]; unit?: string }) {
  return <article className="metric-card">
    <div className="eyebrow">{label}</div>
    <div className="metric-card__value">{value}<small>{unit}</small></div>
    <div className="metric-card__detail">{detail}</div>
    {history ? <Sparkline values={history} label={`${label} recent activity`} /> : null}
  </article>;
}

export function Sparkline({ values, label, tone = "cyan" }: { values: number[]; label: string; tone?: "cyan" | "violet" | "amber" }) {
  const width = 260;
  const height = 46;
  const max = Math.max(...values, 0);
  const min = Math.min(...values, 0);
  const span = Math.max(max - min, 0.00001);
  const y = (value: number) => height - ((value - min) / span) * (height - 6) - 3;
  const points = values.map((value, index) => `${(index / Math.max(values.length - 1, 1)) * width},${y(value)}`).join(" ");
  return <svg className={`sparkline sparkline--${tone}`} role="img" aria-label={label} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
    {values.length === 1 ? <circle cx={width / 2} cy={y(values[0])} r="2" fill="currentColor" /> : <polyline points={points} fill="none" vectorEffect="non-scaling-stroke" />}
  </svg>;
}

export function Timeline({ history, metric, onMetricChange, alerts, onAlert }: { history: TimelinePoint[]; metric: "mbps" | "packets" | "flows"; onMetricChange: (metric: "mbps" | "packets" | "flows") => void; alerts: AlertRecord[]; onAlert?: (alert: AlertRecord) => void }) {
  const values = history.map((point) => metric === "mbps" ? point.mbps : metric === "packets" ? point.packetsPerSecond : point.flowsPerSecond);
  const max = Math.max(...values, 0);
  const label = metric === "mbps" ? "Processing Mbps" : metric === "packets" ? "Packets / sec" : "New flows / sec";
  const first = history.at(0)?.observedAt ?? 0;
  const last = history.at(-1)?.observedAt ?? first;
  const markers = alerts.flatMap((alert) => {
    const at = new Date(alert.emitted_at ?? alert.timestamp).getTime();
    return at >= first && at <= last ? [{ alert, left: ((at - first) / Math.max(last - first, 1)) * 100 }] : [];
  });
  return <section className="panel timeline-panel">
    <div className="panel__heading"><div><div className="eyebrow">REAL RUNTIME TELEMETRY</div><h2>Traffic timeline</h2></div><div className="segmented" aria-label="Timeline metric">
      {(["mbps", "packets", "flows"] as const).map((option) => <button key={option} className={metric === option ? "is-selected" : ""} onClick={() => onMetricChange(option)}>{option === "mbps" ? "Mbps" : option === "packets" ? "Packets/s" : "Flows/s"}</button>)}
    </div></div>
    <div className="chart-value"><strong>{formatDecimal(values.at(-1) ?? 0)}</strong><span>{label}</span></div>
    <div className="timeline-chart"><Sparkline values={values} label={`${label} over backend-aggregated telemetry samples`} />{markers.map(({ alert, left }) => <button key={alert.alert_id} className="alert-marker" style={{ left: `${left}%` }} aria-label={`Open ${alert.threat_class} alert`} onClick={() => onAlert?.(alert)} title={`${alert.threat_class} · ${formatDecimal(alert.calibrated_confidence * 100)}%`} />)}</div>
    <div className="timeline-meta"><span>Bounded history: {history.length} samples</span><span>{formatNumber(markers.length)} alert markers in view</span><span>Peak {formatDecimal(max)} {label}</span></div>
  </section>;
}

export function InspectionPipeline({ replayActive, detectors, metrics, onOpenDetails }: { replayActive: boolean; detectors: DetectorStatus[]; metrics: RuntimeMetrics | null; onOpenDetails: (panel: "detectors" | "evidence") => void }) {
  const stateLabel = replayActive ? "ACTIVE" : "IDLE";
  const modelsAvailable = detectors.some((item) => item.status === "READY");
  const featureState = (metrics?.feature_vectors ?? 0) > 0 ? "OBSERVED" : "WAITING";
  const evidenceState = (metrics?.evidence_decisions ?? 0) > 0 ? "EVALUATED" : "WAITING";
  return <section className="panel pipeline-panel">
    <div className="panel__heading"><div><div className="eyebrow">PASSIVE, READ-ONLY PROCESSING</div><h2>Inspection pipeline</h2></div><StatusBadge label={stateLabel} tone={replayActive ? "good" : "neutral"} /></div>
    <div className={`pipeline ${replayActive ? "pipeline--active" : ""}`}>
      <PipelineNode label="INGEST" state={stateLabel} detail={`${formatDecimal(metrics?.processing_rates.mbps ?? 0)} Mbps`} />
      <PipelineConnector active={replayActive} />
      <PipelineNode label="FLOWS" state={stateLabel} detail={`${formatDecimal(metrics?.processing_rates.flows_per_second ?? 0)} new/s`} />
      <PipelineConnector active={replayActive} />
      <PipelineNode label="FEATURES" state={featureState} detail={`${formatNumber(metrics?.feature_vectors ?? 0)} snapshots`} />
      <PipelineConnector active={replayActive && modelsAvailable} />
      <PipelineNode label="DETECT" state={modelsAvailable ? stateLabel : "UNAVAILABLE"} detail={`${formatNumber(metrics?.inference_vectors ?? 0)} model vectors`} unavailable={!modelsAvailable} onClick={() => onOpenDetails("detectors")} />
      <PipelineConnector active={replayActive && modelsAvailable} />
      <PipelineNode label="EVIDENCE" state={evidenceState} detail={`${formatNumber(metrics?.evidence_decisions ?? 0)} decisions`} onClick={() => onOpenDetails("evidence")} />
      <PipelineConnector active={replayActive && (metrics?.alerts ?? 0) > 0} />
      <PipelineNode label="ALERT" state={(metrics?.alerts ?? 0) > 0 ? "DECISIONS" : "NO DECISIONS"} detail={`${formatNumber(metrics?.alerts ?? 0)} alert records`} />
    </div>
  </section>;
}

function PipelineNode({ label, state, detail, unavailable = false, onClick }: { label: string; state: string; detail: string; unavailable?: boolean; onClick?: () => void }) {
  const content = <><strong>{label}</strong><span>{state}</span><small>{detail}</small></>;
  return onClick ? <button className={`pipeline-node pipeline-node--button ${unavailable ? "pipeline-node--unavailable" : ""}`} onClick={onClick}>{content}</button> : <div className={`pipeline-node ${unavailable ? "pipeline-node--unavailable" : ""}`}>{content}</div>;
}

function PipelineConnector({ active }: { active: boolean }) {
  return <div className={`pipeline-connector ${active ? "pipeline-connector--active" : ""}`} aria-hidden="true"><span /></div>;
}

export function KeyValue({ label, children }: { label: string; children: ReactNode }) {
  return <div className="key-value"><span>{label}</span><strong>{children}</strong></div>;
}
