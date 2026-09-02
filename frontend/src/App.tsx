import { useEffect, useMemo, useState } from "react";

import { AlertInspector } from "./components/AlertInspector";
import { ReplayControl } from "./components/ReplayControl";
import { InspectionPipeline, KeyValue, MetricCard, StatusBadge, Timeline } from "./components/Visuals";
import { useRuntimeTelemetry } from "./hooks/useRuntimeTelemetry";
import { alertDecisionCounts, formatBytes, formatDecimal, formatEndpoint, formatNumber, formatTime } from "./runtime";
import type { AlertRecord, DetectorStatus } from "./types";

type Page = "monitor" | "alerts" | "traffic" | "detectors" | "performance";
type TimelineMetric = "mbps" | "packets" | "flows";
type LiveDetail = "detectors" | "evidence" | null;

const navigation: Array<{ id: Page; label: string; number: string }> = [
  { id: "monitor", label: "Live monitor", number: "01" },
  { id: "alerts", label: "Alerts", number: "02" },
  { id: "traffic", label: "Traffic", number: "03" },
  { id: "detectors", label: "Detectors", number: "04" },
  { id: "performance", label: "Performance", number: "05" },
];

const coverage = [
  ["DDoS", "behaviour", "Rate + target concentration"],
  ["Bot / C2-like", "behaviour", "CICIDS Bot mapping + runtime recurrence"],
  ["Recon", "behaviour", "Destination + port diversity"],
  ["DGA", "dns", "DNS lexical features"],
  ["DNS tunnel", "dns", "Lexical + query frequency"],
  ["Suspicious encrypted", "tls_quic", "Passive metadata"],
] as const;

export function App() {
  const runtime = useRuntimeTelemetry();
  const [page, setPage] = useState<Page>("monitor");
  const [timelineMetric, setTimelineMetric] = useState<TimelineMetric>("mbps");
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null);
  const [liveDetail, setLiveDetail] = useState<LiveDetail>(null);
  const [presentationMode, setPresentationMode] = useState(false);
  const latest = runtime.history.at(-1);
  const decisions = useMemo(() => runtime.metrics?.decisions ?? alertDecisionCounts(runtime.alerts), [runtime.metrics?.decisions, runtime.alerts]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() === "p" && !(event.target instanceof HTMLInputElement)) setPresentationMode((current) => !current);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => { setSelectedAlert(null); }, [runtime.status?.run_id]);

  const activeDetectors = runtime.detectors.filter((detector) => detector.enabled).length;
  const monitorState = runtime.connected && runtime.status?.passive_monitor ? "ACTIVE" : "OFFLINE";
  const replayState = runtime.status?.replay_state ?? "IDLE";

  return <div className={`app-shell ${presentationMode ? "presentation-mode" : ""}`}>
    <header className="global-status-bar">
      <div className="brand"><div className="brand__name">CUSTODIAN</div><div className="brand__subtitle">PASSIVE THREAT OBSERVATION</div></div>
      <div className="system-state" title="Custodian receives copied traffic only and does not transmit into the monitored network.">
        <StatusItem label="MONITOR" value={monitorState} tone={monitorState === "ACTIVE" ? "good" : "danger"} />
        <StatusItem label="RETURN PATH" value={runtime.status?.return_path ?? "NONE"} tone="neutral" />
        <StatusItem label="SOURCE" value={runtime.status?.source_type?.replaceAll("_", " ") ?? "CONNECTING"} tone="neutral" />
        <StatusItem label="MODE" value={runtime.status?.mode?.toUpperCase() ?? "—"} tone="neutral" />
        <StatusItem label="PROGRESS" value={runtime.status?.progress == null ? "—" : `${(runtime.status.progress * 100).toFixed(0)}%`} tone="neutral" />
      </div>
      <div className="connection-state"><StatusBadge label={runtime.connected ? replayState : "TELEMETRY LOST"} tone={runtime.connected ? replayState === "RUNNING" ? "good" : replayState === "PAUSED" ? "warning" : "neutral" : "danger"} /><button className="presentation-toggle" onClick={() => setPresentationMode((current) => !current)}>Presentation {presentationMode ? "on" : "off"}</button></div>
    </header>
    <nav className="primary-nav" aria-label="Primary navigation">{navigation.map((item) => <button key={item.id} className={page === item.id ? "is-active" : ""} onClick={() => setPage(item.id)}><span>{item.number}</span>{item.label}</button>)}</nav>
    {!runtime.connected ? <div className="connection-banner"><strong>Telemetry connection lost.</strong> {runtime.error ?? "Attempting to reconnect to the local runtime."}</div> : null}
    <main className="dashboard">{page === "monitor" ? <LiveMonitor runtime={runtime} latest={latest} decisions={decisions} timelineMetric={timelineMetric} onTimelineMetric={setTimelineMetric} selectedAlert={selectedAlert} onSelectAlert={setSelectedAlert} liveDetail={liveDetail} onLiveDetail={setLiveDetail} /> : null}
      {page === "alerts" ? <AlertsPage alerts={runtime.alerts} selectedAlert={selectedAlert} onSelectAlert={setSelectedAlert} /> : null}
      {page === "traffic" ? <TrafficPage runtime={runtime} latest={latest} timelineMetric={timelineMetric} onTimelineMetric={setTimelineMetric} /> : null}
      {page === "detectors" ? <DetectorsPage detectors={runtime.detectors} activeDetectors={activeDetectors} /> : null}
      {page === "performance" ? <PerformancePage runtime={runtime} latest={latest} /> : null}
    </main>
  </div>;
}

function LiveMonitor({ runtime, latest, decisions, timelineMetric, onTimelineMetric, selectedAlert, onSelectAlert, liveDetail, onLiveDetail }: { runtime: ReturnType<typeof useRuntimeTelemetry>; latest: ReturnType<typeof useRuntimeTelemetry>["history"][number] | undefined; decisions: Record<string, number>; timelineMetric: TimelineMetric; onTimelineMetric: (value: TimelineMetric) => void; selectedAlert: AlertRecord | null; onSelectAlert: (alert: AlertRecord | null) => void; liveDetail: LiveDetail; onLiveDetail: (detail: LiveDetail) => void }) {
  const history = runtime.history;
  return <div className="page-grid">
    <section className="live-ingest-strip" aria-label="Live ingest telemetry">
      <MetricCard label="DATA INSPECTED" value={formatBytes(runtime.metrics?.bytes ?? 0)} detail="Real bytes from local replay" history={history.map((point) => point.bytes)} />
      <MetricCard label="PACKETS" value={formatNumber(runtime.metrics?.packets ?? 0)} detail={`${formatDecimal(runtime.metrics?.processing_rates.packets_per_second ?? 0)} processing / sec`} history={history.map((point) => point.packetsPerSecond)} />
      <MetricCard label="FLOWS ANALYSED" value={formatNumber(runtime.metrics?.flows ?? 0)} detail={`${formatNumber(runtime.status?.active_flows ?? 0)} active`} history={history.map((point) => point.flowsPerSecond)} />
      <MetricCard label="PROCESSING THROUGHPUT" value={formatDecimal(runtime.status?.replay_running ? runtime.metrics?.processing_rates.mbps ?? 0 : runtime.metrics?.average_processing_rates.mbps ?? 0)} unit="Mbps" detail={runtime.status?.replay_running ? "Current replay processing rate" : "Last replay average, if available"} history={history.map((point) => point.mbps)} />
    </section>
    <section className="monitor-grid">
      <Timeline history={history} metric={timelineMetric} onMetricChange={onTimelineMetric} alerts={runtime.alerts} onAlert={onSelectAlert} />
      <InspectionPipeline replayActive={Boolean(runtime.status?.replay_running && !runtime.status?.replay_paused)} detectors={runtime.detectors} metrics={runtime.metrics} onOpenDetails={onLiveDetail} />
    </section>
    <section className="monitor-bottom"><AlertTable alerts={runtime.alerts} selected={selectedAlert} onSelect={onSelectAlert} compact /></section>
    <ReplayControl status={runtime.status} onComplete={runtime.refresh} />
    {liveDetail ? <aside className="live-detail-drawer"><button className="icon-button" onClick={() => onLiveDetail(null)} aria-label="Close details">×</button>{liveDetail === "detectors" ? <DetectorCards detectors={runtime.detectors} activeDetectors={runtime.detectors.filter((detector) => detector.enabled).length} /> : <EvidenceGate decisions={decisions} alerts={runtime.alerts} />}</aside> : null}
    {selectedAlert ? <div className="live-alert-drawer"><AlertInspector alert={selectedAlert} onClose={() => onSelectAlert(null)} /></div> : null}
  </div>;
}

function DetectorCards({ detectors, activeDetectors }: { detectors: DetectorStatus[]; activeDetectors: number }) {
  const labels: Record<DetectorStatus["id"], string> = { behaviour: "BEHAVIOUR", dns: "DNS", tls_quic: "TLS / QUIC" };
  return <section className="panel detector-group">
    <div className="panel__heading"><div><div className="eyebrow">MODEL RUNTIME</div><h2>Detector families</h2></div><span className="muted">{activeDetectors} / 3 loaded</span></div>
    <div className="detector-cards">{detectors.map((detector) => <article className="detector-card" key={detector.id}>
      <div><span className="eyebrow">{labels[detector.id]} MODEL</span><StatusBadge label={detector.status} tone={detector.enabled ? "good" : "neutral"} /></div>
      <strong>{detector.model_version ?? (detector.status === "PLANNED" ? "Deferred by prototype scope" : "No complete artifact")}</strong>
      <p>{detector.enabled ? `${detector.schema_version} · ${detector.classes.join(" · ")}` : detector.reason ?? "No complete model artifact is available."}</p>
    </article>)}</div>
  </section>;
}

function EvidenceGate({ decisions, alerts }: { decisions: Record<string, number>; alerts: AlertRecord[] }) {
  const latest = alerts.at(-1);
  return <section className="panel evidence-gate"><div className="panel__heading"><div><div className="eyebrow">CAPABILITY-AWARE POLICY</div><h2>Evidence gate</h2></div><StatusBadge label={alerts.length ? "EVALUATED" : "WAITING"} tone={alerts.length ? "good" : "neutral"} /></div><div className="gate-counts"><KeyValue label="ACCEPTED">{formatNumber(decisions.ACCEPT ?? 0)}</KeyValue><KeyValue label="UNKNOWN">{formatNumber(decisions.UNKNOWN_SUSPICIOUS ?? 0)}</KeyValue><KeyValue label="INSUFFICIENT">{formatNumber(decisions.INSUFFICIENT_EVIDENCE ?? 0)}</KeyValue></div>{latest ? <div className="gate-latest"><strong>{latest.threat_class} candidate</strong><span>{formatDecimal(latest.calibrated_confidence * 100)}% calibrated</span><StatusBadge label={latest.decision.replaceAll("_", " ")} tone={latest.decision === "ACCEPT" ? "good" : "warning"} /></div> : <p className="empty-copy">No model candidate has reached the Evidence Gate. This is expected while real model artifacts are unavailable.</p>}</section>;
}

function AlertTable({ alerts, selected, onSelect, compact = false }: { alerts: AlertRecord[]; selected: AlertRecord | null; onSelect: (alert: AlertRecord) => void; compact?: boolean }) {
  const visibleAlerts = alerts.slice(compact ? -6 : 0);
  return <section className="panel alert-feed"><div className="panel__heading"><div><div className="eyebrow">STANDARDIZED ALERTRECORDS</div><h2>{compact ? "Recent alerts" : "Live alert feed"}</h2></div><span className="muted">{formatNumber(alerts.length)} records</span></div>{alerts.length === 0 ? <div className="empty-state"><strong>NO EVIDENCE-BACKED ALERTS</strong><p>Traffic may be observed, but no real detector decision has been emitted.</p></div> : <div className="table-scroll"><table><thead>{compact ? <tr><th>Time</th><th>Threat</th><th>Severity</th><th>Source → destination</th><th>Confidence</th><th>Evidence</th></tr> : <tr><th>Time</th><th>Threat</th><th>Severity</th><th>Source</th><th>Destination</th><th>Confidence</th><th>Evidence</th><th>Decision</th></tr>}</thead><tbody>{visibleAlerts.map((alert) => <tr key={alert.alert_id} className={selected?.alert_id === alert.alert_id ? "is-selected" : ""} onClick={() => onSelect(alert)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") onSelect(alert); }}><td>{formatTime(alert.emitted_at ?? alert.timestamp)}</td><td>{alert.threat_class}</td><td><StatusBadge label={alert.severity} tone={alert.severity === "CRITICAL" ? "danger" : alert.severity === "HIGH" ? "warning" : "neutral"} /></td>{compact ? <td className="mono">{formatEndpoint(alert.source)} → {formatEndpoint(alert.destination)}</td> : <><td className="mono">{formatEndpoint(alert.source)}</td><td className="mono">{formatEndpoint(alert.destination)}</td></>}<td>{formatDecimal(alert.calibrated_confidence * 100)}%</td><td>{alert.evidence_quality}</td>{!compact ? <td><StatusBadge label={alert.decision.replaceAll("_", " ")} tone={alert.decision === "ACCEPT" ? "good" : alert.decision === "UNKNOWN_SUSPICIOUS" ? "unknown" : "warning"} /></td> : null}</tr>)}</tbody></table></div>}</section>;
}

function AlertsPage({ alerts, selectedAlert, onSelectAlert }: { alerts: AlertRecord[]; selectedAlert: AlertRecord | null; onSelectAlert: (alert: AlertRecord | null) => void }) {
  return <div className="page-with-inspector"><AlertTable alerts={alerts} selected={selectedAlert} onSelect={onSelectAlert} /><AlertInspector alert={selectedAlert} onClose={() => onSelectAlert(null)} /></div>;
}

function TrafficPage({ runtime, latest, timelineMetric, onTimelineMetric }: { runtime: ReturnType<typeof useRuntimeTelemetry>; latest: ReturnType<typeof useRuntimeTelemetry>["history"][number] | undefined; timelineMetric: TimelineMetric; onTimelineMetric: (value: TimelineMetric) => void }) {
  return <div className="page-grid"><Timeline history={runtime.history} metric={timelineMetric} onMetricChange={onTimelineMetric} alerts={runtime.alerts} /><section className="traffic-stat-grid"><MetricCard label="TOTAL BYTES" value={formatBytes(runtime.metrics?.bytes ?? 0)} detail="Capture frames processed" /><MetricCard label="PACKET RATE" value={formatDecimal(latest?.packetsPerSecond ?? 0)} unit="/ sec" detail="Derived from real samples" /><MetricCard label="NEW FLOW RATE" value={formatDecimal(latest?.flowsPerSecond ?? 0)} unit="/ sec" detail="Derived from real samples" /></section><section className="panel unavailable-panel"><div className="eyebrow">ACTIVE FLOW TABLE</div><h2>Flow details are not exposed by the current runtime API</h2><p>The runtime does maintain active flow state and reports its count. This frontend deliberately does not invent an active-flow table; a future read-only flow-summary endpoint can populate it.</p></section></div>;
}

function DetectorsPage({ detectors, activeDetectors }: { detectors: DetectorStatus[]; activeDetectors: number }) {
  return <div className="page-grid"><DetectorCards detectors={detectors} activeDetectors={activeDetectors} /><section className="panel coverage-matrix"><div className="panel__heading"><div><div className="eyebrow">JUDGE-FACING COVERAGE</div><h2>Detector coverage matrix</h2></div></div><div className="table-scroll"><table><thead><tr><th>Threat</th><th>Model</th><th>Primary evidence</th><th>Runtime status</th></tr></thead><tbody>{coverage.map(([threat, model, evidence]) => { const detector = detectors.find((item) => item.id === model); return <tr key={threat}><td>{threat}</td><td>{model.replaceAll("_", " ")}</td><td>{evidence}</td><td><StatusBadge label={detector?.status ?? "UNAVAILABLE"} tone={detector?.enabled ? "good" : "neutral"} /></td></tr>; })}</tbody></table></div><p className="panel-note">The Behaviour prototype targets BENIGN, DDOS, RECON and BOT_OR_C2_LIKE only. Bot is not a validated C2-beaconing label. DNS/TLS are planned; exfiltration is not trained.</p></section></div>;
}

function PerformancePage({ runtime, latest }: { runtime: ReturnType<typeof useRuntimeTelemetry>; latest: ReturnType<typeof useRuntimeTelemetry>["history"][number] | undefined }) {
  const metrics = runtime.metrics;
  const latency = metrics?.latency_ms.total_pipeline;
  const processing = runtime.status?.replay_running ? metrics?.processing_rates : metrics?.average_processing_rates;
  const stages = ["parse", "flow", "state", "features", "inference", "inference_batch", "evidence", "alert", "total_pipeline"];
  return <div className="page-grid">
    <section className="performance-hero">
      <MetricCard label="PROCESSING THROUGHPUT" value={formatDecimal(processing?.mbps ?? 0)} unit="Mbps" detail={runtime.status?.replay_running ? "Current processing interval" : "Last replay average"} history={runtime.history.map((point) => point.mbps)} />
      <MetricCard label="NEW FLOWS" value={formatDecimal(processing?.flows_per_second ?? 0)} unit="/ sec" detail="Distinct flow sessions, not packet updates" />
      <MetricCard label="P50 PIPELINE" value={latency ? formatDecimal(latency.p50) : "—"} unit="ms" detail="Snapshot eligibility to decision, including batch wait" />
      <MetricCard label="P95 PIPELINE" value={latency ? formatDecimal(latency.p95) : "—"} unit="ms" detail="Awaiting inference if model unavailable" />
    </section>
    <section className="performance-chart-grid">
      <Timeline history={runtime.history} metric="mbps" onMetricChange={() => undefined} alerts={runtime.alerts} />
      <section className="panel resource-panel"><div className="eyebrow">LOCAL PROCESS RESOURCES</div><h2>Measured replay</h2>
        <KeyValue label="CPU">{formatDecimal(metrics?.cpu_percent ?? 0)}%</KeyValue>
        <KeyValue label="Memory">{formatBytes(metrics?.memory_bytes ?? 0)}</KeyValue>
        <KeyValue label="Elapsed">{formatDecimal(metrics?.elapsed_seconds ?? 0)} s</KeyValue>
        <KeyValue label="Original capture average">{metrics?.observed_average_mbps != null ? `${formatDecimal(metrics.observed_average_mbps, 4)} Mbps` : "Unavailable"}</KeyValue>
        <KeyValue label="Feature snapshots">{formatNumber(metrics?.feature_vectors ?? 0)}</KeyValue>
        <KeyValue label="Inference vectors / batches">{formatNumber(metrics?.inference_vectors ?? 0)} / {formatNumber(metrics?.inference_batches ?? 0)}</KeyValue>
        <KeyValue label="Skipped non-IP / unsupported frames">{formatNumber(metrics?.skipped_frames ?? 0)}</KeyValue>
        <p className="panel-note">Processing speed is measured on this laptop. It is separate from the original capture's traffic rate. Inference latency per vector is the measured batch time divided by its size.</p>
      </section>
    </section>
    <section className="panel"><h2>Measured stage latency</h2><table><thead><tr><th>Stage</th><th>P50</th><th>P95</th></tr></thead><tbody>{stages.map((stage) => {
      const timing = metrics?.latency_ms[stage];
      return <tr key={stage}><td>{stage.replaceAll("_", " ")}</td><td>{timing ? `${formatDecimal(timing.p50, 4)} ms` : "Not measured"}</td><td>{timing ? `${formatDecimal(timing.p95, 4)} ms` : "Not measured"}</td></tr>;
    })}</tbody></table><p className="panel-note">BENCHMARK samples packet stages every 32 frames. Model stages remain unmeasured until a real package is available.</p></section>
  </div>;
}

function StatusItem({ label, value, tone }: { label: string; value: string; tone: "good" | "danger" | "neutral" }) {
  return <div className="status-item"><span>{label}</span><StatusBadge label={value} tone={tone} /></div>;
}
