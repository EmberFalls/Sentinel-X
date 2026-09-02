# One-model / fast-PCAP implementation report

Updated 2026-09-02. Scope: `SENTINEL-X_Prototype_OneModel_FastPCAP_Codex.md`, preserving the passive prototype architecture and dark-green UI.

## Outcome

Runtime, training/export code, batch integration, Evidence Gate and UI updates are implemented. XGBoost 3.4.1 loaded successfully after the user changed the local Windows policy, and the actual `behaviour-xgb-v1` package was trained, calibrated, hash-verified and loaded. The API reports Behaviour as READY. DNS and TLS/QUIC remain PLANNED.

The earlier WinError 4551 was a Windows application-control block. No bypass was made by this project. Do not present the CSV evaluation as leakage-free host/session/streaming-PCAP accuracy, and do not infer safety from a zero-alert capture replay.

## Phase status and changed areas

Paths are relative to the repository root. Useful existing code was extended. Pre-existing unrelated deletions and teammate changes were preserved.

| Phase | Implementation and files | Validation / outstanding work |
| --- | --- | --- |
| A: audit | Inspected per-packet pipeline, training wrappers, configs, UI, captures and CSVs. | Found repeated snapshots/state rebuilding, per-packet inference setup, default timestamp pacing, missing trained artifacts. |
| B: replay | `src/sentinelx/ingest/{pcap,replay}.py`, `api/app.py`, `configs/replay.yaml` | Streaming format detection, Ethernet/IP validation, three modes, interruptible waits and file progress. Unit/API tests and real `.cap` replays pass. |
| C: state | `flow/{manager,record}.py`, `state/{manager,windows}.py`, `core/schemas.py`, `parsing/packet.py`, `config.py`, `configs/default.yaml` | Lazy snapshots, online statistics, first-sender direction, bounded LRU flows and indexed temporal events. Tests pass. |
| D: features | `features/{behaviour,behaviour_flow,schema}.py`, `observation/capabilities.py` | Shared vectorized/scalar math. Exact CSV/runtime arithmetic parity test passes; temporal signals remain runtime-only evidence. |
| E: training | `training/{cicids2017,train_behaviour,splits}.py`, `pyproject.toml` | Real CSV cleaning, provenance, grouped four-way split, weighted XGBoost training/export code. Training completed in 9.865 s and the versioned package was exported. |
| F: calibration / evidence | `models/{calibrator,loader,compatibility}.py`, `evidence/gate.py`, `alerts/{builder,dedupe}.py`, `core/enums.py`, `configs/{evidence,severity,models}.yaml` | Independent held-out sigmoid calibration and validation thresholds were exported from real data. Gate tests pass with explicitly test-only inputs. |
| G: batched inference | `runtime/engine.py`, `detection/base.py`, model loader | Ordered batch mapping, timed flush during paced gaps, EOF flush, incremental alerts. Fixture and real-artifact replay tests pass. |
| H: UI / telemetry | `telemetry/metrics.py`, API; `frontend/src/{App.tsx,runtime.ts,types.ts,styles.css}`, `hooks/useRuntimeTelemetry.ts`, `components/{ReplayControl,Visuals,AlertInspector}.tsx`, `frontend/vite.config.ts` | Aggregate WebSockets, controls/progress, raw vs calibrated scores, threshold marker, real counters/rate graph, honest model readiness, stage timings. Build/browser checks pass. |
| I: benchmark | `runtime/benchmark.py`, local `reports/benchmarks/one-model-fastpcap-2026-09-02.json` | All modes measured on `http.cap`; tiny parser/runtime timing test, not model capacity/accuracy validation. |

Tests added/extended: `tests/unit/test_{replay,flow,cicids_features,runtime,model_batch,evidence,config}.py`, `tests/integration/test_{api,real_behaviour}.py`. `.gitignore` excludes unique local test temporary directories.

## Real data preparation

The three locked Friday CSVs already existed in `C:\Users\Aaryan\Downloads`. No dataset was downloaded or invented. Original inputs were unchanged.

| Source label | Raw rows | Target label | Retained unique cleaned rows |
| --- | ---: | --- | ---: |
| BENIGN | 414,322 | BENIGN | 333,332 |
| DDoS | 128,027 | DDOS | 127,987 |
| PortScan | 158,930 | RECON | 1,913 |
| Bot | 1,966 | BOT_OR_C2_LIKE | 1,229 |
| Total | 703,245 | | 464,461 |

Removed: 47 invalid core rows, 18,208 conflicting-label rows for identical selected inputs, and 220,529 repeated selected-input vectors. The large Recon reduction materially changes the evaluation distribution; retained rows do not reflect original natural frequencies.

Outputs: `data/processed/behaviour-xgb-v1.parquet` (real features/provenance/split assignments, ignored by Git) and `data/manifests/behaviour-xgb-v1.json` (SHA-256 hashes, counts, exclusions, limitations, grouping, split seed).

| Split | Rows | Source-row groups |
| --- | ---: | ---: |
| Train | 328,563 | 959 |
| Validation | 46,087 | 137 |
| Calibration | 44,482 | 137 |
| Final test | 45,329 | 137 |

All splits contain all four classes. Groups are contiguous 512-row blocks in each source file. Each attack class occurs in one file, so whole-file splits cannot cover all classes in each role. These CSVs lack IPs, timestamps and protocol. Row blocks are **not verified host/session/time groups**, and evaluation is not claimed leakage-free. Thresholds use validation; sigmoid fitting uses calibration; final-test metrics are evaluated after those choices are fixed.

Inverse-frequency weights apply only to training; no oversampling or synthetic rows. The split seed is the first deterministic partition containing every class in each role, not the best-scoring partition.

## Shared feature contract

`features/behaviour_flow.py` defines `cicids2017-payload-flow-v1`, shared by preparation and runtime. The 14 ordered model inputs are:

```text
flow_duration_seconds
packets_outbound, packets_inbound, packet_count
payload_bytes_outbound, payload_bytes_inbound, payload_bytes_total
payload_packet_size_mean, payload_packet_size_variance
inter_arrival_mean, inter_arrival_variance
payload_directional_ratio
flow_packets_per_second, flow_payload_bytes_per_second
```

Payload excludes Ethernet/IP/transport headers; wire-byte telemetry is separate. Direction is the first sender, not sorted endpoints. Timing is seconds and variance is population variance. Undefined statistics use explicit missingness, not invented zeros.

CIC timing is converted from microseconds. Directional sample standard deviations reconstruct payload population variance. Global packet-size summaries are excluded because the inspected [CICFlowMeter source](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) duplicates the initial payload in its global statistics. Destination Port, absent identifiers/protocol and ambiguous flag summaries are excluded from classifier inputs.

Runtime rates, diversity, fan-out, recurrence, burstiness, UDP share, short-flow ratio and history support the Evidence Gate; they are not fabricated as CSV inputs. Completed training flows versus partial runtime snapshots have unmeasured domain shift. Matching arithmetic does not establish streaming accuracy. Bot maps to BOT_OR_C2_LIKE, not validated C2 beaconing.

## Model, batching and evidence

The README has exact commands. Training uses fixed-seed histogram XGBoost, inverse-frequency sample weights, independent held-out one-vs-rest sigmoid calibration followed by normalization, and validation-derived class thresholds. Expected real exports: `model.json`, `calibrator.joblib`, `feature_schema.json`, `class_mapping.json`, `thresholds.json`, `metrics.json`, `manifest.json`. JSON model storage follows the [XGBoost model API](https://xgboost.readthedocs.io/en/stable/python/python_api.html#xgboost.XGBClassifier.save_model).

The loader rejects incompatible schemas/class maps, incomplete packages and hash mismatches. Hashes verify integrity, not trust: joblib packages must come from a trusted source.

Path: eligible shared-feature snapshot → batch prediction → calibration → class threshold and Evidence Gate → deduplication → bounded alert records. Raw/calibrated scores remain separate for the selected class. BENIGN produces no threat alert. Missing evidence yields INSUFFICIENT_EVIDENCE; low confidence can yield UNKNOWN_SUSPICIOUS; sufficient confidence and class evidence can yield ACCEPT. Gate rules never replace ML classification.

Defaults: snapshots once per capture-second for dirty flows with at least two packets, plus final expired/EOF snapshots. Batches flush at 32 vectors, 50 ms, or EOF; paced waits flush already-eligible jobs during long gaps. NumPy batches replace per-packet DataFrames.

Bounds: 50,000 active flows, 200,000 temporal events, 1,000 retained alerts, 720 timeline samples, 2,000 latency samples per stage. Idle/active flow timeouts: 60/120 seconds. Temporal truncation marks incomplete history. Lifetime scalar counters can grow; retained collections are bounded.

Parsing is Ethernet/IP only. Unsupported frames and truncated/fragmented IP are skipped; no reassembly or decryption was added. Out-of-order timestamps are counted and excluded from ordered temporal state. `.cap` is accepted when the contents are supported capture data; renaming cannot convert a link layer. Existing `sample1.pcap` uses unsupported Zigbee link type 195; use `http.cap` for the verified parser demo.

## Telemetry and UI semantics

Aggregate telemetry uses `/api/v1/stream/telemetry` every 250 ms normally and 1,000 ms in BENCHMARK. Alert snapshots update only on revision changes and include a run ID. Legacy HTTP routes remain. Vite proxies HTTP and WebSockets to `127.0.0.1:8000`.

Unique flow sessions differ from packet-level flow updates. Processing Mbps uses local wall time; original capture average uses capture timestamps. Pauses are excluded from average active-processing duration. Paused/completed runs show zero current rate and retain measured averages. CPU/RSS are process samples, not peak RSS. Graphs contain real bounded aggregate samples.

`total_pipeline` measures feature-snapshot eligibility through decision, including batch wait. It excludes waiting for snapshot eligibility and is not packet-arrival-to-detection latency. Per-vector inference time is measured batch time divided by vector count. BENCHMARK samples packet stages every 32 frames. Missing model timings show Not measured. Alerts have wall-clock emission timestamps for timeline markers and capture timestamps for evidence.

Behaviour is READY; DNS/TLS are PLANNED. No active detector claims exfiltration, DGA, tunneling or encrypted-threat coverage. No presentation alerts were fabricated.

## Measured validation

Real `http.cap`: SHA-256 `25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d`; file size 25,803 bytes; 43 frames, 25,091 frame bytes, three flow sessions, ten eligible snapshots; capture duration about 30.394 seconds.

| Mode | One measured wall time | Packets | Flows | Model vectors |
| --- | ---: | ---: | ---: | ---: |
| PACED 1× | 30.699914 s | 43 | 3 | 0 |
| FAST | 0.012066 s | 43 | 3 | 0 |
| BENCHMARK | 0.007922 s | 43 | 3 | 0 |

Machine, CPU/RSS and stage percentiles are in the local benchmark JSON. These differences show removed timestamp delays, not proved scalable throughput improvement. Tiny single-run timings are noisy and are not capacity benchmarks. This benchmark predates the model package, so its inference/pipeline timings are unavailable. The actual trained CSV evaluation reports validation accuracy 0.9972 and macro F1 0.8866; final-test accuracy 0.9980, macro F1 0.9377 and multiclass Brier score 0.002759. These scores apply only to unique cleaned vectors in the documented row-block split, not host/session/leakage-free or streaming-PCAP evaluation.

Browser: completed FAST and PACED 2× `http.cap`; pause/resume/stop on PACED `dns.cap`; correct progress, honest detector cards, unmeasured inference stages. No application errors appeared in collected browser logs.

Final automated checks after training: **47 passed**; Ruff and TypeScript/Vite build pass. The real-model integration test passed after artifact export. Test-only probability fixtures validate wiring and arithmetic, not trained accuracy. One upstream Starlette/httpx deprecation warning remains; it did not fail tests.

## Remaining acceptance work

1. Replay relevant authorized labelled captures and measure real inference, incremental alerts, false positives and evidence decisions. The tiny unlabelled HTTP capture establishes no threat-class accuracy.
2. Repeat benchmarks with the loaded real artifact and larger authorized captures; report distributions and limitations.
3. If XGBoost is reinstalled or moved, verify `import xgboost` before retraining rather than bypassing Windows application-control protections.

No DNS/TLS training, CTU-13 integration, cache/stretch feature, active-network capability or unrelated architecture redesign was started.
