# Custodian — One-model presentation prototype

Passive, read-only PCAP replay with incremental flow processing, calibrated Behaviour-model integration, an Evidence Gate, and the existing dark-green dashboard. No scanning, traffic injection, mitigation, or payload decryption.

## Readiness

- PACED (1×/2×/5×/10×), FAST, and BENCHMARK replay are implemented, with pause/resume/stop, file progress, bounded state, and aggregated live telemetry.
- Only XGBoost Behaviour is in scope: BENIGN, DDOS, RECON, BOT_OR_C2_LIKE. DNS and TLS/QUIC remain PLANNED.
- A real XGBoost Behaviour package (`behaviour-xgb-v1`) is trained from the approved CICIDS2017 CSVs, calibrated, integrity-checked, and loaded by the API. It covers BENIGN, DDOS, RECON and BOT_OR_C2_LIKE. DNS and TLS/QUIC remain PLANNED.
- The final held-out CSV test accuracy was 0.9980 and macro F1 was 0.9377. These are not leakage-free host/session/streaming-PCAP results; see the implementation report for split and domain-shift limits. A zero-alert replay does not prove a capture is safe.

Phase status, feature definitions, data counts, limitations and measured replay timings: [implementation report](docs/ONE_MODEL_FAST_PCAP.md).

## Run on this laptop

Use two PowerShell terminals. Run from the Custodian repository, not another project's API directory.

Backend:

```powershell
Set-Location 'C:\Users\Aaryan\Documents\ChatGPT\Sentinel-X'
& 'E:\Python\python.exe' -m uvicorn sentinelx.api.app:app --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
Set-Location 'C:\Users\Aaryan\Documents\ChatGPT\Sentinel-X\frontend'
& 'E:\Node\npm.cmd' run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open <http://localhost:5173/>. Put a supported Ethernet/IP `.cap`, `.pcap`, or `.pcapng` inside `data/demo/`. Enter `http.cap`, choose FAST, and click Start replay. PACED follows capture timestamps; FAST ignores their delays. Stop both servers with Ctrl+C. PyCharm needs no special web configuration: choose `E:\Python\python.exe` as the interpreter and the repository root as the backend working directory.

For a fresh install (Python 3.11+ and Node.js required):

```powershell
Set-Location 'C:\Users\Aaryan\Documents\ChatGPT\Sentinel-X'
& 'E:\Python\python.exe' -m pip install -e '.[dev]'
Set-Location frontend
& 'E:\Node\npm.cmd' ci
```

Installing packages does not override Application Control. If a port is occupied, stop only the server you own or configure the Vite proxy and API port together; do not terminate unrelated projects.

## Train after the environment is approved and working

First check XGBoost can load. If a Windows policy blocks it again, use an approved environment rather than bypassing security controls:

```powershell
Set-Location 'C:\Users\Aaryan\Documents\ChatGPT\Sentinel-X'
& 'E:\Python\python.exe' -c 'import xgboost; print(xgboost.__version__)'
& 'E:\Python\python.exe' -m training.train_behaviour --data-dir 'C:\Users\Aaryan\Downloads' --output-dir model_artifacts/behaviour-xgb-v1
```

Only these exact CICIDS2017 files are consumed:

- `Friday-WorkingHours-Morning.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

They already exist in this laptop's Downloads directory. On another machine, put them in `data/raw/cicids2017/` and use that `--data-dir`. The command does not invent missing inputs. Add `--prepare-only` to prepare real data without fitting. Nonempty artifact destinations are not overwritten; use a new versioned directory and update `configs/models.yaml` when retraining. Restart the API after exporting a complete package.

## Validate

```powershell
Set-Location 'C:\Users\Aaryan\Documents\ChatGPT\Sentinel-X'
& 'E:\Python\python.exe' -m pytest -q
& 'E:\Python\python.exe' -m ruff check src tests training
& 'E:\Python\python.exe' -m sentinelx.runtime.benchmark --capture data/demo/http.cap --output reports/benchmarks/my-local-run.json
Set-Location frontend
& 'E:\Node\npm.cmd' run build
```

The benchmark runs PACED at 1×, then FAST and BENCHMARK: allow at least the capture's duration. Use a new report filename each run. The real-model integration test verifies an available local artifact and skips only when one is absent.

Captures, processed datasets, model artifacts and machine-specific benchmark reports are ignored by Git. Only use authorized captures and trusted model packages; joblib deserialization requires trust.
