"""Measure a prepared capture in all three modes without generating any traffic."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from sentinelx.config import load_config_bundle
from sentinelx.core.enums import ReplayMode
from sentinelx.runtime.engine import SentinelEngine


def benchmark(capture: Path, *, config_dir: Path, paced_speed: float = 1):
    config = load_config_bundle(config_dir)
    with capture.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    results = []
    for mode in ReplayMode:
        engine = SentinelEngine(config)
        started = perf_counter()
        list(engine.replay(capture, mode=mode, speed_multiplier=paced_speed))
        duration = perf_counter() - started
        metrics = engine.metrics.snapshot(force=True)
        results.append({
            "mode": mode.value, "paced_speed_multiplier": paced_speed if mode is ReplayMode.PACED else None,
            "wall_seconds": duration, "detectors": engine.detector_status(),
            "metrics": metrics,
            "p50_p95_inference_ms": metrics["latency_ms"].get("inference"),
            "p50_p95_pipeline_ms": metrics["latency_ms"].get("total_pipeline"),
            "active_flow_evictions": engine.flows.evicted_count,
            "retained_temporal_events": engine.state.event_count,
            "alert_decisions": dict(engine.metrics.decisions),
        })
        print(f"{mode.value}: {duration:.6f}s, {metrics['packets']} packets, {metrics['flows']} flows, "
              f"{metrics['inference_vectors']} inference vectors", flush=True)
    return {
        "measured_at": datetime.now(UTC).isoformat(),
        "capture": str(capture.resolve()), "sha256": digest, "file_bytes": capture.stat().st_size,
        "machine": {"platform": platform.platform(), "processor": platform.processor(),
                    "python": platform.python_version()},
        "runs": results,
        "limitations": [
            "One local run per mode; a tiny sample is a timing smoke test, not a capacity benchmark.",
            "CPU is measured for this process. RSS is a sampled resident-memory snapshot, not peak RSS.",
            "Inference/pipeline latencies are null if no real model was available.",
            "Processing throughput is accelerated replay throughput; observed_average_mbps uses capture timestamps.",
            "The reported raw-to-final baseline is not a validated accuracy or threat-label benchmark.",
        ],
    }


def main():
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=root / "data/demo/http.cap")
    parser.add_argument("--output", type=Path, default=root / "reports/benchmarks/one-model-fastpcap.json")
    parser.add_argument("--paced-speed", type=float, default=1)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new filename to preserve measurements")
    report = benchmark(args.capture, config_dir=root / "configs", paced_speed=args.paced_speed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
    print(f"Report: {args.output}", flush=True)


if __name__ == "__main__":
    main()
