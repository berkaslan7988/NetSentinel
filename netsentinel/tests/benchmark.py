"""NetSentinel - Performance measurement (Phase 8).

Measures inference latency (p50/p95/p99), sustainable flow rate, and a simple
packet-drop simulation; writes the result to reports/benchmark_report.md.

Usage (with saved models):
    python tests/benchmark.py
    python tests/benchmark.py --n 5000
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from features.columns import FEATURE_COLUMNS  # noqa: E402

N_FEATURES = len(FEATURE_COLUMNS)


def bench_inference(engine, n: int = 2000, seed: int = 0) -> Dict[str, float]:
    """Measures predict_vector latency over n random vectors."""
    rng = np.random.default_rng(seed)
    vectors = rng.normal(0, 1, size=(n, N_FEATURES)).tolist()

    engine.predict_vector(vectors[0])  # warm-up
    lat_ms: List[float] = []
    for v in vectors:
        t0 = time.perf_counter()
        engine.predict_vector(v)
        lat_ms.append((time.perf_counter() - t0) * 1000)

    lat_ms.sort()
    mean = statistics.fmean(lat_ms)
    return {
        "n": n,
        "mean_ms": mean,
        "p50_ms": lat_ms[int(0.50 * n)],
        "p95_ms": lat_ms[int(0.95 * n)],
        "p99_ms": lat_ms[int(0.99 * n)],
        "max_ms": lat_ms[-1],
        "throughput_fps": 1000.0 / mean if mean else 0.0,
    }


def simulate_drop(sustainable_fps: float, incoming_fps: float, seconds: float = 10.0) -> Dict[str, float]:
    """Theoretical drop rate if the incoming rate exceeds the sustainable rate."""
    incoming = incoming_fps * seconds
    processed = min(incoming, sustainable_fps * seconds)
    dropped = max(0.0, incoming - processed)
    return {
        "incoming_fps": incoming_fps,
        "sustainable_fps": sustainable_fps,
        "drop_rate": (dropped / incoming) if incoming else 0.0,
    }


def write_report(infer: Dict[str, float], drops: List[Dict[str, float]]) -> Path:
    lines = [
        "# NetSentinel - Performance Report (Phase 8)",
        "",
        "## Inference Latency",
        "",
        f"- Sample count: {infer['n']}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Mean | {infer['mean_ms']:.3f} ms |",
        f"| p50 | {infer['p50_ms']:.3f} ms |",
        f"| p95 | {infer['p95_ms']:.3f} ms |",
        f"| p99 | {infer['p99_ms']:.3f} ms |",
        f"| max | {infer['max_ms']:.3f} ms |",
        f"| Sustainable rate | **{infer['throughput_fps']:.0f} flows/s** |",
        "",
        "## Packet Drop Simulation",
        "",
        "| Incoming (flows/s) | Sustainable | Drop rate |",
        "|---|---|---|",
    ]
    for d in drops:
        lines.append(f"| {d['incoming_fps']:.0f} | {d['sustainable_fps']:.0f} | "
                     f"{100 * d['drop_rate']:.2f}% |")
    lines += [
        "",
        "> Target: packet drop < 2% on a moderate home/lab network. Inference is "
        "well under 50ms, so a single flow is not the bottleneck; if one arises it "
        "can be addressed with mini-batch prediction (roadmap Phase 4).",
    ]
    out = config.BASE_DIR / "reports" / "benchmark_report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="NetSentinel performance measurement")
    parser.add_argument("--n", type=int, default=2000)
    parser.add_argument("--mode", default="hybrid")
    args = parser.parse_args()

    from detection.engine import DetectionEngine
    try:
        engine = DetectionEngine(mode=args.mode)
    except Exception as exc:
        print(f"[ERROR] could not load models: {exc}. Run Phase 3 training first.")
        return 1

    infer = bench_inference(engine, n=args.n)
    print(f"Inference: mean {infer['mean_ms']:.2f}ms  p95 {infer['p95_ms']:.2f}ms  "
          f"p99 {infer['p99_ms']:.2f}ms  -> {infer['throughput_fps']:.0f} flows/s")

    sustainable = infer["throughput_fps"]
    drops = [simulate_drop(sustainable, rate) for rate in
             (sustainable * 0.5, sustainable, sustainable * 2)]
    report = write_report(infer, drops)
    print(f"Report: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
