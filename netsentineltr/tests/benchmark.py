"""NetSentinel — Performans ölçümü (Faz 8).

Inference gecikmesi (p50/p95/p99), sürdürülebilir akış hızı ve basit bir paket
drop simülasyonu ölçer; sonucu reports/benchmark_report.md'ye yazar.

Kullanım (kayıtlı modellerle):
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
    """n rastgele vektörde predict_vector gecikmesini ölçer."""
    rng = np.random.default_rng(seed)
    vectors = rng.normal(0, 1, size=(n, N_FEATURES)).tolist()

    engine.predict_vector(vectors[0])  # ısınma
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
    """Gelen hız sürdürülebilir hızı aşarsa oluşacak teorik drop oranı."""
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
        "# NetSentinel — Performans Raporu (Faz 8)",
        "",
        "## Inference Gecikmesi",
        "",
        f"- Örnek sayısı: {infer['n']}",
        "",
        "| Metrik | Değer |",
        "|---|---|",
        f"| Ortalama | {infer['mean_ms']:.3f} ms |",
        f"| p50 | {infer['p50_ms']:.3f} ms |",
        f"| p95 | {infer['p95_ms']:.3f} ms |",
        f"| p99 | {infer['p99_ms']:.3f} ms |",
        f"| max | {infer['max_ms']:.3f} ms |",
        f"| Sürdürülebilir hız | **{infer['throughput_fps']:.0f} akış/sn** |",
        "",
        "## Paket Drop Simülasyonu",
        "",
        "| Gelen (akış/sn) | Sürdürülebilir | Drop oranı |",
        "|---|---|---|",
    ]
    for d in drops:
        lines.append(f"| {d['incoming_fps']:.0f} | {d['sustainable_fps']:.0f} | "
                     f"%{100 * d['drop_rate']:.2f} |")
    lines += [
        "",
        "> Hedef: orta yoğunlukta ev/lab ağında paket düşürme < %2. "
        "Inference 50ms'nin çok altında olduğundan tek akış darboğaz değildir; "
        "darboğaz olursa mini-batch tahmin ile aşılabilir (roadmap Faz 4).",
    ]
    out = config.BASE_DIR / "reports" / "benchmark_report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="NetSentinel performans ölçümü")
    parser.add_argument("--n", type=int, default=2000)
    parser.add_argument("--mode", default="hybrid")
    args = parser.parse_args()

    from detection.engine import DetectionEngine
    try:
        engine = DetectionEngine(mode=args.mode)
    except Exception as exc:
        print(f"[HATA] Model yüklenemedi: {exc}. Önce Faz 3 eğitimini çalıştır.")
        return 1

    infer = bench_inference(engine, n=args.n)
    print(f"Inference: ort {infer['mean_ms']:.2f}ms  p95 {infer['p95_ms']:.2f}ms  "
          f"p99 {infer['p99_ms']:.2f}ms  -> {infer['throughput_fps']:.0f} akış/sn")

    sustainable = infer["throughput_fps"]
    drops = [simulate_drop(sustainable, rate) for rate in
             (sustainable * 0.5, sustainable, sustainable * 2)]
    report = write_report(infer, drops)
    print(f"Rapor: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
