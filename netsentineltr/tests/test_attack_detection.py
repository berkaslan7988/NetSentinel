"""Faz 8 testleri: saldırı simülatörü güvenliği, uçtan uca tespit, benchmark.

Bunlar 'saldırı tespit edildi mi?' sorusunu test formunda kanıtlar.
"""
import time

import numpy as np
import pytest

from features.columns import FEATURE_COLUMNS

import tests.attack_simulator as sim
from tests.benchmark import bench_inference, simulate_drop

N = len(FEATURE_COLUMNS)


@pytest.fixture
def model_dir(tmp_path):
    import joblib
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    rng = np.random.default_rng(0)
    X = np.vstack([rng.normal(0, 1, (150, N)), rng.normal(6, 1, (150, N))])
    y = np.array([0] * 150 + [1] * 150)
    s = StandardScaler().fit(X)
    joblib.dump(s, tmp_path / "scaler.pkl")
    joblib.dump(RandomForestClassifier(n_estimators=25, random_state=0).fit(s.transform(X), y),
                tmp_path / "supervised_rf.pkl")
    joblib.dump(IsolationForest(n_estimators=25, random_state=0).fit(s.transform(X)[y == 0]),
                tmp_path / "isolation_forest.pkl")
    return tmp_path


# --------------------------------------------------------------------- #
# Saldırı simülatörü — güvenlik korumaları
# --------------------------------------------------------------------- #
def test_loopback_and_private_allowed():
    assert sim.is_allowed_target("127.0.0.1")
    assert sim.is_allowed_target("192.168.1.50")
    assert sim.is_allowed_target("10.0.0.5")
    assert sim.is_allowed_target("172.16.3.4")


def test_public_targets_refused():
    assert not sim.is_allowed_target("8.8.8.8")
    assert not sim.is_allowed_target("1.1.1.1")
    assert not sim.is_allowed_target("not-an-ip")


@pytest.mark.skipif(not sim.SCAPY_AVAILABLE, reason="Scapy yok")
def test_port_scan_builds_correct_packet_count(monkeypatch):
    sent = []
    monkeypatch.setattr(sim, "send", lambda pkt, verbose=0: sent.append(pkt))
    n = sim.port_scan("127.0.0.1", 1, 20)
    assert n == 20
    assert len(sent) == 20


@pytest.mark.skipif(not sim.SCAPY_AVAILABLE, reason="Scapy yok")
def test_syn_flood_count(monkeypatch):
    sent = []
    monkeypatch.setattr(sim, "send", lambda pkt, verbose=0: sent.append(pkt))
    assert sim.syn_flood("10.0.0.1", 80, 100) == 100
    assert len(sent) == 100


# --------------------------------------------------------------------- #
# Uçtan uca tespit kanıtı (CSV saldırı satırları -> alarm)
# --------------------------------------------------------------------- #
def test_attack_rows_trigger_alerts(model_dir, tmp_path):
    import pandas as pd

    from detection.engine import DetectionEngine
    from ui.pipeline import ReplayPipeline, csv_result_source

    # Saldırı-benzeri (~6) satırlardan CSV
    rng = np.random.default_rng(2)
    benign = rng.normal(0, 1, (5, N))
    attack = rng.normal(6, 1, (15, N))
    df = pd.DataFrame(np.vstack([benign, attack]), columns=FEATURE_COLUMNS)
    df["Destination Port"] = 80
    csv_path = tmp_path / "attacks.csv"
    df.to_csv(csv_path, index=False)

    engine = DetectionEngine(mode="hybrid", model_dir=model_dir, load_ae=False)
    pipe = ReplayPipeline(csv_result_source(engine, str(csv_path)), rate_hz=500)
    pipe.start()
    time.sleep(1.0)
    pipe.stop()

    # Saldırılar tespit edilip alarm üretmeli
    assert pipe.stats.total_threats >= 5
    assert pipe.stats.total_alerts >= 1
    assert not pipe.alerts_q.empty()


# --------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------- #
def test_benchmark_latency_under_50ms(model_dir):
    from detection.engine import DetectionEngine
    engine = DetectionEngine(mode="hybrid", model_dir=model_dir, load_ae=False)
    res = bench_inference(engine, n=300)
    assert res["p95_ms"] < 50
    assert res["throughput_fps"] > 0


def test_drop_simulation_math():
    # gelen = sürdürülebilir -> drop 0; gelen = 2x -> ~%50
    assert simulate_drop(100, 100)["drop_rate"] == 0.0
    assert simulate_drop(100, 200)["drop_rate"] == pytest.approx(0.5, abs=0.01)
