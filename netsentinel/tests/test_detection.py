"""Tests for detection.engine and detection.worker.

Small RF + IsolationForest + scaler are trained on synthetic data and saved to a
temp dir; the DetectionEngine loads them from there. No torch needed (load_ae=False).
"""
import queue
import time

import numpy as np
import pytest

from detection.engine import DetectionEngine
from detection.result import DetectionResult
from detection.worker import DetectionWorker
from features.columns import FEATURE_COLUMNS
from flows.flow import Direction, Flow, PacketRecord

N_FEATURES = len(FEATURE_COLUMNS)


@pytest.fixture
def model_dir(tmp_path):
    """Trains small synthetic models and saves them to tmp_path."""
    import joblib
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    rng = np.random.default_rng(0)
    # BENIGN: small values; ATTACK: shifted distribution
    benign = rng.normal(0, 1, size=(150, N_FEATURES))
    attack = rng.normal(5, 1, size=(150, N_FEATURES))
    X = np.vstack([benign, attack])
    y = np.array([0] * 150 + [1] * 150)

    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    rf = RandomForestClassifier(n_estimators=20, random_state=0).fit(Xs, y)
    iso = IsolationForest(n_estimators=20, random_state=0).fit(Xs[y == 0])

    joblib.dump(scaler, tmp_path / "scaler.pkl")
    joblib.dump(rf, tmp_path / "supervised_rf.pkl")
    joblib.dump(iso, tmp_path / "isolation_forest.pkl")
    return tmp_path


@pytest.fixture
def engine(model_dir):
    return DetectionEngine(mode="hybrid", model_dir=model_dir, load_ae=False)


def make_flow(payload=100):
    f = Flow("10.0.0.1", "10.0.0.2", 1234, 80, "TCP", start_time=0.0, last_time=1.0)
    f.add_packet(PacketRecord(timestamp=0.0, payload_len=payload, flags="S",
                              header_len=20, window=8192), Direction.FORWARD)
    f.add_packet(PacketRecord(timestamp=0.5, payload_len=payload, flags="A",
                              header_len=20, window=64240), Direction.BACKWARD)
    f.add_packet(PacketRecord(timestamp=1.0, payload_len=payload, flags="PA",
                              header_len=20, window=8192), Direction.FORWARD)
    return f


# --------------------------------------------------------------------- #
def test_engine_loads_models(engine):
    assert engine.scaler is not None
    assert engine.supervised is not None
    assert engine.iso is not None
    assert engine.ae is None  # load_ae=False


def test_predict_vector_structure(engine):
    vec = [0.0] * N_FEATURES
    res = engine.predict_vector(vec, identity={"src_ip": "1.1.1.1"})
    assert isinstance(res, DetectionResult)
    assert res.supervised_label in ("BENIGN", "ATTACK")
    assert 0.0 <= res.supervised_proba <= 1.0
    assert res.iso_anomaly in (True, False)
    assert isinstance(res.iso_score, float)
    assert isinstance(res.is_threat, bool)
    assert 0.0 <= res.threat_score <= 1.0
    assert res.src_ip == "1.1.1.1"


def test_predict_flow(engine):
    res = engine.predict_flow(make_flow())
    assert res.src_ip == "10.0.0.1"
    assert res.dst_port == 80
    assert res.protocol == "TCP"
    assert res.supervised_label in ("BENIGN", "ATTACK")


def test_wrong_vector_length_raises(engine):
    with pytest.raises(ValueError):
        engine.predict_vector([0.0] * 10)


def test_attack_like_vector_flags_threat(engine):
    # an unscaled vector resembling the ATTACK distribution (mean ~5) in training
    vec = [5.0] * N_FEATURES
    res = engine.predict_vector(vec)
    assert res.is_threat is True


def test_supervised_mode_only(model_dir):
    eng = DetectionEngine(mode="supervised", model_dir=model_dir, load_ae=False)
    assert eng.iso is None
    res = eng.predict_vector([0.0] * N_FEATURES)
    assert res.iso_score is None
    assert res.supervised_label is not None


def test_latency_under_50ms(engine):
    vec = [0.0] * N_FEATURES
    engine.predict_vector(vec)  # warm-up
    start = time.perf_counter()
    for _ in range(20):
        engine.predict_vector(vec)
    avg_ms = (time.perf_counter() - start) / 20 * 1000
    assert avg_ms < 50, f"average inference {avg_ms:.1f}ms (>50ms)"


# --------------------------------------------------------------------- #
def test_worker_processes_flows(engine):
    in_q: queue.Queue = queue.Queue()
    out_q: queue.Queue = queue.Queue()
    worker = DetectionWorker(engine, in_q, out_q)
    worker.start()

    for _ in range(5):
        worker.submit(make_flow())

    in_q.join()  # wait for all work to finish
    worker.stop()

    results = []
    while not out_q.empty():
        results.append(out_q.get())
    assert len(results) == 5
    assert all(isinstance(r, DetectionResult) for r in results)
    assert worker.processed == 5
    assert worker.errors == 0
