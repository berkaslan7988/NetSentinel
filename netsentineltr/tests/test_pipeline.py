"""ui.pipeline için testler (Qt gerektirmez).

DetectionPipeline kuyruk/istatistik mantığı, ReplayPipeline besleme, ve
csv_result_source / db_result_source kaynaklarını doğrular.
"""
import time

import numpy as np
import pytest

from detection.result import DetectionResult
from features.columns import FEATURE_COLUMNS
from ui.pipeline import (
    DetectionPipeline, ReplayPipeline, csv_result_source, db_result_source,
)

N = len(FEATURE_COLUMNS)


def res(src="10.0.0.1", label="BENIGN", proba=0.0, threat=False, bytes_=100):
    r = DetectionResult(
        src_ip=src, dst_ip="2.2.2.2", src_port=1, dst_port=80, protocol="TCP",
        timestamp=time.time(), total_bytes=bytes_,
        supervised_label=label, supervised_proba=proba,
    )
    r.is_threat = threat
    r.threat_score = proba
    return r


@pytest.fixture
def model_dir(tmp_path):
    import joblib
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    rng = np.random.default_rng(0)
    X = np.vstack([rng.normal(0, 1, (120, N)), rng.normal(5, 1, (120, N))])
    y = np.array([0] * 120 + [1] * 120)
    s = StandardScaler().fit(X)
    joblib.dump(s, tmp_path / "scaler.pkl")
    joblib.dump(RandomForestClassifier(n_estimators=20, random_state=0).fit(s.transform(X), y),
                tmp_path / "supervised_rf.pkl")
    joblib.dump(IsolationForest(n_estimators=20, random_state=0).fit(s.transform(X)[y == 0]),
                tmp_path / "isolation_forest.pkl")
    return tmp_path


# --------------------------------------------------------------------- #
def test_detection_pipeline_emit_counts():
    p = DetectionPipeline()
    p.emit(res(label="BENIGN", proba=0.0))
    p.emit(res(label="ATTACK", proba=0.95, threat=True))
    assert p.stats.total_flows == 2
    assert p.stats.total_threats == 1
    # ikisi de results_q'ya düşmeli
    got = [p.results_q.get_nowait(), p.results_q.get_nowait()]
    assert len(got) == 2


def test_detection_pipeline_emits_alert():
    p = DetectionPipeline()
    # ATTACK proba 0.95 -> risk >= 25 -> alarm
    p.emit(res(label="ATTACK", proba=0.95, threat=True))
    assert p.stats.total_alerts >= 1
    assert not p.alerts_q.empty()


def test_replay_pipeline_feeds_queue():
    source = [res(label="ATTACK", proba=0.9, threat=True) for _ in range(5)]
    p = ReplayPipeline(source, rate_hz=200)
    p.start()
    time.sleep(0.5)
    p.stop()
    drained = []
    while not p.results_q.empty():
        drained.append(p.results_q.get_nowait())
    assert len(drained) == 5
    assert p.stats.total_flows == 5


# --------------------------------------------------------------------- #
def test_csv_result_source_detects_attacks(model_dir, tmp_path):
    import pandas as pd
    from detection.engine import DetectionEngine

    # benign (~0) + attack-benzeri (~5) satırlardan küçük bir CSV
    rng = np.random.default_rng(1)
    benign = rng.normal(0, 1, (10, N))
    attack = rng.normal(5, 1, (10, N))
    data = np.vstack([benign, attack])
    df = pd.DataFrame(data, columns=FEATURE_COLUMNS)
    df["Destination Port"] = 443
    df["Label"] = ["BENIGN"] * 10 + ["ATTACK"] * 10
    csv_path = tmp_path / "mini.csv"
    df.to_csv(csv_path, index=False)

    engine = DetectionEngine(mode="supervised", model_dir=model_dir, load_ae=False)
    results = list(csv_result_source(engine, str(csv_path)))
    assert len(results) == 20
    # attack-benzeri satırların en az yarısı ATTACK tahmin edilmeli
    attack_preds = sum(1 for r in results[10:] if r.supervised_label == "ATTACK")
    assert attack_preds >= 5
    # kimlik alanları dolu
    assert results[0].dst_port == 443
    assert results[0].src_ip.startswith("192.168.")


def test_db_result_source_roundtrip(tmp_path):
    from storage.database import Database
    from storage.writer import result_to_flow_row

    db = Database(tmp_path / "r.db")
    db.insert_flows([result_to_flow_row(res(src="5.5.5.5", label="ATTACK", proba=0.9))])
    db.insert_flows([result_to_flow_row(res(src="6.6.6.6", label="BENIGN", proba=0.1))])
    out = list(db_result_source(db, limit=10))
    assert len(out) == 2
    labels = {r.src_ip: r.supervised_label for r in out}
    assert labels["5.5.5.5"] == "ATTACK"
    db.close()
