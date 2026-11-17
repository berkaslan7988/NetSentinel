"""Demo traffic and the dashboard Session (no Qt, no models, no network)."""
import time

from alerts.scoring import RiskScorer
from detection.result import DetectionResult
from ui.demo import DemoPipeline, DemoTraffic
from ui.session import BUCKET_SECONDS, WINDOW_BUCKETS, Session

EPOCH = 1_700_000_000.0


def drain(pipe, session):
    while not pipe.results_q.empty():
        session.add_result(pipe.results_q.get_nowait())
    while not pipe.alerts_q.empty():
        session.add_alert(pipe.alerts_q.get_nowait())


def test_demo_is_deterministic_and_chunk_independent():
    a = DemoTraffic(seed=3, epoch=EPOCH)
    b = DemoTraffic(seed=3, epoch=EPOCH)
    whole = a.between(EPOCH + 100, EPOCH + 130)
    parts = b.between(EPOCH + 100, EPOCH + 117.5) + b.between(EPOCH + 117.5, EPOCH + 130)
    assert [(r.src_ip, r.dst_port, r.timestamp) for r in whole] == \
           [(r.src_ip, r.dst_port, r.timestamp) for r in parts]
    assert all(EPOCH + 100 <= r.timestamp < EPOCH + 130 for r in whole)


def test_demo_modes_fill_only_their_models():
    sup = DemoTraffic(mode="supervised", epoch=EPOCH).between(EPOCH, EPOCH + 5)
    uns = DemoTraffic(mode="unsupervised", epoch=EPOCH).between(EPOCH, EPOCH + 5)
    assert all(r.iso_anomaly is None and r.ae_error is None for r in sup)
    assert all(r.supervised_proba is not None for r in sup)
    assert all(r.supervised_proba is None and r.ae_error is not None for r in uns)


def test_demo_attacks_score_high_and_benign_low():
    scorer = RiskScorer()
    flows = DemoTraffic(epoch=EPOCH).between(EPOCH + 430, EPOCH + 470)   # brute force running
    brute = [r for r in flows if r.src_ip == "203.0.113.45"]
    benign = [r for r in flows if r.src_ip.startswith("192.168.10.") and r.dst_port in (443, 53)]
    assert len(brute) > 40
    assert min(scorer.score(r) for r in brute) >= 50
    assert sum(scorer.score(r) for r in benign) / len(benign) < 10


def test_demo_pipeline_warm_start_fills_session_and_alerts():
    pipe = DemoPipeline(warm_seconds=600)
    pipe.start()
    pipe.stop()
    s = Session()
    drain(pipe, s)
    now = time.time()
    assert s.total_flows > 5000
    assert 0 < s.threat_flows < s.total_flows
    ips = {a.src_ip for a in s.alerts}
    assert {"198.51.100.77", "203.0.113.45", "203.0.113.9"} <= ips
    assert any(a.severity.value == "CRITICAL" for a in s.alerts)
    timeline = s.timeline(now)
    assert len(timeline) == WINDOW_BUCKETS
    assert sum(b.threats for b in timeline) > 500
    assert s.top_sources(1)[0].ip == "198.51.100.77"


def _res(src, proba, iso=False, ae=False, nbytes=1000):
    r = DetectionResult(src_ip=src, dst_ip="10.0.0.1", src_port=1234, dst_port=22, protocol="TCP",
                        timestamp=0.0, total_bytes=nbytes, supervised_proba=proba,
                        supervised_label="ATTACK" if proba >= 0.5 else "BENIGN",
                        iso_anomaly=iso, ae_anomaly=ae)
    r.is_threat = proba >= 0.5 or iso or ae
    return r


def test_session_scores_buckets_and_profiles():
    s = Session()
    t0 = 1000 * BUCKET_SECONDS
    s.add_result(_res("10.0.0.9", 0.02), seen=t0)                      # benign
    s.add_result(_res("10.0.0.9", 0.02, ae=True), seen=t0 + 1)         # lone AE flag -> low
    s.add_result(_res("203.0.113.5", 0.98, True, True), seen=t0 + 2)   # critical
    s.add_result(_res("203.0.113.5", 0.72), seen=t0 + BUCKET_SECONDS)  # 54 -> high
    assert s.total_flows == 4 and s.threat_flows == 2
    b0, b1 = s.timeline(t0 + BUCKET_SECONDS, 2)
    assert (b0.benign, b0.low, b0.crit) == (1, 1, 1)
    assert b1.high == 1 and b1.top == "high"
    prof = s.sources["203.0.113.5"]
    assert prof.threat_flows == 2 and prof.known == 2 and round(prof.max_risk) == 98
    assert "10.0.0.9" not in s.sources
    assert s.peak.res.src_ip == "203.0.113.5"
    assert [sf.res.src_ip for sf in s.newest(10, threats_only=True)] == ["203.0.113.5"] * 2
    assert s.newest(10, needle="10.0.0.9:1234")[0].res.src_ip == "10.0.0.9"
    assert s.throughput_series(t0 + 2 * BUCKET_SECONDS, 2) == [3000 / BUCKET_SECONDS, 1000 / BUCKET_SECONDS]
