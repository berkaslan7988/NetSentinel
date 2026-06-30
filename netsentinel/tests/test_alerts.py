"""Tests for alerts.scoring and alerts.engine.

In particular, verifies that the AE false-positive scenario from the user's live
logs is suppressed.
"""
from alerts.alert import Alert
from alerts.engine import AlertEngine
from alerts.scoring import RiskScorer, Severity, severity_for
from detection.result import DetectionResult


def result(src="1.1.1.1", dst="2.2.2.2", dport=443, proto="TCP",
           label="BENIGN", proba=0.0, iso_anom=False, ae_anom=False):
    return DetectionResult(
        src_ip=src, dst_ip=dst, src_port=12345, dst_port=dport, protocol=proto,
        timestamp=0.0, supervised_label=label, supervised_proba=proba,
        iso_anomaly=iso_anom, iso_score=0.0, ae_anomaly=ae_anom, ae_error=0.0,
    )


# --------------------------------------------------------------------- #
# Scoring - false-positive suppression
# --------------------------------------------------------------------- #
def test_single_ae_flag_is_low_risk():
    # the user's log: RF=0.05, only AE anomalous -> NO alert
    s = RiskScorer()
    r = result(proba=0.05, iso_anom=False, ae_anom=True)
    score = s.score(r)
    assert score == 11.25                      # 75*0.05 + 25*0.30
    assert s.severity(score) is Severity.LOW


def test_both_unsup_agree_is_medium():
    s = RiskScorer()
    r = result(proba=0.05, iso_anom=True, ae_anom=True)
    score = s.score(r)
    assert score == 28.75                      # 75*0.05 + 25*1.0
    assert s.severity(score) is Severity.MEDIUM


def test_known_attack_high_or_critical():
    s = RiskScorer()
    r = result(label="ATTACK", proba=0.95, iso_anom=False, ae_anom=False)
    score = s.score(r)
    assert score >= 50                         # 75*0.95 = 71.25
    assert s.severity(score) in (Severity.HIGH, Severity.CRITICAL)


def test_benign_no_signal_zero():
    s = RiskScorer()
    assert s.score(result(proba=0.0)) == 0.0


def test_severity_thresholds():
    assert severity_for(10) is Severity.LOW
    assert severity_for(25) is Severity.MEDIUM
    assert severity_for(50) is Severity.HIGH
    assert severity_for(75) is Severity.CRITICAL
    assert severity_for(99) is Severity.CRITICAL


# --------------------------------------------------------------------- #
# AlertEngine - alert generation & dedup
# --------------------------------------------------------------------- #
def test_low_risk_produces_no_alert():
    alerts = []
    eng = AlertEngine(on_alert=alerts.append)
    # only AE anomalous -> risk 11.25 < min_risk(25)
    out = eng.process(result(proba=0.05, ae_anom=True), now=0.0)
    assert out is None
    assert alerts == []


def test_known_attack_emits_alert():
    alerts = []
    eng = AlertEngine(on_alert=alerts.append)
    out = eng.process(result(label="ATTACK", proba=0.95), now=0.0)
    assert out is not None
    assert isinstance(out, Alert)
    assert len(alerts) == 1
    assert out.severity in (Severity.HIGH, Severity.CRITICAL)


def test_dedup_same_ip_in_window():
    alerts = []
    eng = AlertEngine(on_alert=alerts.append, window_seconds=60)
    # 50 threat flows from the same IP (PortScan-like) -> ONE alert
    for i in range(50):
        eng.process(result(src="10.0.0.5", label="ATTACK", proba=0.9,
                           dport=1000 + i), now=float(i))
    assert len(alerts) == 1                    # single aggregate alert
    assert alerts[0].flow_count == 50
    # 50 flows -> at least HIGH severity (flow-count escalation)
    assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_separate_ips_separate_alerts():
    alerts = []
    eng = AlertEngine(on_alert=alerts.append)
    eng.process(result(src="10.0.0.1", label="ATTACK", proba=0.9), now=0.0)
    eng.process(result(src="10.0.0.2", label="ATTACK", proba=0.9), now=0.0)
    assert len(alerts) == 2


def test_window_expiry_new_alert():
    alerts = []
    eng = AlertEngine(on_alert=alerts.append, window_seconds=60)
    eng.process(result(src="10.0.0.7", label="ATTACK", proba=0.9), now=0.0)
    eng.process(result(src="10.0.0.7", label="ATTACK", proba=0.9), now=120.0)  # window expired
    assert len(alerts) == 2


def test_top_attackers_ranking():
    eng = AlertEngine()
    for _ in range(10):
        eng.process(result(src="10.0.0.9", label="ATTACK", proba=0.9), now=0.0)
    for _ in range(3):
        eng.process(result(src="10.0.0.8", label="ATTACK", proba=0.9), now=0.0)
    top = eng.top_attackers(5)
    assert top[0].src_ip == "10.0.0.9"
    assert top[0].threat_count == 10
    assert top[1].src_ip == "10.0.0.8"


def test_flood_of_normal_traffic_silent():
    # the user's scenario: 60 normal HTTPS flows, all with only AE blowing up
    alerts = []
    eng = AlertEngine(on_alert=alerts.append)
    for i in range(60):
        eng.process(result(src=f"192.168.1.{i % 5}", proba=0.05, ae_anom=True),
                    now=float(i))
    assert alerts == []                        # no spam - problem solved
