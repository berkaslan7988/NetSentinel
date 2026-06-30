"""Tests for storage.database and storage.writer.

Uses a temporary SQLite file - never touches real data.
"""
import time

import pytest

from alerts.alert import Alert
from alerts.scoring import Severity
from detection.result import DetectionResult
from storage.database import Database
from storage.writer import DBWriter, alert_to_row, result_to_flow_row


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "test.db")
    yield d
    d.close()


def make_result(src="10.0.0.1", label="ATTACK", proba=0.9, ts=0.0):
    return DetectionResult(
        src_ip=src, dst_ip="2.2.2.2", src_port=1234, dst_port=80, protocol="TCP",
        timestamp=ts, duration=1.5, fwd_packets=3, bwd_packets=2, total_bytes=500,
        supervised_label=label, supervised_proba=proba,
        iso_anomaly=False, iso_score=0.1, ae_anomaly=True, ae_error=12.3,
    )


def make_alert(src="10.0.0.1", ts=0.0):
    return Alert(alert_id="A000001", src_ip=src, first_seen=ts, last_seen=ts,
                 risk_score=70.0, severity=Severity.HIGH, flow_count=5,
                 attack_types={"ATTACK"}, sample_dst="2.2.2.2", sample_dst_port=80)


# --------------------------------------------------------------------- #
# Schema & basic insert/query
# --------------------------------------------------------------------- #
def test_schema_created(db):
    assert db.count("flows") == 0
    assert db.count("alerts") == 0
    assert db.count("stats") == 0


def test_insert_and_query_flows(db):
    rows = [result_to_flow_row(make_result(ts=float(i))) for i in range(5)]
    n = db.insert_flows(rows)
    assert n == 5
    assert db.count("flows") == 5
    recent = db.recent_flows(limit=3)
    assert len(recent) == 3
    assert recent[0]["ts"] == 4.0          # newest first (DESC)
    assert recent[0]["label"] == "ATTACK"
    assert recent[0]["total_bytes"] == 500


def test_query_by_src_ip(db):
    db.insert_flows([result_to_flow_row(make_result(src="1.1.1.1"))])
    db.insert_flows([result_to_flow_row(make_result(src="2.2.2.2"))])
    only = db.recent_flows(src_ip="1.1.1.1")
    assert len(only) == 1
    assert only[0]["src_ip"] == "1.1.1.1"


def test_query_since(db):
    db.insert_flows([result_to_flow_row(make_result(ts=t)) for t in (10, 20, 30)])
    recent = db.recent_flows(since=20)
    assert len(recent) == 2                # ts >= 20


def test_insert_and_query_alerts(db):
    db.insert_alerts([alert_to_row(make_alert())])
    a = db.recent_alerts()
    assert len(a) == 1
    assert a[0]["severity"] == "HIGH"
    assert a[0]["flow_count"] == 5
    assert a[0]["attack_type"] == "ATTACK"


def test_insert_stat_and_query(db):
    db.insert_stat(ts=1.0, total_flows=100, total_alerts=3,
                   throughput_bps=2048.0, drop_rate=0.01)
    s = db.recent_stats()
    assert len(s) == 1
    assert s[0]["total_flows"] == 100
    assert s[0]["packet_drop_rate"] == 0.01


def test_top_source_ips(db):
    for _ in range(5):
        db.insert_flows([result_to_flow_row(make_result(src="9.9.9.9"))])
    for _ in range(2):
        db.insert_flows([result_to_flow_row(make_result(src="8.8.8.8", label="BENIGN"))])
    top = db.top_source_ips()
    assert top[0]["src_ip"] == "9.9.9.9"
    assert top[0]["flows"] == 5
    assert top[0]["attacks"] == 5


# --------------------------------------------------------------------- #
# DBWriter - batch + thread
# --------------------------------------------------------------------- #
def test_writer_batches_and_persists(db):
    writer = DBWriter(db, batch_size=10, flush_interval=0.2)
    writer.start()
    for i in range(25):
        writer.submit_result(make_result(ts=float(i)))
    writer.submit_alert(make_alert())
    writer.stop()                          # flushes the remaining batch too
    assert db.count("flows") == 25
    assert db.count("alerts") == 1
    assert writer.flows_written == 25
    assert writer.alerts_written == 1


def test_writer_flush_on_interval(db):
    writer = DBWriter(db, batch_size=1000, flush_interval=0.15)
    writer.start()
    writer.submit_result(make_result())
    time.sleep(0.4)                        # should flush by interval before batch fills
    assert db.count("flows") == 1
    writer.stop()


def test_no_bloat_many_inserts_fast(db):
    # can 5000 records be written and queried quickly (indexed)
    rows = [result_to_flow_row(make_result(src=f"10.0.{i % 255}.{i % 7}", ts=float(i)))
            for i in range(5000)]
    db.insert_flows(rows)
    assert db.count("flows") == 5000
    start = time.perf_counter()
    db.recent_flows(limit=50)
    db.recent_flows(src_ip="10.0.0.0")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5                   # indexed queries are fast
