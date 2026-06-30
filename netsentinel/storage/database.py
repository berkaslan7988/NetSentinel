"""NetSentinel - SQLite storage layer (Phase 6).

Persists flows, alerts and statistics; the dashboard (Phase 7) and reporting
(Phase 9) use the history query API.

Design:
  * A single connection (check_same_thread=False) + a Lock serializes all
    access - simple and correct. Writes are batched via `executemany`.
  * Indexes (timestamp, src_ip) for query speed.
  * WAL mode: reduces read/write contention, smoother under long runs.

Schema (roadmap Section 3, Phase 6):
  flows(id, ts, src_ip, dst_ip, src_port, dst_port, protocol, duration,
        fwd_packets, bwd_packets, total_bytes, label, probability, anomaly_score)
  alerts(id, ts, src_ip, dst_ip, attack_type, risk_score, severity, flow_count)
  stats(ts, total_flows, total_alerts, throughput_bps, packet_drop_rate)
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL    NOT NULL,
    src_ip        TEXT    NOT NULL,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT,
    duration      REAL,
    fwd_packets   INTEGER,
    bwd_packets   INTEGER,
    total_bytes   INTEGER,
    label         TEXT,
    probability   REAL,
    anomaly_score REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    TEXT,
    ts          REAL    NOT NULL,
    src_ip      TEXT    NOT NULL,
    dst_ip      TEXT,
    attack_type TEXT,
    risk_score  REAL,
    severity    TEXT,
    flow_count  INTEGER
);
CREATE TABLE IF NOT EXISTS stats (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               REAL NOT NULL,
    total_flows      INTEGER,
    total_alerts     INTEGER,
    throughput_bps   REAL,
    packet_drop_rate REAL
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats(ts);
"""

# Column order of the row tuples (for executemany)
FLOW_COLS = ("ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
             "duration", "fwd_packets", "bwd_packets", "total_bytes",
             "label", "probability", "anomaly_score")
ALERT_COLS = ("alert_id", "ts", "src_ip", "dst_ip", "attack_type",
              "risk_score", "severity", "flow_count")
STAT_COLS = ("ts", "total_flows", "total_alerts", "throughput_bps", "packet_drop_rate")


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            try:
                self._conn.execute("PRAGMA journal_mode=WAL;")
            except sqlite3.Error:
                pass
            self._conn.commit()

    # ----------------------------------------------------------------- #
    # Batch writes
    # ----------------------------------------------------------------- #
    def insert_flows(self, rows: Sequence[Sequence]) -> int:
        return self._insert_many("flows", FLOW_COLS, rows)

    def insert_alerts(self, rows: Sequence[Sequence]) -> int:
        return self._insert_many("alerts", ALERT_COLS, rows)

    def insert_stat(self, ts, total_flows, total_alerts, throughput_bps, drop_rate) -> int:
        return self._insert_many(
            "stats", STAT_COLS,
            [(ts, total_flows, total_alerts, throughput_bps, drop_rate)],
        )

    def _insert_many(self, table: str, cols: Sequence[str], rows: Sequence[Sequence]) -> int:
        rows = list(rows)
        if not rows:
            return 0
        placeholders = ",".join("?" * len(cols))
        sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
        with self._lock:
            self._conn.executemany(sql, rows)
            self._conn.commit()
        return len(rows)

    # ----------------------------------------------------------------- #
    # Query API
    # ----------------------------------------------------------------- #
    def _query(self, sql: str, params: Iterable = ()) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def recent_flows(self, limit: int = 100, since: Optional[float] = None,
                     src_ip: Optional[str] = None) -> List[sqlite3.Row]:
        sql = "SELECT * FROM flows"
        clauses, params = [], []
        if since is not None:
            clauses.append("ts >= ?"); params.append(since)
        if src_ip is not None:
            clauses.append("src_ip = ?"); params.append(src_ip)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return self._query(sql, params)

    def recent_alerts(self, limit: int = 100, since: Optional[float] = None,
                      severity: Optional[str] = None) -> List[sqlite3.Row]:
        sql = "SELECT * FROM alerts"
        clauses, params = [], []
        if since is not None:
            clauses.append("ts >= ?"); params.append(since)
        if severity is not None:
            clauses.append("severity = ?"); params.append(severity)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        return self._query(sql, params)

    def recent_stats(self, limit: int = 100) -> List[sqlite3.Row]:
        return self._query("SELECT * FROM stats ORDER BY ts DESC LIMIT ?", (limit,))

    def count(self, table: str) -> int:
        if table not in ("flows", "alerts", "stats"):
            raise ValueError(f"invalid table: {table}")
        return self._query(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"]

    def top_source_ips(self, limit: int = 10) -> List[sqlite3.Row]:
        return self._query(
            "SELECT src_ip, COUNT(*) AS flows, "
            "SUM(CASE WHEN label='ATTACK' THEN 1 ELSE 0 END) AS attacks "
            "FROM flows GROUP BY src_ip ORDER BY flows DESC LIMIT ?",
            (limit,),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
