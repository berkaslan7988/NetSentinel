"""NetSentinel — DBWriter (Faz 6).

Akış/alarm kayıtlarını arka plan thread'inde **toplu** (batch) yazar. Tespit ve
alarm yolu bloklamaz: sadece kuyruğa koyar. Yazıcı, kayıtlar `batch_size`'a
ulaşınca ya da `flush_interval` geçince DB'ye topluca yazar (her kayıtta tek tek
yazmak yavaştır — roadmap, Faz 6).

Kullanım:
    db = Database(config.DB_PATH)
    writer = DBWriter(db); writer.start()
    writer.submit_result(detection_result)   # akış satırı
    writer.submit_alert(alert)               # alarm satırı
    ...
    writer.stop()                            # kalan batch'i de yazar
"""
from __future__ import annotations

import queue
import threading
import time
from typing import Optional

import config
from alerts.alert import Alert
from detection.result import DetectionResult
from storage.database import Database

_STOP = object()


def result_to_flow_row(res: DetectionResult) -> tuple:
    """DetectionResult -> flows tablosu satırı (FLOW_COLS sırasında)."""
    anomaly = res.ae_error if res.ae_error is not None else res.iso_score
    return (
        res.timestamp, res.src_ip, res.dst_ip, res.src_port, res.dst_port,
        res.protocol, res.duration, res.fwd_packets, res.bwd_packets,
        res.total_bytes, res.supervised_label, res.supervised_proba, anomaly,
    )


def alert_to_row(alert: Alert) -> tuple:
    """Alert -> alerts tablosu satırı (ALERT_COLS sırasında)."""
    attack_type = ", ".join(sorted(alert.attack_types)) if alert.attack_types else ""
    return (
        alert.alert_id, alert.last_seen, alert.src_ip, alert.sample_dst,
        attack_type, alert.risk_score, alert.severity.value, alert.flow_count,
    )


class DBWriter:
    def __init__(
        self,
        db: Database,
        batch_size: int = None,
        flush_interval: float = None,
    ) -> None:
        self.db = db
        self.batch_size = batch_size if batch_size is not None else config.DB_BATCH_SIZE
        self.flush_interval = flush_interval if flush_interval is not None else config.DB_FLUSH_INTERVAL
        self._q: "queue.Queue" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self.flows_written = 0
        self.alerts_written = 0

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="DBWriter", daemon=True)
        self._thread.start()

    def submit_result(self, res: DetectionResult) -> None:
        self._q.put(("flow", result_to_flow_row(res)))

    def submit_alert(self, alert: Alert) -> None:
        self._q.put(("alert", alert_to_row(alert)))

    def _run(self) -> None:
        flow_buf, alert_buf = [], []
        last_flush = time.time()

        def flush() -> None:
            nonlocal flow_buf, alert_buf, last_flush
            if flow_buf:
                self.flows_written += self.db.insert_flows(flow_buf)
                flow_buf = []
            if alert_buf:
                self.alerts_written += self.db.insert_alerts(alert_buf)
                alert_buf = []
            last_flush = time.time()

        while True:
            timeout = max(0.05, self.flush_interval - (time.time() - last_flush))
            try:
                item = self._q.get(timeout=timeout)
            except queue.Empty:
                flush()
                continue
            if item is _STOP:
                flush()
                break
            kind, row = item
            (flow_buf if kind == "flow" else alert_buf).append(row)
            if len(flow_buf) + len(alert_buf) >= self.batch_size:
                flush()

    def stop(self, timeout: float = 3.0) -> None:
        if self._thread is None:
            return
        self._q.put(_STOP)
        self._thread.join(timeout=timeout)
        self._thread = None
