"""NetSentinel — Dashboard veri hattı (Faz 7), Qt'den bağımsız.

UI thread'ini hafif tutmak için tüm ağır iş (yakalama, akış, inference, alarm)
burada arka plan thread'lerinde yapılır. UI yalnızca thread-safe kuyruklardan
(results_q, alerts_q) okuyup widget'ları günceller (QTimer ile 250ms batch).

İki kaynak:
  * LivePipeline   — Sniffer -> FlowManager -> DetectionWorker -> AlertEngine.
  * ReplayPipeline — CSV (CIC-IDS2017) ya da DB'den kayıtları throttled besler,
    böylece canlı trafik olmadan da demo/GIF çekilebilir.

Her ikisi de DetectionPipeline tabanını paylaşır (kuyruklar + alarm + istatistik).
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional

import config
from alerts.engine import AlertEngine
from detection.result import DetectionResult


@dataclass
class PipelineStats:
    started_at: float = 0.0
    total_flows: int = 0
    total_threats: int = 0
    total_alerts: int = 0
    total_bytes: int = 0
    last_throughput_bps: float = 0.0

    def elapsed(self) -> float:
        return max(1e-6, time.time() - self.started_at)


class DetectionPipeline:
    """Sonuçları kuyruklayan + alarm üreten ortak taban."""

    def __init__(self, alert_engine: Optional[AlertEngine] = None) -> None:
        self.results_q: "queue.Queue[DetectionResult]" = queue.Queue()
        self.alerts_q: "queue.Queue" = queue.Queue()
        self.alert_engine = alert_engine or AlertEngine(on_alert=self._on_alert)
        if self.alert_engine.on_alert is None:
            self.alert_engine.on_alert = self._on_alert
        self.stats = PipelineStats(started_at=time.time())
        self._win_bytes = 0
        self._win_start = time.time()

    def _on_alert(self, alert) -> None:
        self.stats.total_alerts += 1
        self.alerts_q.put(alert)

    def emit(self, res: DetectionResult) -> None:
        """Bir tahmini işler: alarm + kuyruk + istatistik."""
        self.alert_engine.process(res)
        self.results_q.put(res)
        self.stats.total_flows += 1
        if res.is_threat:
            self.stats.total_threats += 1
        self.stats.total_bytes += int(res.total_bytes or 0)
        # kayan pencere throughput (1 sn)
        self._win_bytes += int(res.total_bytes or 0)
        now = time.time()
        if now - self._win_start >= 1.0:
            self.stats.last_throughput_bps = self._win_bytes / (now - self._win_start)
            self._win_bytes = 0
            self._win_start = now

    def top_attackers(self, n: int = 10):
        return self.alert_engine.top_attackers(n)


# --------------------------------------------------------------------- #
# Canlı hat
# --------------------------------------------------------------------- #
class LivePipeline(DetectionPipeline):
    def __init__(self, mode: str = "hybrid", iface=None, bpf_filter: str = "ip") -> None:
        super().__init__()
        from capture.sniffer import Sniffer
        from detection.engine import DetectionEngine
        from detection.worker import DetectionWorker
        from flows.manager import FlowManager

        self.engine = DetectionEngine(mode=mode)
        self._in_q: "queue.Queue" = queue.Queue()
        self._det_out: "queue.Queue" = queue.Queue()
        self.worker = DetectionWorker(self.engine, self._in_q, self._det_out)
        self.manager = FlowManager(
            on_flow_closed=lambda flow: self.worker.submit(flow),
            active_timeout=config.FLOW_ACTIVE_TIMEOUT,
            idle_timeout=config.FLOW_IDLE_TIMEOUT,
        )
        self.sniffer = Sniffer(
            on_packet=self.manager.process_packet, iface=iface, bpf_filter=bpf_filter
        )
        self._consumer: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        self.stats = PipelineStats(started_at=time.time())
        self.worker.start()
        self.manager.start_cleanup(interval=config.FLOW_CLEANUP_INTERVAL)
        self._stop.clear()
        self._consumer = threading.Thread(target=self._consume, name="LiveConsumer", daemon=True)
        self._consumer.start()
        self.sniffer.start()

    def _consume(self) -> None:
        while not self._stop.is_set():
            try:
                res = self._det_out.get(timeout=0.2)
            except queue.Empty:
                continue
            self.emit(res)

    def stop(self) -> None:
        try:
            self.sniffer.stop()
        except Exception:
            pass
        self.manager.stop_cleanup()
        self.manager.flush_all()
        time.sleep(0.3)
        self.worker.stop()
        self._stop.set()


# --------------------------------------------------------------------- #
# Replay (demo) hattı
# --------------------------------------------------------------------- #
class ReplayPipeline(DetectionPipeline):
    """Önceden hazırlanmış DetectionResult akışını throttled besler."""

    def __init__(self, result_source: Iterable[DetectionResult], rate_hz: float = 20.0) -> None:
        super().__init__()
        self._source = result_source
        self.rate_hz = max(0.1, rate_hz)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        self.stats = PipelineStats(started_at=time.time())
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="Replay", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        delay = 1.0 / self.rate_hz
        for res in self._source:
            if self._stop.is_set():
                break
            self.emit(res)
            time.sleep(delay)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


# --------------------------------------------------------------------- #
# Replay kaynakları (DetectionResult üreten generator'lar)
# --------------------------------------------------------------------- #
_SYNTH_IPS = [f"192.168.1.{i}" for i in range(10, 40)]


def csv_result_source(
    engine, csv_path: str, limit: Optional[int] = None
) -> Iterator[DetectionResult]:
    """CIC-IDS2017 CSV satırlarını DetectionEngine'den geçirip sonuç üretir.

    Gerçek saldırı feature'ları içerdiği için dashboard canlı trafik olmadan da
    saldırı tespitiyle 'yanar' — demo/GIF için ideal.
    """
    import random

    import pandas as pd

    from features.columns import FEATURE_COLUMNS

    df = pd.read_csv(csv_path, nrows=limit, low_memory=False)
    df.columns = df.columns.str.strip()
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise KeyError(f"CSV'de eksik kolon: {missing[:3]}...")
    feats = df[FEATURE_COLUMNS].replace([float("inf"), float("-inf")], 0.0).fillna(0.0)
    rng = random.Random(0)
    ts0 = time.time()
    for i, (_, row) in enumerate(feats.iterrows()):
        vec = row.tolist()
        identity = {
            "src_ip": rng.choice(_SYNTH_IPS),
            "dst_ip": "10.0.0.1",
            "src_port": rng.randint(1024, 65535),
            "dst_port": int(row["Destination Port"]),
            "protocol": "TCP",
            "timestamp": ts0 + i,
        }
        res = engine.predict_vector(vec, identity)
        res.total_bytes = int(row.get("Total Length of Fwd Packets", 0)
                              + row.get("Total Length of Bwd Packets", 0))
        yield res


def db_result_source(db, limit: int = 1000) -> Iterator[DetectionResult]:
    """DB'deki flows tablosundan geçmiş bir oturumu DetectionResult olarak üretir."""
    rows = db.recent_flows(limit=limit)
    for r in reversed(rows):  # eskiden yeniye (kronolojik)
        label = r["label"]
        proba = r["probability"] if r["probability"] is not None else 0.0
        res = DetectionResult(
            src_ip=r["src_ip"], dst_ip=r["dst_ip"] or "",
            src_port=r["src_port"] or 0, dst_port=r["dst_port"] or 0,
            protocol=r["protocol"] or "", timestamp=r["ts"],
            duration=r["duration"] or 0.0,
            fwd_packets=r["fwd_packets"] or 0, bwd_packets=r["bwd_packets"] or 0,
            total_bytes=r["total_bytes"] or 0,
            supervised_label=label, supervised_proba=proba,
            ae_error=r["anomaly_score"],
        )
        res.is_threat = (label == "ATTACK") or (proba is not None and proba >= 0.5)
        res.threat_score = proba or 0.0
        yield res
