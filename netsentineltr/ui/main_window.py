"""NetSentinel — Dashboard ana penceresi (Faz 7).

Mimari kuralı (roadmap Bölüm 2 & Faz 7): UI thread'i ASLA ağır iş yapmaz.
Pipeline (capture/inference/alert) kendi arka plan thread'lerinde çalışır ve
sonuçları thread-safe kuyruklara koyar. Burada bir QTimer 250ms'de bir kuyrukları
boşaltıp widget'ları günceller — worker thread'den widget'a asla dokunulmaz.
"""
from __future__ import annotations

import os
import queue
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QMainWindow,
    QPushButton, QVBoxLayout, QWidget,
)

import config
from ui import theme
from ui.pipeline import (
    LivePipeline, ReplayPipeline, csv_result_source, db_result_source,
)
from ui.widgets import (
    AlertPanel, FlowTable, StatBar, TimeSeriesChart, TopAttackers,
)

UI_REFRESH_MS = 250
MAX_DRAIN = 200  # tek güncellemede kuyruktan en çok kaç öğe çekilsin


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NetSentinel")
        self.resize(1280, 800)
        self.pipeline = None
        self._replay_csv: Optional[str] = None

        self._build_ui()

        self.timer = QTimer(self)
        self.timer.setInterval(UI_REFRESH_MS)
        self.timer.timeout.connect(self._tick)

    # ----------------------------------------------------------------- #
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # Başlık
        title = QLabel(theme.banner())
        title.setObjectName("title")
        root.addWidget(title)

        # Kontrol çubuğu
        root.addLayout(self._build_controls())

        # İstatistik kartları
        self.stat_bar = StatBar()
        root.addWidget(self.stat_bar)

        # Grafikler
        charts = QHBoxLayout()
        self.throughput_chart = TimeSeriesChart("THROUGHPUT (KB/s)", theme.GRAPH_THROUGHPUT)
        self.anomaly_chart = TimeSeriesChart("ANOMALİ / TEHDİT ORANI", theme.GRAPH_ANOMALY)
        charts.addWidget(self.throughput_chart)
        charts.addWidget(self.anomaly_chart)
        root.addLayout(charts)

        # Alt panel: akış tablosu | (alarm + top attackers)
        grid = QGridLayout()
        self.flow_table = FlowTable()
        self.alert_panel = AlertPanel()
        self.top_attackers = TopAttackers()
        grid.addWidget(self.flow_table, 0, 0, 2, 1)
        grid.addWidget(self.alert_panel, 0, 1)
        grid.addWidget(self.top_attackers, 1, 1)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 1)
        root.addLayout(grid)

    def _build_controls(self) -> QHBoxLayout:
        bar = QHBoxLayout()

        self.source_combo = QComboBox()
        self.source_combo.addItems(["Canlı", "Replay: CSV", "Replay: DB"])

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["hybrid", "supervised", "unsupervised"])

        self.file_btn = QPushButton("CSV seç…")
        self.file_btn.clicked.connect(self._pick_csv)

        self.start_btn = QPushButton("▶ BAŞLAT")
        self.start_btn.clicked.connect(self._start)
        self.stop_btn = QPushButton("■ DURDUR")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.setEnabled(False)

        self.status = QLabel("hazır")
        self.status.setStyleSheet(f"color: {theme.MUTED};")

        bar.addWidget(QLabel("Kaynak:"))
        bar.addWidget(self.source_combo)
        bar.addWidget(QLabel("Mod:"))
        bar.addWidget(self.mode_combo)
        bar.addWidget(self.file_btn)
        bar.addStretch(1)
        bar.addWidget(self.status)
        bar.addStretch(1)
        bar.addWidget(self.start_btn)
        bar.addWidget(self.stop_btn)
        return bar

    # ----------------------------------------------------------------- #
    def _pick_csv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "CIC-IDS2017 CSV seç", str(config.CIC_DATA_DIR), "CSV (*.csv)"
        )
        if path:
            self._replay_csv = path
            self.status.setText(f"CSV: {os.path.basename(path)}")

    def _start(self) -> None:
        source = self.source_combo.currentText()
        mode = self.mode_combo.currentText()
        try:
            if source == "Canlı":
                self.pipeline = LivePipeline(mode=mode)
            elif source == "Replay: CSV":
                if not self._replay_csv:
                    self.status.setText("önce CSV seç")
                    return
                from detection.engine import DetectionEngine
                engine = DetectionEngine(mode=mode)
                src = csv_result_source(engine, self._replay_csv, limit=5000)
                self.pipeline = ReplayPipeline(src, rate_hz=30)
            else:  # Replay: DB
                from storage.database import Database
                db = Database(config.DB_PATH)
                self.pipeline = ReplayPipeline(db_result_source(db), rate_hz=30)
        except Exception as exc:
            self.status.setText(f"hata: {exc}")
            return

        self.pipeline.start()
        self.timer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.source_combo.setEnabled(False)
        self.status.setText("● çalışıyor")

    def _stop(self) -> None:
        self.timer.stop()
        if self.pipeline is not None:
            self.pipeline.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.source_combo.setEnabled(True)
        self.status.setText("durduruldu")

    # ----------------------------------------------------------------- #
    def _tick(self) -> None:
        """QTimer slot — UI thread'inde kuyrukları boşaltıp widget'ları günceller."""
        if self.pipeline is None:
            return
        threats_in_window = 0
        drained = 0
        # Sonuçlar
        while drained < MAX_DRAIN:
            try:
                res = self.pipeline.results_q.get_nowait()
            except queue.Empty:
                break
            self.flow_table.add_result(res)
            if res.is_threat:
                threats_in_window += 1
            drained += 1
        # Alarmlar
        while True:
            try:
                alert = self.pipeline.alerts_q.get_nowait()
            except queue.Empty:
                break
            self.alert_panel.add_alert(alert)

        # İstatistik kartları + grafikler
        stats = self.pipeline.stats
        self.stat_bar.update_stats(stats)
        self.throughput_chart.push(stats.last_throughput_bps / 1024.0)
        self.anomaly_chart.push(threats_in_window)
        self.top_attackers.update_attackers(self.pipeline.top_attackers(10))

    def closeEvent(self, event) -> None:
        self._stop()
        super().closeEvent(event)
