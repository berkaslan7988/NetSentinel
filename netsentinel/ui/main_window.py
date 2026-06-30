"""NetSentinel - Dashboard main window (Phase 7).

Architecture rule (roadmap Section 2 & Phase 7): the UI thread NEVER does heavy
work. The pipeline (capture/inference/alerting) runs on its own background
threads and puts results on thread-safe queues. Here a QTimer drains the queues
every 250ms and updates the widgets - a worker thread never touches a widget.
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
MAX_DRAIN = 200  # max items pulled from a queue per update


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

        # Title
        title = QLabel(theme.banner())
        title.setObjectName("title")
        root.addWidget(title)

        # Control bar
        root.addLayout(self._build_controls())

        # Stat cards
        self.stat_bar = StatBar()
        root.addWidget(self.stat_bar)

        # Charts
        charts = QHBoxLayout()
        self.throughput_chart = TimeSeriesChart("THROUGHPUT (KB/s)", theme.GRAPH_THROUGHPUT)
        self.anomaly_chart = TimeSeriesChart("ANOMALY / THREAT RATE", theme.GRAPH_ANOMALY)
        charts.addWidget(self.throughput_chart)
        charts.addWidget(self.anomaly_chart)
        root.addLayout(charts)

        # Bottom: flow table | (alerts + top attackers)
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
        self.source_combo.addItems(["Live", "Replay: CSV", "Replay: DB"])

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["hybrid", "supervised", "unsupervised"])

        self.file_btn = QPushButton("Pick CSV...")
        self.file_btn.clicked.connect(self._pick_csv)

        self.start_btn = QPushButton("> START")
        self.start_btn.clicked.connect(self._start)
        self.stop_btn = QPushButton("# STOP")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.clicked.connect(self._stop)
        self.stop_btn.setEnabled(False)

        self.status = QLabel("ready")
        self.status.setStyleSheet(f"color: {theme.MUTED};")

        bar.addWidget(QLabel("Source:"))
        bar.addWidget(self.source_combo)
        bar.addWidget(QLabel("Mode:"))
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
            self, "Pick a CIC-IDS2017 CSV", str(config.CIC_DATA_DIR), "CSV (*.csv)"
        )
        if path:
            self._replay_csv = path
            self.status.setText(f"CSV: {os.path.basename(path)}")

    def _start(self) -> None:
        source = self.source_combo.currentText()
        mode = self.mode_combo.currentText()
        try:
            if source == "Live":
                self.pipeline = LivePipeline(mode=mode)
            elif source == "Replay: CSV":
                if not self._replay_csv:
                    self.status.setText("pick a CSV first")
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
            self.status.setText(f"error: {exc}")
            return

        self.pipeline.start()
        self.timer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.source_combo.setEnabled(False)
        self.status.setText("* running")

    def _stop(self) -> None:
        self.timer.stop()
        if self.pipeline is not None:
            self.pipeline.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.source_combo.setEnabled(True)
        self.status.setText("stopped")

    # ----------------------------------------------------------------- #
    def _tick(self) -> None:
        """QTimer slot - drains the queues and updates widgets on the UI thread."""
        if self.pipeline is None:
            return
        threats_in_window = 0
        drained = 0
        # Results
        while drained < MAX_DRAIN:
            try:
                res = self.pipeline.results_q.get_nowait()
            except queue.Empty:
                break
            self.flow_table.add_result(res)
            if res.is_threat:
                threats_in_window += 1
            drained += 1
        # Alerts
        while True:
            try:
                alert = self.pipeline.alerts_q.get_nowait()
            except queue.Empty:
                break
            self.alert_panel.add_alert(alert)

        # Stat cards + charts
        stats = self.pipeline.stats
        self.stat_bar.update_stats(stats)
        self.throughput_chart.push(stats.last_throughput_bps / 1024.0)
        self.anomaly_chart.push(threats_in_window)
        self.top_attackers.update_attackers(self.pipeline.top_attackers(10))

    def closeEvent(self, event) -> None:
        self._stop()
        super().closeEvent(event)
