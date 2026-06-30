"""NetSentinel — Dashboard widget'ları (Faz 7).

Fosfor yeşil terminal estetiğinde, yeniden kullanılabilir panel parçaları.
Tümü saf görsel: veriyi dışarıdan (UI thread'inde, QTimer ile) alır; kendi
başına ağ/inference yapmaz.
"""
from __future__ import annotations

import time
from collections import deque
from typing import List

import pyqtgraph as pg
from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from ui import theme


# --------------------------------------------------------------------- #
class StatCard(QFrame):
    """Tek bir istatistik kartı (büyük değer + küçük etiket)."""

    def __init__(self, label: str, initial: str = "0") -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        self.value = QLabel(initial)
        self.value.setObjectName("statValue")
        self.caption = QLabel(label.upper())
        self.caption.setObjectName("statLabel")
        lay.addWidget(self.value)
        lay.addWidget(self.caption)

    def set_value(self, text: str) -> None:
        self.value.setText(text)


class StatBar(QWidget):
    """Üst sıradaki istatistik kartları."""

    def __init__(self) -> None:
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.flows = StatCard("akış")
        self.threats = StatCard("tehdit")
        self.alerts = StatCard("alarm")
        self.throughput = StatCard("throughput")
        for c in (self.flows, self.threats, self.alerts, self.throughput):
            lay.addWidget(c)

    def update_stats(self, stats) -> None:
        self.flows.set_value(str(stats.total_flows))
        self.threats.set_value(str(stats.total_threats))
        self.alerts.set_value(str(stats.total_alerts))
        kbps = stats.last_throughput_bps / 1024.0
        self.throughput.set_value(f"{kbps:.1f} KB/s")


# --------------------------------------------------------------------- #
class FlowTable(QFrame):
    """Renk kodlu canlı akış tablosu (yeni satır üstte, ring buffer)."""

    COLS = ["zaman", "kaynak", "hedef", "proto", "etiket", "risk"]

    def __init__(self, max_rows: int = 200) -> None:
        super().__init__()
        self.setObjectName("panel")
        self.max_rows = max_rows
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.addWidget(self._header("CANLI AKIŞLAR"))
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels([c.upper() for c in self.COLS])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.table)

    @staticmethod
    def _header(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {theme.FG_DIM}; letter-spacing: 2px; padding: 2px;")
        return lbl

    def add_result(self, res) -> None:
        self.table.insertRow(0)
        is_attack = res.supervised_label == "ATTACK" or res.is_threat
        color = QColor(theme.ATTACK_COLOR if is_attack else theme.BENIGN_COLOR)
        t = time.strftime("%H:%M:%S", time.localtime(res.timestamp or time.time()))
        cells = [
            t,
            f"{res.src_ip}:{res.src_port}",
            f"{res.dst_ip}:{res.dst_port}",
            res.protocol,
            res.supervised_label or "-",
            f"{res.threat_score * 100:.0f}",
        ]
        for col, txt in enumerate(cells):
            item = QTableWidgetItem(str(txt))
            item.setForeground(QBrush(color))
            self.table.setItem(0, col, item)
        while self.table.rowCount() > self.max_rows:
            self.table.removeRow(self.table.rowCount() - 1)


# --------------------------------------------------------------------- #
class AlertPanel(QFrame):
    """Severity renkli canlı alarm akışı."""

    def __init__(self, max_rows: int = 100) -> None:
        super().__init__()
        self.setObjectName("panel")
        self.max_rows = max_rows
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.addWidget(FlowTable._header("ALARMLAR"))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["SEVERITY", "KAYNAK", "TÜR", "AKIŞ"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.table)

    def add_alert(self, alert) -> None:
        self.table.insertRow(0)
        color = QColor(theme.SEVERITY_COLORS.get(alert.severity.value, theme.FG))
        types = ", ".join(sorted(alert.attack_types)) if alert.attack_types else "anomali"
        cells = [alert.severity.value, alert.src_ip, types, str(alert.flow_count)]
        for col, txt in enumerate(cells):
            item = QTableWidgetItem(str(txt))
            item.setForeground(QBrush(color))
            if col == 0:
                f = QFont(); f.setBold(True); item.setFont(f)
            self.table.setItem(0, col, item)
        while self.table.rowCount() > self.max_rows:
            self.table.removeRow(self.table.rowCount() - 1)


# --------------------------------------------------------------------- #
class TopAttackers(QFrame):
    """En aktif kaynak IP'ler (top-N)."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("panel")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.addWidget(FlowTable._header("EN AKTİF KAYNAKLAR"))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["KAYNAK IP", "TEHDİT", "MAX RİSK"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.table)

    def update_attackers(self, profiles: List) -> None:
        self.table.setRowCount(0)
        for p in profiles:
            r = self.table.rowCount()
            self.table.insertRow(r)
            for col, txt in enumerate([p.src_ip, str(p.threat_count), f"{p.max_risk:.0f}"]):
                self.table.setItem(r, col, QTableWidgetItem(str(txt)))


# --------------------------------------------------------------------- #
class TimeSeriesChart(pg.PlotWidget):
    """Sabit uzunlukta ring buffer'lı gerçek zamanlı çizgi grafiği."""

    def __init__(self, title: str, color: str, maxlen: int = 120) -> None:
        super().__init__()
        self.setBackground(theme.BG_PANEL)
        self.showGrid(x=False, y=True, alpha=0.2)
        self.setTitle(title, color=theme.FG_DIM, size="9pt")
        self.getAxis("left").setPen(theme.GRID)
        self.getAxis("bottom").setPen(theme.GRID)
        self.getAxis("left").setTextPen(theme.MUTED)
        self.getAxis("bottom").setTextPen(theme.MUTED)
        self._data = deque(maxlen=maxlen)
        self._curve = self.plot(pen=pg.mkPen(color, width=2))

    def push(self, value: float) -> None:
        self._data.append(float(value))
        self._curve.setData(list(self._data))
