"""Pieces shared by several views: flow columns, the painted alert and source
lists, the legend, and number formatting."""
from __future__ import annotations

import time
from typing import List, Optional, Sequence

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFontMetricsF, QPainter
from PySide6.QtWidgets import QGridLayout, QLabel, QWidget

from ui import theme
from ui.i18n import ago, duration, num, t, upper
from ui.session import ScoredFlow, SourceProfile
from ui.tables import Col
from ui.widgets import ElidedLabel, chip_width, label, paint_bar, paint_chip, paint_empty, pal


# ------------------------------------------------------------------ format
def clock(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def fmt_bytes(n: float, per_second: bool = False) -> tuple[str, str]:
    """(value, unit) with one decimal: 842.6 KB/s, 63.1 MB."""
    suffix = "/s" if per_second else ""
    for unit, size in (("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= size:
            return num(n / size, 1), unit + suffix
    return num(n, 0), "B" + suffix


def alert_sev(alert) -> str:
    return theme.sev_key(alert.severity)


def alert_kind(alert) -> str:
    known = "ATTACK" in alert.attack_types
    anomaly = "anomaly" in alert.attack_types
    if known and anomaly:
        return t("Known attack + anomaly")
    return t("Known attack") if known else t("Anomaly")


def flow_flags(sf: ScoredFlow):
    r = sf.res
    rf = None if r.supervised_label is None else r.supervised_label == "ATTACK"
    return (rf, r.iso_anomaly, r.ae_anomaly)


# --------------------------------------------------------------- flow table
def flow_cols(extended: bool = False) -> List[Col]:
    cols = [
        Col("time", t("Time"), "time", 92),
        Col("src", t("Source"), "addr", stretch=1),
        Col("dst", t("Destination"), "addr", stretch=1),
        Col("proto", t("Proto"), "text", 58),
    ]
    if extended:
        cols += [Col("bytes", t("Bytes"), "mono", 84, align=Qt.AlignRight),
                 Col("dur", t("Duration"), "mono", 84, align=Qt.AlignRight)]
    cols += [
        Col("verdict", t("Verdict"), "verdict", 82),
        Col("pips", t("Signals"), "pips", 106),
        Col("risk", t("Risk"), "risk", 118, align=Qt.AlignRight),
    ]
    return cols


def flow_value(sf: ScoredFlow, key: str):
    r = sf.res
    if key == "time":
        return clock(sf.seen), sf.sev
    if key == "src":
        return r.src_ip, r.src_port, False
    if key == "dst":
        return r.dst_ip, r.dst_port, True
    if key == "proto":
        return r.protocol or "-"
    if key == "bytes":
        v, u = fmt_bytes(r.total_bytes or 0)
        return (f"{v} {u}", "ink2", 400)
    if key == "dur":
        return (f"{num(r.duration or 0, 2)} s", "ink2", 400)
    if key == "verdict":
        return r.supervised_label or "-"
    if key == "pips":
        return flow_flags(sf)
    if key == "risk":
        return sf.risk, sf.sev
    return None


def flow_text(sf: ScoredFlow, key: str) -> str:
    r = sf.res
    return {
        "time": clock(sf.seen), "src": f"{r.src_ip}:{r.src_port}", "dst": f"{r.dst_ip}:{r.dst_port}",
        "proto": r.protocol, "verdict": r.supervised_label or "-", "risk": f"{sf.risk:.0f}",
    }.get(key, "")


def flow_key(sf: ScoredFlow):
    return sf.seq


# ------------------------------------------------------------------ legend
class Legend(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(20)
        self._items = [("benign", t("Benign")), ("med", t("Medium")), ("high", t("High")),
                       ("crit", t("Critical"))]
        fm = QFontMetricsF(theme.ui(12))
        self.setFixedWidth(int(sum(fm.horizontalAdvance(s) + 15 for _, s in self._items)
                               + 14 * (len(self._items) - 1) + 2))

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        f = theme.ui(12)
        fm = QFontMetricsF(f)
        p.setFont(f)
        x = 0.0
        for key, text in self._items:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(getattr(P, key)))
            p.drawRoundedRect(QRectF(x, 5.5, 9, 9), 2, 2)
            p.setPen(QColor(P.ink3))
            tw = fm.horizontalAdvance(text)
            p.drawText(QRectF(x + 15, 0, tw + 2, 20), Qt.AlignVCenter, text)
            x += 15 + tw + 14
        p.end()


# --------------------------------------------------------------- alert list
class AlertList(QWidget):
    """Two-line painted alert rows (overview)."""

    clicked = Signal(str)
    ROW_MIN = 48          # rows stretch so the visible ones fill the panel exactly

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(self.ROW_MIN * 2)
        self.setCursor(Qt.PointingHandCursor)
        self.setMouseTracking(True)
        self._alerts: List = []
        self._now = time.time()
        self._hover = -1

    def set_alerts(self, alerts: Sequence, now: float) -> None:
        self._alerts = list(alerts)
        self._now = now
        self.update()

    def _visible(self) -> int:
        return max(1, self.height() // self.ROW_MIN)

    @property
    def ROW(self) -> float:  # noqa: N802
        return self.height() / self._visible()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        if not self._alerts:
            paint_empty(p, QRectF(self.rect()), t("No alerts"),
                        t("Flows with risk 25 or more open an alert."))
            p.end()
            return
        cw = chip_width()
        for i, a in enumerate(self._alerts[: self._visible()]):
            row_h = self.ROW
            y = i * row_h
            row = QRectF(0, y, self.width(), row_h)
            if i == self._hover:
                p.fillRect(row, QColor(P.hover))
            p.fillRect(QRectF(0, y + row_h - 1, self.width(), 1), QColor(P.line))
            sev = alert_sev(a)
            paint_chip(p, 14, y + row_h / 2, sev)
            y += (row_h - 54) / 2          # centre the two text lines in the row
            x = 14 + cw + 12
            right = self.width() - 14
            # line 1: source IP, risk
            p.setFont(theme.mono(13, 600))
            p.setPen(QColor(P.ink))
            p.drawText(QRectF(x, y + 8, right - x - 50, 20), Qt.AlignVCenter, a.src_ip)
            p.setFont(theme.mono(15, 600))
            p.setPen(theme.sev_ink(sev, P))
            p.drawText(QRectF(right - 50, y + 7, 50, 22), Qt.AlignVCenter | Qt.AlignRight,
                       f"{a.risk_score:.0f}")
            # line 2: what, how much, where; age on the right
            age = ago(self._now - a.last_seen)
            fm_age = QFontMetricsF(theme.mono(11))
            age_w = fm_age.horizontalAdvance(age) + 4
            p.setFont(theme.mono(11))
            p.setPen(QColor(P.ink3))
            p.drawText(QRectF(right - age_w, y + 29, age_w, 18), Qt.AlignVCenter | Qt.AlignRight, age)
            span = duration(max(0.0, a.last_seen - a.first_seen))
            target = f"{a.sample_dst}:{a.sample_dst_port}"
            desc = t("{kind} · {n} flows · {span} · to ", kind=alert_kind(a),
                     n=num(a.flow_count), span=span)
            f = theme.ui(12)
            fm = QFontMetricsF(f)
            avail = right - age_w - 12 - x
            p.setFont(f)
            dw = fm.horizontalAdvance(desc)
            if dw >= avail:
                p.drawText(QRectF(x, y + 29, avail, 18), Qt.AlignVCenter,
                           fm.elidedText(desc + target, Qt.ElideRight, avail))
            else:
                p.drawText(QRectF(x, y + 29, dw + 1, 18), Qt.AlignVCenter, desc)
                fmono = theme.mono(11.5)
                p.setFont(fmono)
                p.setPen(QColor(P.ink2))
                p.drawText(QRectF(x + dw, y + 29, avail - dw, 18), Qt.AlignVCenter,
                           QFontMetricsF(fmono).elidedText(target, Qt.ElideRight, avail - dw))
        p.end()

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        i = int(e.position().y() // self.ROW)
        i = i if i < min(len(self._alerts), self._visible()) else -1
        if i != self._hover:
            self._hover = i
            self.update()

    def leaveEvent(self, e) -> None:  # noqa: N802
        self._hover = -1
        self.update()

    def mousePressEvent(self, e) -> None:  # noqa: N802
        i = int(e.position().y() // self.ROW)
        if 0 <= i < min(len(self._alerts), self._visible()):
            self.clicked.emit(self._alerts[i].alert_id)


class SourceList(QWidget):
    """Painted top-sources rows: IP, threat-flow bar + count, peak risk."""

    clicked = Signal(str)
    ROW = 31

    def __init__(self, rows: int = 5, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(self.ROW * rows)
        self.setCursor(Qt.PointingHandCursor)
        self._rows: List[SourceProfile] = []

    def set_sources(self, sources: Sequence[SourceProfile]) -> None:
        self._rows = list(sources)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        if not self._rows:
            paint_empty(p, QRectF(self.rect()), t("No threat sources yet"))
            p.end()
            return
        top = max(s.threat_flows for s in self._rows) or 1
        w = self.width()
        ip_w = max(118.0, w * 0.36)
        for i, s in enumerate(self._rows[: self.height() // self.ROW]):
            y = i * self.ROW
            p.fillRect(QRectF(0, y + self.ROW - 1, w, 1), QColor(P.line))
            p.setFont(theme.mono(12))
            p.setPen(QColor(P.ink))
            p.drawText(QRectF(14, y, ip_w, self.ROW), Qt.AlignVCenter, s.ip)
            bar_x = 14 + ip_w + 8
            num_w, risk_w = 52.0, 30.0
            bar_w = max(20.0, w - bar_x - num_w - risk_w - 14 - 22)
            paint_bar(p, QRectF(bar_x, y, bar_w, self.ROW), s.threat_flows / top,
                      theme.sev_color(s.sev, P))
            p.setFont(theme.mono(12))
            p.setPen(QColor(P.ink2))
            p.drawText(QRectF(bar_x + bar_w + 8, y, num_w, self.ROW), Qt.AlignVCenter | Qt.AlignRight,
                       num(s.threat_flows))
            p.setFont(theme.mono(12, 600))
            p.setPen(theme.sev_ink(s.sev, P))
            p.drawText(QRectF(w - 14 - risk_w, y, risk_w, self.ROW), Qt.AlignVCenter | Qt.AlignRight,
                       f"{s.max_risk:.0f}")
        p.end()

    def mousePressEvent(self, e) -> None:  # noqa: N802
        i = int(e.position().y() // self.ROW)
        if 0 <= i < len(self._rows):
            self.clicked.emit(self._rows[i].ip)


# ----------------------------------------------------------- fact grid
class Facts(QWidget):
    """Two-column label / value grid used in detail panes."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("transparent")
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(16)
        self.grid.setVerticalSpacing(7)
        self.grid.setColumnStretch(1, 1)
        self._values: dict = {}

    def add(self, key: str, caption: str, mono: bool = True) -> None:
        r = self.grid.rowCount()
        self.grid.addWidget(label(caption, theme.ui(12), "ink3"), r, 0, Qt.AlignLeft | Qt.AlignTop)
        val = ElidedLabel("-", theme.mono(12) if mono else theme.ui(12))
        self.grid.addWidget(val, r, 1)
        self._values[key] = val

    def set(self, key: str, text: str) -> None:
        self._values[key].setText(text)


def section_label(text: str) -> QLabel:
    return label(upper(text), theme.label_font(11), "label")
