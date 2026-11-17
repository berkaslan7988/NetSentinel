"""NetSentinel - the flow timeline (the dashboard's hero) and small activity bars.

One bar per 5 s bucket over the last 10 minutes: benign flows in graphite at
the bottom, threat flows stacked on top in their severity colors. Alert onsets
get a dashed marker with the source IP. Hover a bar for its numbers.
"""
from __future__ import annotations

import math
import time
from typing import List, Optional, Sequence, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFontMetricsF, QPainter, QPen
from PySide6.QtWidgets import QToolTip, QWidget

from ui import theme
from ui.i18n import num, t
from ui.session import BUCKET_SECONDS, Bucket
from ui.widgets import chip_width, paint_chip, paint_empty, pal

AXIS_W = 34.0
LANE_H = 26.0
XLAB_H = 20.0


def nice_max(v: float) -> float:
    """Round an axis maximum up to 4 x a 1/2/2.5/5 step."""
    if v <= 0:
        return 40.0
    raw = v / 4.0
    mag = 10 ** math.floor(math.log10(raw))
    for m in (1, 2, 2.5, 5, 10):
        if raw <= m * mag:
            return 4 * m * mag
    return 4 * 10 * mag


class FlowTimeline(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(150)
        self.setMouseTracking(True)
        self._buckets: List[Bucket] = []
        self._markers: List[Tuple[float, str, str]] = []
        self._now = time.time()
        self._hover = -1
        self.empty_hint = ""

    def set_data(self, buckets: List[Bucket], markers: Sequence[Tuple[float, str, str]],
                 now: float) -> None:
        self._buckets = buckets
        self._markers = list(markers)
        self._now = now
        self.update()

    # geometry ---------------------------------------------------------------
    def _plot(self) -> QRectF:
        return QRectF(AXIS_W + 10, LANE_H, self.width() - AXIS_W - 10 - 2,
                      self.height() - LANE_H - XLAB_H)

    def _slot(self, i: int, plot: QRectF) -> Tuple[float, float]:
        n = max(1, len(self._buckets))
        step = plot.width() / n
        gap = 2.0 if step >= 6 else (1.0 if step >= 3 else 0.0)
        return plot.x() + i * step, max(1.0, step - gap)

    def _x_for_time(self, ts: float, plot: QRectF) -> Optional[float]:
        if not self._buckets:
            return None
        start = self._buckets[0].start
        span = len(self._buckets) * BUCKET_SECONDS
        frac = (ts - start) / span
        if frac < 0 or frac > 1:
            return None
        return plot.x() + frac * plot.width()

    # painting ---------------------------------------------------------------
    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, False)
        plot = self._plot()
        top = max((b.total for b in self._buckets), default=0)
        ymax = nice_max(top)

        # grid + y labels
        p.setFont(theme.mono(10))
        grid_pen = QPen(QColor(P.grid), 1, Qt.DashLine)
        for k in range(5):
            y = plot.bottom() - plot.height() * k / 4
            if k:
                p.setPen(grid_pen)
                p.drawLine(QPointF(plot.x(), y), QPointF(plot.right(), y))
            p.setPen(QColor(P.ink3))
            p.drawText(QRectF(0, y - 8, AXIS_W, 16), Qt.AlignRight | Qt.AlignVCenter,
                       num(ymax * k / 4))
        p.setPen(QColor(P.line2))
        p.drawLine(QPointF(plot.x(), plot.bottom()), QPointF(plot.right(), plot.bottom()))

        if not top:
            paint_empty(p, plot, t("No flows yet"), self.empty_hint)
            self._x_labels(p, plot)
            p.end()
            return

        # hover column
        if 0 <= self._hover < len(self._buckets):
            x, w = self._slot(self._hover, plot)
            p.fillRect(QRectF(x - 1, plot.y(), w + 2, plot.height()), QColor(P.hover if not P.is_dark else P.panel2))

        # markers (lines first, under the bars)
        placed = self._place_markers(p, plot)
        dash = QPen(QColor(P.line2), 1, Qt.DashLine)
        p.setPen(dash)
        for x, _sev, _ip in placed:
            p.drawLine(QPointF(x, LANE_H - 4), QPointF(x, plot.bottom()))

        # bars
        scale = plot.height() / ymax
        colors = {"benign": QColor(P.benign), "med": QColor(P.med),
                  "high": QColor(P.high), "crit": QColor(P.crit)}
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(Qt.NoPen)
        for i, b in enumerate(self._buckets):
            if not b.total:
                continue
            x, w = self._slot(i, plot)
            y = plot.bottom()
            segs = [("benign", b.benign + b.low), ("med", b.med), ("high", b.high), ("crit", b.crit)]
            segs = [(k, n) for k, n in segs if n]
            for j, (key, n) in enumerate(segs):
                h = max(2.0 if key != "benign" else 1.0, n * scale)
                gap = 1.0 if j else 0.0
                rect = QRectF(x, y - h - gap, w, h)
                p.setBrush(colors[key])
                if j == len(segs) - 1 and w >= 3:
                    p.drawRoundedRect(rect.adjusted(0, 0, 0, 1.5), 1.5, 1.5)
                    p.fillRect(QRectF(rect.x(), rect.bottom() - 1.5, rect.width(), 1.5), colors[key])
                else:
                    p.drawRect(rect)
                y -= h + gap

        # marker labels in the lane
        for x, sev, ip in placed:
            cw = paint_chip(p, x, LANE_H / 2 - 3, sev)
            p.setFont(theme.mono(11))
            p.setPen(QColor(P.ink2))
            p.drawText(QRectF(x + cw + 6, 0, 140, LANE_H - 6), Qt.AlignVCenter | Qt.AlignLeft, ip)

        p.setRenderHint(QPainter.Antialiasing, False)
        self._x_labels(p, plot)
        p.end()

    def _place_markers(self, p: QPainter, plot: QRectF) -> List[Tuple[float, str, str]]:
        fm = QFontMetricsF(theme.mono(11))
        placed: List[Tuple[float, str, str]] = []
        order = {"crit": 0, "high": 1, "med": 2}
        # most severe first wins a contested spot, then left to right
        cands = []
        for ts, sev, ip in self._markers:
            x = self._x_for_time(ts, plot)
            if x is not None:
                cands.append((order.get(sev, 3), x, sev, ip))
        chosen: List[Tuple[float, float, str, str]] = []
        for _rank, x, sev, ip in sorted(cands):
            w = chip_width() + 6 + fm.horizontalAdvance(ip) + 14
            if x + w > plot.right() + 4:
                continue
            if any(not (x + w <= cx or x >= cx + cw) for cx, cw, _, _ in chosen):
                continue
            chosen.append((x, w, sev, ip))
        for x, _w, sev, ip in sorted(chosen):
            placed.append((x, sev, ip))
        return placed

    def _x_labels(self, p: QPainter, plot: QRectF) -> None:
        P = pal()
        if not self._buckets:
            return
        p.setFont(theme.mono(10))
        start = self._buckets[0].start
        span = len(self._buckets) * BUCKET_SECONDS
        steps = 5
        for k in range(steps + 1):
            ts = start + span * k / steps
            x = plot.x() + plot.width() * k / steps
            text = t("now") if k == steps else time.strftime("%H:%M:%S", time.localtime(ts))
            p.setPen(QColor(P.ink2 if k == steps else P.ink3))
            align = Qt.AlignLeft if k == 0 else (Qt.AlignRight if k == steps else Qt.AlignHCenter)
            w = 70.0
            rx = x if k == 0 else (x - w if k == steps else x - w / 2)
            p.drawText(QRectF(rx, plot.bottom() + 5, w, 14), align | Qt.AlignVCenter, text)

    # hover --------------------------------------------------------------------
    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        plot = self._plot()
        x = e.position().x()
        idx = -1
        if self._buckets and plot.x() <= x <= plot.right():
            idx = int((x - plot.x()) / (plot.width() / len(self._buckets)))
            idx = min(idx, len(self._buckets) - 1)
        if idx != self._hover:
            self._hover = idx
            self.update()
        if idx >= 0:
            b = self._buckets[idx]
            when = time.strftime("%H:%M:%S", time.localtime(b.start))
            lines = [when, t("{n} flows", n=num(b.total)), t("{n} benign", n=num(b.benign + b.low))]
            for key, name in (("crit", t("critical")), ("high", t("high")), ("med", t("medium"))):
                if getattr(b, key):
                    lines.append(f"{num(getattr(b, key))} {name}")
            QToolTip.showText(e.globalPosition().toPoint(), "\n".join(lines), self)
        else:
            QToolTip.hideText()

    def leaveEvent(self, e) -> None:  # noqa: N802
        self._hover = -1
        self.update()


class MiniBars(QWidget):
    """Compact per-bucket activity for one source (alert and source detail)."""

    def __init__(self, height: int = 44, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(height)
        self._values: List[int] = []
        self._sev = "med"

    def set_values(self, values: Sequence[int], sev: str) -> None:
        self._values = list(values)
        self._sev = sev
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        r = QRectF(0, 0, self.width(), self.height() - 1)
        p.fillRect(QRectF(0, r.bottom(), r.width(), 1), QColor(P.line2))
        vals = self._values
        if vals and max(vals) > 0:
            top = max(vals)
            n = len(vals)
            step = r.width() / n
            gap = 1.0 if step >= 3 else 0.0
            color = theme.sev_color(self._sev, P)
            for i, v in enumerate(vals):
                if v <= 0:
                    continue
                h = max(1.5, (r.height() - 2) * (v / top))
                p.fillRect(QRectF(i * step, r.bottom() - h, max(1.0, step - gap), h), color)
        p.end()
