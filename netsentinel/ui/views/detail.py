"""Detail-pane pieces: model signal bars and the risk-score breakdown."""
from __future__ import annotations

from typing import List, Optional, Tuple

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFontMetricsF, QPainter
from PySide6.QtWidgets import QWidget

import config
from alerts.engine import _severity_from_count
from alerts.scoring import RiskScorer
from ui import theme
from ui.demo import AE_THRESHOLD
from ui.i18n import num, t
from ui.session import ScoredFlow
from ui.widgets import paint_bar, paint_chip, pal


class SignalRows(QWidget):
    """One row per model: name, a bar, the raw output and its verdict."""

    ROW = 40

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(self.ROW * 3)
        self._sf: Optional[ScoredFlow] = None
        self.ae_threshold = AE_THRESHOLD

    def set_flow(self, sf: Optional[ScoredFlow]) -> None:
        self._sf = sf
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        sf = self._sf
        if sf is None:
            p.end()
            return
        r = sf.res
        rows: List[Tuple[str, Optional[float], Optional[float], str, Optional[bool]]] = []
        if r.supervised_proba is None:
            rows.append(("RandomForest", None, None, t("not loaded"), None))
        else:
            rows.append(("RandomForest", r.supervised_proba, None,
                         f"p = {num(r.supervised_proba, 2)}", r.supervised_label == "ATTACK"))
        if r.iso_score is None:
            rows.append(("IsolationForest", None, None, t("not loaded"), None))
        else:
            # decision_function: negative = anomalous; show as distance to the boundary
            frac = max(0.0, min(1.0, 0.5 - r.iso_score * 2.5))
            rows.append(("IsolationForest", frac, 0.5, f"{num(r.iso_score, 3)}", bool(r.iso_anomaly)))
        if r.ae_error is None:
            rows.append(("Autoencoder", None, None, t("not loaded"), None))
        else:
            frac = min(1.0, r.ae_error / (2 * self.ae_threshold))
            rows.append(("Autoencoder", frac, 0.5, f"{num(r.ae_error, 3)}", bool(r.ae_anomaly)))

        w = self.width()
        for i, (name, frac, tick, value, flagged) in enumerate(rows):
            y = i * self.ROW
            p.setFont(theme.ui(12, 600))
            p.setPen(QColor(P.ink))
            p.drawText(QRectF(0, y + 2, w, 16), Qt.AlignVCenter, name)
            state = t("not loaded") if flagged is None else (t("flagged") if flagged else t("normal"))
            p.setFont(theme.ui(12))
            p.setPen(QColor(P.crit_ink if flagged else P.ink3))
            p.drawText(QRectF(0, y + 2, w, 16), Qt.AlignVCenter | Qt.AlignRight, state)
            bar = QRectF(0, y + 20, w - 70, 14)
            if frac is None:
                paint_bar(p, bar, 0.0, QColor(P.line2))
            else:
                color = QColor(P.crit if flagged else P.ink3)
                paint_bar(p, bar, frac, color)
                if tick is not None:
                    x = bar.x() + bar.width() * tick
                    p.fillRect(QRectF(x - 0.5, bar.center().y() - 6, 1, 12), QColor(P.ink2))
            p.setFont(theme.mono(12))
            p.setPen(QColor(P.ink2))
            if frac is not None:
                p.drawText(QRectF(w - 64, y + 20, 64, 14), Qt.AlignVCenter | Qt.AlignRight, value)
        p.end()


class RiskBreakdown(QWidget):
    """How the 0-100 risk was built: 75 x RF + 25 x IF/AE agreement (+ volume floor)."""

    ROW = 24

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.scorer = RiskScorer()
        self._sf: Optional[ScoredFlow] = None
        self._volume: Optional[Tuple[int, str]] = None
        self._final: Optional[str] = None
        self.setFixedHeight(self.ROW * 4 + 10)

    def set_flow(self, sf: Optional[ScoredFlow], volume: Optional[Tuple[int, str]] = None,
                 final: Optional[str] = None) -> None:
        self._sf = sf
        self._volume = volume
        self._final = final
        self.setFixedHeight(self.ROW * (5 if volume else 4) + 10)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        sf = self._sf
        p = QPainter(self)
        if sf is None:
            p.end()
            return
        res = sf.res
        sc = self.scorer
        proba = res.supervised_proba if res.supervised_proba is not None else 0.0
        agree = sc.unsup_signal(res)
        n_flags = int(bool(res.iso_anomaly)) + int(bool(res.ae_anomaly))
        agree_text = {2: t("both agree"), 1: t("one model"), 0: t("neither")}[n_flags]
        rows = [
            (t("RandomForest"), f"{sc.w_sup * 100:.0f} × {num(proba, 2)}", sc.w_sup * proba * 100),
            (t("IF + AE, {state}", state=agree_text), f"{sc.w_unsup * 100:.0f} × {num(agree, 1)}",
             sc.w_unsup * agree * 100),
        ]
        w = self.width()
        mono = theme.mono(12)
        for i, (name, formula, value) in enumerate(rows):
            y = i * self.ROW
            p.setFont(theme.ui(12))
            p.setPen(QColor(P.ink2))
            p.drawText(QRectF(0, y, w * 0.5, self.ROW), Qt.AlignVCenter, name)
            p.setFont(mono)
            p.setPen(QColor(P.ink3))
            p.drawText(QRectF(w * 0.5, y, w * 0.5 - 56, self.ROW), Qt.AlignVCenter | Qt.AlignRight, formula)
            p.setPen(QColor(P.ink))
            p.drawText(QRectF(w - 50, y, 50, self.ROW), Qt.AlignVCenter | Qt.AlignRight, num(value, 1))
        y = 2 * self.ROW + 4
        p.fillRect(QRectF(0, y, w, 1), QColor(P.line))
        y += 5
        p.setFont(theme.ui(12, 600))
        p.setPen(QColor(P.ink))
        p.drawText(QRectF(0, y, w * 0.5, self.ROW), Qt.AlignVCenter, t("Risk score"))
        paint_chip(p, w - 50 - 10 - 52, y + self.ROW / 2, sf.sev, 52)
        p.setFont(theme.mono(13, 600))
        p.setPen(theme.sev_ink(sf.sev, P))
        p.drawText(QRectF(w - 50, y, 50, self.ROW), Qt.AlignVCenter | Qt.AlignRight, num(sf.risk, 1))
        y += self.ROW
        p.setFont(theme.ui(11.5))
        p.setPen(QColor(P.ink3))
        th = config.SEVERITY_THRESHOLDS
        p.drawText(QRectF(0, y, w, self.ROW), Qt.AlignVCenter,
                   t("Medium from {m}, high from {h}, critical from {c}",
                     m=th["MEDIUM"], h=th["HIGH"], c=th["CRITICAL"]))
        if self._volume:
            count, floor = self._volume
            y += self.ROW
            p.setFont(theme.ui(12))
            p.setPen(QColor(P.ink2))
            txt = t("Volume: {n} flows in the window", n=num(count))
            p.drawText(QRectF(0, y, w - 70, self.ROW), Qt.AlignVCenter, txt)
            if floor != "low":
                paint_chip(p, w - 52, y + self.ROW / 2, floor, 52)
            else:
                p.setPen(QColor(P.ink3))
                p.drawText(QRectF(w - 70, y, 70, self.ROW), Qt.AlignVCenter | Qt.AlignRight, t("no floor"))
        p.end()


def volume_floor(flow_count: int) -> str:
    """Severity floor the alert engine applies for this many flows."""
    return theme.sev_key(_severity_from_count(flow_count))
