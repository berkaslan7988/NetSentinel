"""Models: the three detectors, their CIC-IDS2017 scores, and the scoring rules."""
from __future__ import annotations

import json
from typing import Optional

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget,
)

import config
from ui import theme
from ui.i18n import num, pct, t
from ui.views.common import section_label
from ui.widgets import hrule, label, pal, small_label

# Measured by training/evaluate.py on CIC-IDS2017 (~2.36M flows, 30 % test split).
METRICS = {
    "rf": {"f1": 0.9968, "precision": 0.9950, "recall": 0.9987, "auc": 1.0000, "fpr": 0.0011},
    "ae": {"f1": 0.6027, "precision": 0.9081, "recall": 0.4510, "auc": None, "fpr": 0.0100},
    "if": {"f1": 0.5081, "precision": 0.8049, "recall": 0.3712, "auc": None, "fpr": 0.0198},
}
FILES = {"rf": "supervised_rf.pkl", "if": "isolation_forest.pkl", "ae": "autoencoder.pt"}


def _ae_meta() -> dict:
    try:
        return json.loads((config.MODELS_DIR / "ae_meta.json").read_text())
    except Exception:
        return {"threshold": 0.3043, "architecture": [78, 32, 8, 32, 78], "percentile": 99.0}


class StatusPill(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(22)
        self._text, self._on = "", False

    def set(self, text: str, on: bool) -> None:
        self._text, self._on = text, on
        fm = self.fontMetrics()
        self.setFixedWidth(fm.horizontalAdvance(text) + 30)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        r = QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        p.setPen(QColor(P.line2))
        p.setBrush(QColor(P.panel2))
        p.drawRoundedRect(r, 11, 11)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(P.ink2 if self._on else P.line2))
        p.drawEllipse(QRectF(10, 8, 6, 6))
        p.setPen(QColor(P.ink2 if self._on else P.ink3))
        p.setFont(theme.ui(11.5, 600))
        p.drawText(QRectF(22, 0, self.width() - 26, self.height()), Qt.AlignVCenter, self._text)
        p.end()


class ModelCard(QFrame):
    def __init__(self, key: str, name: str, role: str, desc: str, extras: list, parent=None) -> None:
        super().__init__(parent)
        self.key = key
        self.setObjectName("panel")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(0)
        head = QHBoxLayout()
        head.setSpacing(10)
        col = QVBoxLayout()
        col.setSpacing(2)
        col.addWidget(label(name, theme.ui(15, 600)))
        col.addWidget(label(role, theme.ui(12), "ink3"))
        head.addLayout(col, 1)
        self.pill = StatusPill()
        self.pill.setFont(theme.ui(11.5, 600))
        head.addWidget(self.pill, 0, Qt.AlignTop)
        lay.addLayout(head)
        lay.addSpacing(16)

        m = METRICS[key]
        lay.addWidget(small_label(t("F1 on CIC-IDS2017")))
        lay.addSpacing(6)
        lay.addWidget(label(num(m["f1"], 4), theme.mono(30, 500)))
        lay.addSpacing(14)
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(4)
        for i, (cap, val) in enumerate(((t("Precision"), m["precision"]), (t("Recall"), m["recall"]),
                                        ("ROC-AUC", m["auc"]), (t("False positives"), m["fpr"]))):
            grid.addWidget(small_label(cap), 0, i)
            text = "-" if val is None else (pct(val * 100, 2) if cap == t("False positives") else num(val, 4))
            grid.addWidget(label(text, theme.mono(13, 500)), 1, i)
        lay.addLayout(grid)
        lay.addSpacing(14)
        lay.addWidget(hrule())
        lay.addSpacing(12)
        d = QLabel(desc)
        d.setWordWrap(True)
        d.setFont(theme.ui(12.5))
        d.setObjectName("ink2")
        lay.addWidget(d)
        lay.addSpacing(10)
        for cap, val in extras:
            row = QHBoxLayout()
            row.addWidget(label(cap, theme.ui(12), "ink3"))
            row.addStretch(1)
            row.addWidget(label(val, theme.mono(12)))
            lay.addLayout(row)
            lay.addSpacing(4)
        lay.addStretch(1)

    def set_status(self, text: str, on: bool) -> None:
        self.pill.set(text, on)


class ScoreScale(QWidget):
    """0-100 risk axis with the severity bands."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(46)

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        th = config.SEVERITY_THRESHOLDS
        bands = [("low", 0, th["MEDIUM"]), ("med", th["MEDIUM"], th["HIGH"]),
                 ("high", th["HIGH"], th["CRITICAL"]), ("crit", th["CRITICAL"], 100)]
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w = self.width()
        for key, lo, hi in bands:
            x0, x1 = w * lo / 100, w * hi / 100
            col = QColor(P.line2) if key == "low" else theme.sev_color(key, P)
            p.setPen(Qt.NoPen)
            p.setBrush(col)
            p.drawRoundedRect(QRectF(x0 + (1 if lo else 0), 4, x1 - x0 - (2 if lo else 1), 8), 2, 2)
        p.setFont(theme.mono(10.5))
        for v in (0, th["MEDIUM"], th["HIGH"], th["CRITICAL"], 100):
            x = w * v / 100
            align = Qt.AlignLeft if v == 0 else (Qt.AlignRight if v == 100 else Qt.AlignHCenter)
            rx = x if v == 0 else (x - 40 if v == 100 else x - 20)
            p.setPen(QColor(P.ink3))
            p.drawText(QRectF(rx, 18, 40, 14), align | Qt.AlignVCenter, str(v))
        p.setFont(theme.ui(11.5))
        for key, lo, hi in bands:
            name = {"low": t("no alert"), "med": t("medium"), "high": t("high"), "crit": t("critical")}[key]
            p.setPen(theme.sev_ink(key, P))
            p.drawText(QRectF(w * lo / 100, 31, w * (hi - lo) / 100, 15), Qt.AlignHCenter | Qt.AlignVCenter, name)
        p.end()


class Examples(QWidget):
    """Three flows through the scorer, from the RiskScorer docstring."""

    ROW = 28
    CASES = [  # RF probability, IF flag, AE flag
        (0.05, False, True),
        (0.05, True, True),
        (0.95, True, True),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        from alerts.scoring import RiskScorer
        self.scorer = RiskScorer()
        self.setFixedHeight(self.ROW * len(self.CASES))

    def paintEvent(self, _e) -> None:  # noqa: N802
        from detection.result import DetectionResult
        from ui.widgets import paint_chip
        P = pal()
        p = QPainter(self)
        w = self.width()
        for i, (proba, iso, ae) in enumerate(self.CASES):
            res = DetectionResult(src_ip="", dst_ip="", src_port=0, dst_port=0, protocol="", timestamp=0,
                                  supervised_proba=proba, iso_anomaly=iso, ae_anomaly=ae)
            risk = self.scorer.score(res)
            sev = theme.sev_for_risk(risk)
            y = i * self.ROW
            p.fillRect(QRectF(0, y + self.ROW - 1, w, 1), QColor(P.line))
            flags = " + ".join(n for n, f in (("IF", iso), ("AE", ae)) if f)
            p.setFont(theme.ui(12.5))
            p.setPen(QColor(P.ink2))
            p.drawText(QRectF(0, y, w * 0.42, self.ROW), Qt.AlignVCenter,
                       t("RF {p}, {flags} flag", p=num(proba, 2), flags=flags))
            agree = self.scorer.unsup_signal(res)
            p.setFont(theme.mono(12))
            p.setPen(QColor(P.ink3))
            p.drawText(QRectF(w * 0.42, y, w * 0.58 - 150, self.ROW), Qt.AlignVCenter | Qt.AlignRight,
                       f"{self.scorer.w_sup * 100:.0f} × {num(proba, 2)} + "
                       f"{self.scorer.w_unsup * 100:.0f} × {num(agree, 1)}")
            p.setPen(theme.sev_ink(sev, P))
            p.setFont(theme.mono(12, 600))
            p.drawText(QRectF(w - 140, y, 46, self.ROW), Qt.AlignVCenter | Qt.AlignRight, num(risk, 1))
            if sev == "low":
                p.setFont(theme.ui(12))
                p.setPen(QColor(P.ink3))
                p.drawText(QRectF(w - 80, y, 80, self.ROW), Qt.AlignVCenter | Qt.AlignRight, t("no alert"))
            else:
                paint_chip(p, w - 80 + (80 - 52), y + self.ROW / 2, sev, 52)
        p.end()


class ModelsView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("page")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("transparent")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        inner = QWidget()
        inner.setObjectName("transparent")
        root = QVBoxLayout(inner)
        root.setContentsMargins(16, 14, 16, 16)
        root.setSpacing(12)
        scroll.setWidget(inner)
        outer.addWidget(scroll)

        meta = _ae_meta()
        arch = "-".join(str(x) for x in meta.get("architecture", [78, 32, 8, 32, 78]))
        w_sup = int(config.RISK_WEIGHT_SUPERVISED * 100)
        w_uns = int(config.RISK_WEIGHT_UNSUPERVISED * 100)
        row = QHBoxLayout()
        row.setSpacing(12)
        self.cards = {
            "rf": ModelCard("rf", "RandomForest", t("Supervised, known attacks"),
                            t("Learns the labelled attacks in CIC-IDS2017. Its attack probability carries "
                              "{w} of the risk score.", w=pct(w_sup, 0)),
                            [(t("Weight in risk"), num(config.RISK_WEIGHT_SUPERVISED, 2)),
                             (t("File"), "models/" + FILES["rf"])]),
            "if": ModelCard("if", "IsolationForest", t("Unsupervised, outliers"),
                            t("Trained on benign traffic only. Flags flows that are easy to isolate, "
                              "which catches traffic unlike anything seen in training."),
                            [(t("Trained on"), t("benign flows")), (t("File"), "models/" + FILES["if"])]),
            "ae": ModelCard("ae", "Autoencoder", t("Unsupervised, reconstruction"),
                            t("A PyTorch network that rebuilds benign flows. A reconstruction error above "
                              "the {p}th percentile of benign traffic is anomalous.",
                              p=int(meta.get("percentile", 99))),
                            [(t("Architecture"), arch),
                             (t("Error threshold"), num(float(meta.get("threshold", 0.3043)), 4)),
                             (t("File"), "models/" + FILES["ae"])]),
        }
        for key in ("rf", "if", "ae"):
            row.addWidget(self.cards[key], 1)
        root.addLayout(row)

        row2 = QHBoxLayout()
        row2.setSpacing(12)
        score = QFrame()
        score.setObjectName("panel")
        sl = QVBoxLayout(score)
        sl.setContentsMargins(18, 16, 18, 18)
        sl.setSpacing(0)
        sl.addWidget(label(t("How risk is scored"), theme.ui(15, 600)))
        sl.addSpacing(10)
        formula = QLabel(t("risk = {a} × RF attack probability + {b} × IF/AE agreement", a=w_sup, b=w_uns))
        formula.setFont(theme.mono(13, 500))
        sl.addWidget(formula)
        sl.addSpacing(6)
        sl.addWidget(label(t("Agreement is {both} when both unsupervised models flag the flow, {one} when "
                             "one does, 0 when neither does. A lone autoencoder flag cannot raise an alert.",
                             both=num(config.RISK_UNSUP_BOTH, 1), one=num(config.RISK_UNSUP_ONE, 1)),
                           theme.ui(12.5), "ink2"))
        sl.itemAt(sl.count() - 1).widget().setWordWrap(True)
        sl.addSpacing(16)
        sl.addWidget(ScoreScale())
        sl.addSpacing(16)
        sl.addWidget(section_label(t("Worked examples")))
        sl.addSpacing(6)
        sl.addWidget(Examples())
        sl.addSpacing(14)
        rules = QLabel(t("An alert opens at risk {m}. Threat flows from one source within {w} s are merged "
                         "into one alert, and its volume raises the floor: 10 flows medium, 30 high, "
                         "100 critical.", m=config.ALERT_MIN_RISK, w=config.ALERT_WINDOW_SECONDS))
        rules.setWordWrap(True)
        rules.setFont(theme.ui(12.5))
        rules.setObjectName("ink2")
        sl.addWidget(rules)
        sl.addStretch(1)
        row2.addWidget(score, 3)

        perf = QFrame()
        perf.setObjectName("panel")
        pl = QVBoxLayout(perf)
        pl.setContentsMargins(18, 16, 18, 18)
        pl.setSpacing(0)
        pl.addWidget(label(t("Pipeline"), theme.ui(15, 600)))
        pl.addSpacing(12)
        facts = QGridLayout()
        facts.setHorizontalSpacing(18)
        facts.setVerticalSpacing(10)
        items = [
            (t("Features per flow"), "78", t("CICFlowMeter order")),
            (t("Inference, benchmark"), num(9.3, 1) + " ms", t("p95 about 10 ms")),
            (t("Sustained rate"), t("{n} flows/s", n="108"), "RF + IF"),
            (t("Training data"), num(2.36, 2) + " M", t("CIC-IDS2017 flows")),
        ]
        for i, (cap, val, sub) in enumerate(items):
            facts.addWidget(small_label(cap), (i // 2) * 3, i % 2)
            facts.addWidget(label(val, theme.mono(20, 500)), (i // 2) * 3 + 1, i % 2)
            facts.addWidget(label(sub, theme.ui(12), "ink3"), (i // 2) * 3 + 2, i % 2)
        pl.addLayout(facts)
        pl.addSpacing(14)
        self.live = label("", theme.ui(12.5), "ink2")
        self.live.setWordWrap(True)
        pl.addWidget(self.live)
        pl.addStretch(1)
        row2.addWidget(perf, 2)
        root.addLayout(row2)
        root.addStretch(1)

    def refresh(self, kind: Optional[str], detect_ms: Optional[float], loaded: dict) -> None:
        for key, card in self.cards.items():
            if kind == "demo":
                card.set_status(t("Simulated in demo"), False)
            elif loaded.get(key):
                card.set_status(t("Loaded"), True)
            elif (config.MODELS_DIR / FILES[key]).exists():
                card.set_status(t("On disk"), True)
            else:
                card.set_status(t("Not trained"), False)
        if kind == "live" and detect_ms is not None:
            self.live.setText(t("This session: {ms} ms per flow, measured live.", ms=num(detect_ms, 1)))
        elif kind == "demo":
            self.live.setText(t("Demo mode draws model outputs from these measured rates instead of "
                                "running the models, so it needs no trained files."))
        else:
            self.live.setText(t("Train the models with the scripts in training/ to run live detection."))
