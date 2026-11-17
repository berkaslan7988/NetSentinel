"""NetSentinel - dashboard main window.

Architecture rule: the UI thread never does heavy work. The pipeline
(capture / inference / alerting, or the demo generator) runs on background
threads and fills thread-safe queues. A QTimer drains them every 250 ms into
the Session, then refreshes the visible view; a worker never touches a widget.
"""
from __future__ import annotations

import os
import queue
import time
from typing import Optional

from PySide6.QtCore import QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFontMetricsF, QKeySequence, QPainter, QShortcut
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QComboBox, QFileDialog, QHBoxLayout, QMainWindow, QPushButton,
    QStackedWidget, QVBoxLayout, QWidget,
)

import config
from ui import icons, prefs, theme
from ui.brand import app_icon
from ui.i18n import language, num, set_language, t, upper
from ui.session import Session
from ui.views.alerts import AlertsView
from ui.views.common import alert_sev
from ui.views.flows import FlowsView
from ui.views.models import FILES, ModelsView
from ui.views.overview import OverviewView
from ui.views.sources import SourcesView
from ui.widgets import ElidedLabel, IconButton, Mark, SearchBox, Segmented, TabButton, label, pal

UI_REFRESH_MS = 250
MAX_DRAIN = 50000          # the demo's warm start delivers ~14k flows at once

VIEWS = ("overview", "alerts", "flows", "sources", "models")


class Notice(Exception):
    """A start-up problem whose message is already written for the user."""


def models_present() -> bool:
    return (config.MODELS_DIR / "scaler.pkl").exists() and any(
        (config.MODELS_DIR / FILES[k]).exists() for k in ("rf", "if"))


class PipelineStrip(QWidget):
    """Footer: the pipeline stages with live numbers, separated by chevrons."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(28)
        self._stages: list = []

    def set_stages(self, stages) -> None:
        self._stages = list(stages)
        f_l, f_v = theme.ui(11.5), theme.mono(11.5)
        w = QFontMetricsF(theme.label_font(10.5)).horizontalAdvance(upper(t("Pipeline"))) + 14
        for name, value in self._stages:
            w += QFontMetricsF(f_l).horizontalAdvance(name) + 5 + QFontMetricsF(f_v).horizontalAdvance(value) + 24
        self.setFixedWidth(int(w))
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        h = self.height()
        p.setFont(theme.label_font(10.5))
        p.setPen(QColor(P.ink3))
        fm = QFontMetricsF(p.font())
        x = 0.0
        cap = upper(t("Pipeline"))
        p.drawText(QRectF(x, 0, fm.horizontalAdvance(cap) + 2, h), Qt.AlignVCenter, cap)
        x += fm.horizontalAdvance(cap) + 14
        f_l, f_v = theme.ui(11.5), theme.mono(11.5)
        for i, (name, value) in enumerate(self._stages):
            if i:
                icons.paint(p, "chevron-right", P.ink3, QRectF(x - 17, h / 2 - 5, 10, 10), 2.2)
            p.setFont(f_l)
            p.setPen(QColor(P.ink3))
            wl = QFontMetricsF(f_l).horizontalAdvance(name)
            p.drawText(QRectF(x, 0, wl + 2, h), Qt.AlignVCenter, name)
            x += wl + 5
            p.setFont(f_v)
            p.setPen(QColor(P.ink2))
            wv = QFontMetricsF(f_v).horizontalAdvance(value)
            p.drawText(QRectF(x, 0, wv + 2, h), Qt.AlignVCenter, value)
            x += wv + 24
        p.end()


class MainWindow(QMainWindow):
    def __init__(self, autostart_demo: bool = False, theme_name: Optional[str] = None,
                 lang: Optional[str] = None) -> None:
        super().__init__()
        self.prefs = prefs.load()
        self.theme_name = theme_name or self.prefs.get("theme") or self._system_theme()
        set_language(lang or self.prefs.get("lang") or language())
        self.setWindowTitle("NetSentinel")
        self.setWindowIcon(app_icon())
        self.resize(1440, 900)
        self.setMinimumSize(1180, 760)

        self.session = Session()
        self.pipeline = None
        self.engine = None
        self.source = "demo" if (autostart_demo or not models_present()) else "live"
        self.mode = "hybrid"
        self.view = "overview"
        self._replay_csv: Optional[str] = None
        self._notice_text = ""
        self._notice_error = False
        self._pkt_prev = (0, time.time(), 0.0)

        self._apply_palette()
        self._build()
        for i, key in enumerate(VIEWS):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self, activated=lambda k=key: self.show_view(k))

        self.timer = QTimer(self)
        self.timer.setInterval(UI_REFRESH_MS)
        self.timer.timeout.connect(self._tick)
        self.timer.start()
        if autostart_demo:
            self.source = "demo"
            self._sync_controls()
            self.start()
        else:
            self._tick()

    # ----------------------------------------------------------------- #
    @staticmethod
    def _system_theme() -> str:
        try:
            scheme = QApplication.styleHints().colorScheme()
            return "light" if scheme == Qt.ColorScheme.Light else "dark"
        except Exception:
            return "dark"

    def _apply_palette(self) -> None:
        pal_ = theme.by_name(self.theme_name)
        theme.set_current(pal_)
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.stylesheet(pal_))

    def _build(self) -> None:
        old = self.centralWidget()
        root = QWidget()
        root.setObjectName("root")
        lay = QVBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self._build_topbar())
        self.stack = QStackedWidget()
        self.overview = OverviewView()
        self.alerts = AlertsView()
        self.flows = FlowsView()
        self.sources = SourcesView()
        self.models = ModelsView()
        self.pages = {"overview": self.overview, "alerts": self.alerts, "flows": self.flows,
                      "sources": self.sources, "models": self.models}
        for key in VIEWS:
            self.stack.addWidget(self.pages[key])
        lay.addWidget(self.stack, 1)
        lay.addWidget(self._build_footer())
        self.setCentralWidget(root)
        if old is not None:
            old.deleteLater()

        self.overview.alertClicked.connect(self._open_alert)
        self.overview.sourceClicked.connect(self._open_source)
        self.overview.flowClicked.connect(self._open_flow)
        self.sources.sourceClicked.connect(self._open_source)
        self._sync_controls()
        self.show_view(self.view)

    def _build_topbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("topbar")
        bar.setAttribute(Qt.WA_StyledBackground, True)
        bar.setFixedHeight(53)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(16, 0, 16, 1)
        lay.setSpacing(0)
        lay.addWidget(Mark(24))
        lay.addSpacing(10)
        word = label("NetSentinel", theme.font(theme.UI, 15, 600, spacing=-0.15))
        lay.addWidget(word)
        lay.addSpacing(18)

        self.tabs = {}
        group = QButtonGroup(self)
        group.setExclusive(True)
        for key, text in (("overview", t("Overview")), ("alerts", t("Alerts")), ("flows", t("Flows")),
                          ("sources", t("Sources")), ("models", t("Models"))):
            b = TabButton(text)
            b.clicked.connect(lambda _=False, k=key: self.show_view(k))
            group.addButton(b)
            self.tabs[key] = b
            lay.addWidget(b, 0, Qt.AlignBottom)
            lay.addSpacing(2)
        lay.addStretch(1)

        lay.addWidget(label(t("Source"), theme.ui(12.5), "ink3"))
        lay.addSpacing(8)
        self.source_combo = QComboBox()
        self.source_combo.setCursor(Qt.PointingHandCursor)
        self._sources = [("demo", t("Demo")), ("live", t("Live capture")), ("csv", t("Replay CSV")),
                         ("db", t("Replay database"))]
        for key, text in self._sources:
            self.source_combo.addItem(text, key)
        self.source_combo.setMinimumWidth(150)
        self.source_combo.setAccessibleName(t("Source"))
        self.source_combo.activated.connect(self._source_picked)
        lay.addWidget(self.source_combo)
        lay.addSpacing(10)
        self.mode_seg = Segmented([("hybrid", t("Hybrid")), ("supervised", t("Supervised")),
                                   ("unsupervised", t("Unsupervised"))], self.mode)
        self.mode_seg.changed.connect(self._mode_picked)
        lay.addWidget(self.mode_seg)
        lay.addSpacing(14)
        self.clock_icon = label("")
        lay.addWidget(self.clock_icon)
        lay.addSpacing(7)
        self.clock = label("00:00:00", theme.mono(12.5), "ink2")
        self.clock.setMinimumWidth(64)
        lay.addWidget(self.clock)
        lay.addSpacing(10)
        self.start_btn = QPushButton()
        self.start_btn.setObjectName("primary")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setIconSize(QSize(12, 12))
        self.start_btn.setFont(theme.ui(12.5, 600))
        self.start_btn.setMinimumWidth(84)
        self.start_btn.clicked.connect(self.toggle)
        lay.addWidget(self.start_btn)
        lay.addSpacing(8)
        self.theme_btn = IconButton("contrast", t("Switch theme"))
        self.theme_btn.clicked.connect(self.toggle_theme)
        lay.addWidget(self.theme_btn)
        lay.addSpacing(6)
        self.lang_btn = QPushButton(language().upper())
        self.lang_btn.setObjectName("textButton")
        self.lang_btn.setCursor(Qt.PointingHandCursor)
        self.lang_btn.setFixedHeight(30)
        self.lang_btn.setToolTip(t("Language: English / Türkçe"))
        self.lang_btn.setAccessibleName(t("Language: English / Türkçe"))
        self.lang_btn.clicked.connect(self.toggle_language)
        lay.addWidget(self.lang_btn)
        return bar

    def _build_footer(self) -> QWidget:
        foot = QWidget()
        foot.setObjectName("footer")
        foot.setAttribute(Qt.WA_StyledBackground, True)
        foot.setFixedHeight(30)
        lay = QHBoxLayout(foot)
        lay.setContentsMargins(16, 1, 16, 0)
        lay.setSpacing(16)
        self.strip = PipelineStrip()
        lay.addWidget(self.strip)
        self.notice = ElidedLabel("", theme.ui(11.5), "ink3")
        self.notice.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        lay.addWidget(self.notice, 1)
        lay.addWidget(label(f"v{config.APP_VERSION}", theme.mono(11.5), "ink3"))
        return foot

    # ----------------------------------------------------------------- #
    def show_view(self, key: str) -> None:
        self.view = key
        self.stack.setCurrentWidget(self.pages[key])
        self.tabs[key].setChecked(True)
        self._refresh_view(time.time())

    def _open_alert(self, alert_id: str) -> None:
        self.alerts.focus_alert(alert_id)
        self.show_view("alerts")

    def _open_source(self, ip: str) -> None:
        self.alerts._session = self.session
        self.alerts.focus_source(ip)
        self.show_view("alerts")

    def _open_flow(self, sf) -> None:
        self.flows.focus_flow(sf)
        self.show_view("flows")

    # controls -----------------------------------------------------------------
    def _sync_controls(self) -> None:
        running = self.pipeline is not None
        idx = next(i for i, (k, _) in enumerate(self._sources) if k == self.source)
        self.source_combo.setCurrentIndex(idx)
        self.source_combo.setEnabled(not running)
        self.mode_seg.set_current(self.mode)
        self.mode_seg.setEnabled(not running)
        P = pal()
        self.start_btn.setText(t("Stop") if running else t("Start"))
        self.start_btn.setIcon(icons.icon("stop" if running else "play", P.on_btn, 12))
        self.clock_icon.setPixmap(icons.pixmap("bars", P.ink2 if running else P.ink3, 14, 1.8))
        self.lang_btn.setText(language().upper())
        self._update_notice()

    def _source_picked(self, index: int) -> None:
        key = self.source_combo.itemData(index)
        if key == "csv":
            path, _ = QFileDialog.getOpenFileName(
                self, t("Pick a CIC-IDS2017 CSV"), str(config.CIC_DATA_DIR), "CSV (*.csv)")
            if not path:
                self._sync_controls()
                return
            self._replay_csv = path
        self.source = key
        self._notice_text = ""
        self._sync_controls()

    def _mode_picked(self, key: str) -> None:
        self.mode = key

    def _notice(self, text: str, error: bool = False) -> None:
        self._notice_text, self._notice_error = text, error
        self._update_notice()

    def _update_notice(self) -> None:
        P = pal()
        if self._notice_text:
            text, err = self._notice_text, self._notice_error
        elif self.source == "demo":
            text, err = t("Demo mode: synthetic traffic scored by the real risk and alert engine. "
                          "No models, capture driver or admin rights needed."), False
        elif self.source == "live":
            text, err = (t("Live capture: run as administrator, on your own network only.")
                         if models_present() else
                         t("Live capture needs trained models in models/. Train them, or use Demo.")), False
        elif self.source == "csv":
            name = os.path.basename(self._replay_csv) if self._replay_csv else t("no file picked")
            text, err = t("Replay CSV: {name}", name=name), False
        else:
            text, err = t("Replay database: {path}", path=config.DB_PATH.name), False
        self.notice.setText(text)
        self.notice.setStyleSheet(f"color: {P.crit_ink if err else P.ink3};")

    def toggle(self) -> None:
        if self.pipeline is None:
            self.start()
        else:
            self.stop()

    def start(self) -> None:
        if self.pipeline is not None:
            return
        self._notice_text = ""
        try:
            pipe = self._make_pipeline()
        except Exception as exc:  # missing models, Npcap, a bad CSV ...
            self._notice(self._explain(exc), error=True)
            return
        if pipe is None:
            return
        self.session.reset()
        try:
            pipe.start()
        except Exception as exc:
            self._notice(self._explain(exc), error=True)
            return
        self.pipeline = pipe
        self._pkt_prev = (0, time.time(), 0.0)
        self._sync_controls()
        self._tick()

    def _make_pipeline(self):
        from ui.demo import DemoPipeline
        from ui.pipeline import LivePipeline, ReplayPipeline, csv_result_source, db_result_source

        self.engine = None
        if self.source == "demo":
            return DemoPipeline(mode=self.mode)
        if self.source == "live":
            pipe = LivePipeline(mode=self.mode)
            self.engine = pipe.engine
            return pipe
        if self.source == "csv":
            if not self._replay_csv:
                self._source_picked(self.source_combo.currentIndex())
                if not self._replay_csv:
                    return None
            from detection.engine import DetectionEngine
            self.engine = DetectionEngine(mode=self.mode)
            return ReplayPipeline(csv_result_source(self.engine, self._replay_csv, limit=5000), rate_hz=30)
        if not config.DB_PATH.exists():
            raise Notice(t("No recorded session yet. Run main.py --detect --save first ({path}).",
                           path=config.DB_PATH.name))
        from storage.database import Database
        return ReplayPipeline(db_result_source(Database(config.DB_PATH)), rate_hz=30)

    @staticmethod
    def _explain(exc: Exception) -> str:
        text = str(exc).strip() or exc.__class__.__name__
        if isinstance(exc, Notice):
            return text
        if "scaler not found" in text or "No model could be loaded" in text:
            return t("No trained models in models/. Train them (see README), or switch the source to Demo.")
        return t("Could not start: {err}", err=text.splitlines()[0][:160])

    def stop(self) -> None:
        if self.pipeline is not None:
            try:
                self.pipeline.stop()
            finally:
                self._tick()
                self.pipeline = None
        self._sync_controls()

    # theme / language -----------------------------------------------------------
    def toggle_theme(self) -> None:
        self.set_theme("light" if self.theme_name == "dark" else "dark")

    def set_theme(self, name: str) -> None:
        self.theme_name = name
        self.prefs["theme"] = name
        prefs.save(self.prefs)
        self._apply_palette()
        for w in self.findChildren(IconButton):
            w.refresh()
        for w in self.findChildren(SearchBox):
            w.refresh()
        self._sync_controls()
        self._refresh_view(time.time())
        self.update()

    def toggle_language(self) -> None:
        self.set_language("tr" if language() == "en" else "en")

    def set_language(self, lang: str) -> None:
        set_language(lang)
        self.prefs["lang"] = language()
        prefs.save(self.prefs)
        self._build()
        self._tick()

    # the UI tick ------------------------------------------------------------------
    def _tick(self) -> None:
        now = time.time()
        pipe = self.pipeline
        if pipe is not None:
            drained = 0
            while drained < MAX_DRAIN:
                try:
                    res = pipe.results_q.get_nowait()
                except queue.Empty:
                    break
                self.session.add_result(res)
                drained += 1
            while True:
                try:
                    self.session.add_alert(pipe.alerts_q.get_nowait())
                except queue.Empty:
                    break
        self._refresh_chrome(now)
        self._refresh_view(now)

    def _refresh_chrome(self, now: float) -> None:
        s = self.session
        running = self.pipeline is not None
        if running and s.started_at:
            el = max(0, int(now - s.started_at))
            self.clock.setText(f"{el // 3600:02d}:{el % 3600 // 60:02d}:{el % 60:02d}")
        elif not running:
            self.clock.setText("00:00:00" if not s.total_flows else self.clock.text())
        open_alerts = s.open_alerts(now)
        top = None
        for a in open_alerts:
            k = alert_sev(a)
            if top is None or theme.sev_rank(k) > theme.sev_rank(top):
                top = k
        self.tabs["alerts"].set_badge(len(open_alerts), top)

        kind = getattr(self.pipeline, "kind", None)
        if kind == "demo":
            src = t("synthetic")
        elif kind == "live":
            pkts = getattr(self.pipeline, "packets", 0)
            prev_n, prev_t, rate = self._pkt_prev
            if now - prev_t >= 1.0:
                rate = (pkts - prev_n) / (now - prev_t)
                self._pkt_prev = (pkts, now, rate)
            src = t("{n} pkt/s", n=num(rate))
        elif kind == "replay":
            src = "CSV" if self.source == "csv" else "SQLite"
        else:
            src = t("idle")
        detect = "-"
        if kind == "demo":
            detect = t("simulated")
        elif kind == "live":
            ms = self.pipeline.detect_ms()
            detect = f"{num(ms, 1)} ms" if ms is not None else "-"
        self.strip.set_stages([
            (t("Source"), src),
            (t("Flows"), f"{num(s.flow_rate(now), 1)}/s"),
            (t("Features"), "78"),
            (t("Detect"), detect),
            (t("Alerts"), t("{n} open", n=len(open_alerts))),
        ])

    def _refresh_view(self, now: float) -> None:
        if not hasattr(self, "pages"):
            return
        page = self.pages[self.view]
        if page is self.models:
            kind = getattr(self.pipeline, "kind", None)
            ms = self.pipeline.detect_ms() if kind == "live" else None
            loaded = {}
            if self.engine is not None:
                loaded = {"rf": self.engine.supervised is not None, "if": self.engine.iso is not None,
                          "ae": self.engine.ae is not None}
            page.refresh(kind, ms, loaded)
        else:
            page.refresh(self.session, now)

    def closeEvent(self, event) -> None:  # noqa: N802
        self.timer.stop()
        if self.pipeline is not None:
            self.pipeline.stop()
            self.pipeline = None
        super().closeEvent(event)
