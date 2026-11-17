"""Alerts: every grouped alert this session and why the selected one scored as it did."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

import config
from ui import theme
from ui.i18n import ago, duration, num, t
from ui.session import Session
from ui.tables import Col, DataTable, RowsModel
from ui.timeline import MiniBars
from ui.views.common import Facts, alert_kind, alert_sev, clock, flow_key, section_label
from ui.views.detail import RiskBreakdown, volume_floor
from ui.widgets import ChipWidget, Panel, Segmented, label


def _alert_cols():
    return [
        Col("sev", t("Severity"), "chip"),
        Col("src", t("Source"), "addr", stretch=1),
        Col("kind", t("Seen as"), "text", 168),
        Col("flows", t("Flows"), "mono", 76, align=Qt.AlignRight),
        Col("risk", t("Risk"), "risk", 118, align=Qt.AlignRight),
        Col("first", t("First seen"), "mono", 96),
        Col("last", t("Last seen"), "mono", 96),
        Col("status", t("Status"), "text", 82),
    ]


class AlertsView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("page")
        self._now = 0.0
        self._session: Optional[Session] = None
        root = QHBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)

        self.panel = Panel(t("Alerts"), "")
        self.filter = Segmented([("open", t("Open")), ("all", t("All"))], "all")
        self.panel.add_tool(self.filter)
        self.model = RowsModel(_alert_cols(), self._value, lambda a: a.alert_id)
        self.table = DataTable(self.model, t("No alerts"),
                               t("An alert opens when a flow scores 25 or more. Flows from the same "
                                 "source within {s} s are grouped into it.", s=config.ALERT_WINDOW_SECONDS))
        self.panel.body.addWidget(self.table)
        root.addWidget(self.panel, 1)

        self.detail = Panel(t("Alert detail"))
        self.detail.setFixedWidth(404)
        self.placeholder = QLabel(t("Select an alert to see its timeline and score breakdown."))
        self.placeholder.setObjectName("ink3")
        self.placeholder.setFont(theme.ui(12))
        self.placeholder.setWordWrap(True)
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setContentsMargins(28, 0, 28, 0)
        self.detail.body.addWidget(self.placeholder, 1)
        self.content = QWidget()
        self.content.setObjectName("transparent")
        lay = QVBoxLayout(self.content)
        lay.setContentsMargins(16, 14, 16, 16)
        lay.setSpacing(0)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.chip = ChipWidget()
        top.addWidget(self.chip, 0, Qt.AlignVCenter)
        self.ip = label("", theme.mono(18, 600))
        top.addWidget(self.ip, 0, Qt.AlignVCenter)
        top.addStretch(1)
        self.status = label("", theme.ui(12), "ink3")
        top.addWidget(self.status, 0, Qt.AlignVCenter)
        lay.addLayout(top)
        lay.addSpacing(12)
        risk_row = QHBoxLayout()
        risk_row.setSpacing(6)
        self.risk = label("0", theme.mono(28, 500))
        risk_row.addWidget(self.risk, 0, Qt.AlignBottom)
        risk_row.addWidget(label("/100", theme.ui(12), "ink3"), 0, Qt.AlignBottom)
        risk_row.addStretch(1)
        lay.addLayout(risk_row)
        lay.addSpacing(14)
        self.facts = Facts()
        self.facts.add("kind", t("Seen as"), mono=False)
        for key, cap in (("target", t("Target")), ("flows", t("Flows")),
                         ("span", t("Duration")), ("first", t("First seen")), ("last", t("Last seen")),
                         ("id", t("Alert ID"))):
            self.facts.add(key, cap)
        lay.addWidget(self.facts)
        lay.addSpacing(18)
        lay.addWidget(section_label(t("Activity from this source, last 10 min")))
        lay.addSpacing(8)
        self.activity = MiniBars(40)
        lay.addWidget(self.activity)
        lay.addSpacing(18)
        lay.addWidget(section_label(t("Why this score (peak flow)")))
        lay.addSpacing(8)
        self.breakdown = RiskBreakdown()
        lay.addWidget(self.breakdown)
        lay.addSpacing(14)
        lay.addWidget(section_label(t("Latest flows from this source")))
        lay.addSpacing(4)
        self.recent_model = RowsModel(
            [Col("time", t("Time"), "time", 92), Col("dst", t("Destination"), "addr", stretch=1),
             Col("risk", t("Risk"), "risk", 104, align=Qt.AlignRight)],
            self._recent_value, flow_key)
        self.recent = DataTable(self.recent_model, show_selection=False)
        self.recent.horizontalHeader().setVisible(False)
        self.recent.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.recent.setFixedHeight(31 * 5)
        lay.addWidget(self.recent)
        lay.addStretch(1)
        self.detail.body.addWidget(self.content, 1)
        root.addWidget(self.detail)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._show_selected())
        self._pending: Optional[str] = None
        self._show(None)

    # ------------------------------------------------------------------ #
    def _value(self, a, key: str):
        now = self._now
        if key == "sev":
            return alert_sev(a)
        if key == "src":
            return a.src_ip, "", False
        if key == "kind":
            return (alert_kind(a), "ink2", 400)
        if key == "flows":
            return (num(a.flow_count), "ink", 400)
        if key == "risk":
            return a.risk_score, theme.sev_for_risk(a.risk_score)
        if key == "first":
            return (clock(a.first_seen), "ink3", 400)
        if key == "last":
            return (clock(a.last_seen), "ink3", 400)
        if key == "status":
            is_open = self._session is not None and self._session.is_open(a, now)
            return (t("Open") if is_open else t("Closed"), "ink" if is_open else "ink3", 600 if is_open else 400)
        return None

    @staticmethod
    def _recent_value(sf, key: str):
        if key == "time":
            return clock(sf.seen), sf.sev
        if key == "dst":
            return sf.res.dst_ip, sf.res.dst_port, True
        if key == "risk":
            return sf.risk, sf.sev
        return None

    def focus_alert(self, alert_id: str) -> None:
        self.filter.set_current("all")
        self._pending = alert_id

    def focus_source(self, ip: str) -> None:
        if self._session is None:
            return
        mine = [a for a in self._session.alerts if a.src_ip == ip]
        if mine:
            self.focus_alert(max(mine, key=lambda a: a.last_seen).alert_id)

    def _show_selected(self) -> None:
        self._show(self.table.selected_row())

    def _show(self, a) -> None:
        self.placeholder.setVisible(a is None)
        self.content.setVisible(a is not None)
        if a is None:
            self.detail.set_meta("")
            return
        s, now = self._session, self._now
        sev = alert_sev(a)
        self.detail.set_meta(a.alert_id)
        self.chip.set_key(sev)
        self.ip.setText(a.src_ip)
        is_open = s is not None and s.is_open(a, now)
        self.status.setText(t("Open, last flow {ago}", ago=ago(now - a.last_seen)) if is_open
                            else t("Closed"))
        self.risk.setText(f"{a.risk_score:.0f}")
        self.facts.set("kind", alert_kind(a))
        self.facts.set("target", f"{a.sample_dst}:{a.sample_dst_port}")
        self.facts.set("flows", num(a.flow_count))
        self.facts.set("span", duration(a.last_seen - a.first_seen))
        self.facts.set("first", clock(a.first_seen))
        self.facts.set("last", f"{clock(a.last_seen)}  ({ago(now - a.last_seen)})")
        self.facts.set("id", a.alert_id)
        if s is not None:
            self.activity.set_values(s.source_activity(a.src_ip, now), sev)
            prof = s.sources.get(a.src_ip)
            peak = prof.peak if prof else None
            self.breakdown.set_flow(peak, volume=(a.flow_count, volume_floor(a.flow_count)))
            self.recent.sync(s.flows_from(a.src_ip, 5))

    def refresh(self, s: Session, now: float) -> None:
        self._session, self._now = s, now
        alerts = s.alerts_by_recency()
        if self.filter.current() == "open":
            alerts = [a for a in alerts if s.is_open(a, now)]
        self.table.sync(alerts)
        if self._pending is not None:
            if self.table.select_key(self._pending):
                self._pending = None
        n_open = len(s.open_alerts(now))
        self.panel.set_meta(t("{open} open, {total} this session, grouped per source over {s} s",
                              open=n_open, total=len(s.alerts), s=config.ALERT_WINDOW_SECONDS))
        self._show(self.table.selected_row())
