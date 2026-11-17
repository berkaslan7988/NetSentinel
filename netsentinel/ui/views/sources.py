"""Sources: one profile per source IP that produced threat flows."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QWidget

import config
from ui.i18n import ago, num, t
from ui.session import Session, SourceProfile
from ui.tables import Col, DataTable, RowsModel
from ui.widgets import Panel


def _seen_as(p: SourceProfile) -> str:
    if p.known and p.anomaly:
        return t("Known attack + anomaly")
    return t("Known attack") if p.known else t("Anomaly")


def _internal(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.")) or any(ip.startswith(f"172.{i}.") for i in range(16, 32))


class SourcesView(QWidget):
    sourceClicked = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("page")
        self._now = 0.0
        self._session = None
        self._top = 1
        root = QHBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)
        self.panel = Panel(t("Sources"), "")
        cols = [
            Col("ip", t("Source"), "addr", 146),
            Col("where", t("Network"), "text", 80),
            Col("flows", t("Threat flows"), "bar", stretch=1),
            Col("peak", t("Peak risk"), "risk", 104, align=Qt.AlignRight),
            Col("cum", t("Total risk"), "mono", 86, align=Qt.AlignRight),
            Col("seen", t("Seen as"), "text", 140),
            Col("act", t("Activity, 10 min"), "spark", 136),
            Col("last", t("Last threat"), "mono", 110, align=Qt.AlignRight),
        ]
        self.model = RowsModel(cols, self._value, lambda p: p.ip)
        self.table = DataTable(self.model, t("No threat sources yet"),
                               t("A source appears here once one of its flows scores {n} or more.",
                                 n=config.ALERT_MIN_RISK))
        self.table.rowClicked.connect(lambda p: self.sourceClicked.emit(p.ip))
        self.table.setCursor(Qt.PointingHandCursor)
        self.panel.body.addWidget(self.table)
        root.addWidget(self.panel, 1)

        self.targets_panel = Panel(t("Most targeted hosts"), t("by threat flows received"))
        self.targets_panel.setFixedWidth(430)
        tcols = [
            Col("ip", t("Host"), "addr", 124),
            Col("flows", t("Threat flows"), "bar", stretch=1),
            Col("ports", t("Ports"), "mono", 100),
            Col("peak", t("Peak risk"), "risk", 88, align=Qt.AlignRight),
        ]
        self.tmodel = RowsModel(tcols, self._tvalue, lambda p: p.ip)
        self.ttable = DataTable(self.tmodel, t("No targets yet"), show_selection=False)
        self.targets_panel.body.addWidget(self.ttable)
        root.addWidget(self.targets_panel)
        self._ttop = 1

    def _value(self, p: SourceProfile, key: str):
        if key == "ip":
            return p.ip, "", False
        if key == "where":
            return (t("internal") if _internal(p.ip) else t("external"), "ink3", 400)
        if key == "flows":
            return p.threat_flows / self._top, p.sev, num(p.threat_flows)
        if key == "peak":
            return p.max_risk, p.sev
        if key == "cum":
            return (num(p.cumulative_risk), "ink2", 400)
        if key == "seen":
            return (_seen_as(p), "ink2", 400)
        if key == "act":
            return self._session.source_activity(p.ip, self._now), p.sev
        if key == "last":
            return (ago(self._now - p.last_seen), "ink3", 400)
        return None

    def _tvalue(self, p, key: str):
        if key == "ip":
            return p.ip, "", False
        if key == "flows":
            return p.threat_flows / self._ttop, p.sev, num(p.threat_flows)
        if key == "ports":
            ports = p.top_ports(2)
            more = len(p.ports) - len(ports)
            text = ", ".join(str(x) for x in ports) + (f" +{more}" if more > 0 else "")
            return (text, "ink2", 400)
        if key == "peak":
            return p.max_risk, p.sev
        return None

    def refresh(self, s: Session, now: float) -> None:
        self._session, self._now = s, now
        rows = s.top_sources(200)
        self._top = max((p.threat_flows for p in rows), default=1) or 1
        self.table.sync(rows)
        targets = s.top_targets(40)
        self._ttop = max((p.threat_flows for p in targets), default=1) or 1
        self.ttable.sync(targets)
        n_int = sum(1 for p in rows if _internal(p.ip))
        self.panel.set_meta(t("{n} sources raised threat flows: {e} external, {i} internal. "
                              "Click one to open its alert.", n=len(rows), e=len(rows) - n_int, i=n_int))
