"""Flows: every scored flow (newest first) and how the selected one was scored."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ui import theme
from ui.i18n import ago, num, t
from ui.session import ScoredFlow, Session
from ui.tables import DataTable, RowsModel
from ui.views.common import (
    Facts, clock, flow_cols, flow_key, flow_text, flow_value, fmt_bytes, section_label,
)
from ui.views.detail import RiskBreakdown, SignalRows
from ui.widgets import ChipWidget, Panel, SearchBox, Segmented, label


class FlowDetail(Panel):
    def __init__(self, parent=None) -> None:
        super().__init__(t("Flow detail"))
        self.setFixedWidth(372)
        self.placeholder = QLabel(t("Select a flow to see each model's output and how its risk score was built."))
        self.placeholder.setObjectName("ink3")
        self.placeholder.setFont(theme.ui(12))
        self.placeholder.setWordWrap(True)
        self.placeholder.setAlignment(Qt.AlignCenter)
        self.placeholder.setContentsMargins(28, 0, 28, 0)
        self.body.addWidget(self.placeholder, 1)

        self.content = QWidget()
        self.content.setObjectName("transparent")
        lay = QVBoxLayout(self.content)
        lay.setContentsMargins(16, 14, 16, 16)
        lay.setSpacing(0)
        top = QHBoxLayout()
        top.setSpacing(10)
        self.risk = label("0", theme.mono(28, 500))
        top.addWidget(self.risk, 0, Qt.AlignBottom)
        top.addWidget(label("/100", theme.ui(12), "ink3"), 0, Qt.AlignBottom)
        top.addSpacing(4)
        self.chip = ChipWidget()
        top.addWidget(self.chip, 0, Qt.AlignVCenter)
        top.addStretch(1)
        self.verdict = label("", theme.ui(12, 600))
        top.addWidget(self.verdict, 0, Qt.AlignVCenter)
        lay.addLayout(top)
        lay.addSpacing(14)
        self.facts = Facts()
        for key, cap in (("src", t("Source")), ("dst", t("Destination")), ("proto", t("Protocol")),
                         ("seen", t("Seen")), ("dur", t("Duration")), ("pkts", t("Packets")),
                         ("bytes", t("Bytes"))):
            self.facts.add(key, cap)
        lay.addWidget(self.facts)
        lay.addSpacing(18)
        lay.addWidget(section_label(t("Model signals")))
        lay.addSpacing(10)
        self.signals = SignalRows()
        lay.addWidget(self.signals)
        lay.addSpacing(12)
        lay.addWidget(section_label(t("Risk score")))
        lay.addSpacing(8)
        self.breakdown = RiskBreakdown()
        lay.addWidget(self.breakdown)
        lay.addStretch(1)
        self.body.addWidget(self.content, 1)
        self.show_flow(None, 0.0)

    def show_flow(self, sf: Optional[ScoredFlow], now: float) -> None:
        self.placeholder.setVisible(sf is None)
        self.content.setVisible(sf is not None)
        if sf is None:
            self.set_meta("")
            return
        r = sf.res
        self.set_meta(clock(sf.seen))
        self.risk.setText(f"{sf.risk:.0f}")
        self.chip.set_key(sf.sev)
        P = theme.current()
        if r.supervised_label == "ATTACK":
            self.verdict.setText(t("RF: attack"))
            self.verdict.setStyleSheet(f"color: {P.crit_ink};")
        elif r.supervised_label == "BENIGN":
            self.verdict.setText(t("RF: benign"))
            self.verdict.setStyleSheet(f"color: {P.ink3};")
        else:
            self.verdict.setText(t("RF not loaded"))
            self.verdict.setStyleSheet(f"color: {P.ink3};")
        self.facts.set("src", f"{r.src_ip}:{r.src_port}")
        self.facts.set("dst", f"{r.dst_ip}:{r.dst_port}")
        self.facts.set("proto", r.protocol or "-")
        self.facts.set("seen", f"{clock(sf.seen)}  ({ago(now - sf.seen)})")
        self.facts.set("dur", f"{num(r.duration or 0, 3)} s")
        self.facts.set("pkts", t("{f} out / {b} back", f=num(r.fwd_packets or 0), b=num(r.bwd_packets or 0)))
        v, u = fmt_bytes(r.total_bytes or 0)
        self.facts.set("bytes", f"{v} {u}")
        self.signals.set_flow(sf)
        self.breakdown.set_flow(sf)


class FlowsView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("page")
        root = QHBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)
        self.panel = Panel(t("Flows"), "")
        self.filter = Segmented([("all", t("All")), ("threats", t("Threats"))])
        self.search = SearchBox(t("Filter by IP or port"), 230)
        self.panel.add_tool(self.filter)
        self.panel.add_tool(self.search)
        self.model = RowsModel(flow_cols(extended=True), flow_value, flow_key, flow_text)
        self.table = DataTable(self.model, t("No flows yet"),
                               t("Pick a source in the top bar and press Start."))
        self.panel.body.addWidget(self.table)
        root.addWidget(self.panel, 1)
        self.detail = FlowDetail()
        root.addWidget(self.detail)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._show_selected())
        self._now = 0.0
        self._limit = 1000

    def _show_selected(self) -> None:
        self.detail.show_flow(self.table.selected_row(), self._now)

    def focus_flow(self, sf: ScoredFlow) -> None:
        self.search.edit.clear()
        self.filter.set_current("all")
        self._pending = sf.seq

    def refresh(self, s: Session, now: float) -> None:
        self._now = now
        threats = self.filter.current() == "threats"
        rows = s.newest(self._limit, threats_only=threats, needle=self.search.text())
        self.table.sync(rows)
        pending = getattr(self, "_pending", None)
        if pending is not None:
            self._pending = None
            if self.table.select_key(pending):
                self.table.scrollTo(self.model.index(self.model.index_of(pending), 0),
                                    QAbstractItemView.PositionAtCenter)
        shown = len(rows)
        self.panel.set_meta(t("{shown} shown of {total} scored this session",
                              shown=num(shown), total=num(s.total_flows)))
        sel = self.table.selected_row()
        if sel is not None:
            self.detail.show_flow(sel, now)
