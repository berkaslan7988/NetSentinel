"""Overview: session totals, the flow timeline, live flows, alerts, top sources."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QHBoxLayout, QVBoxLayout, QWidget

import config
from ui import theme
from ui.i18n import num, t
from ui.i18n import pct as fmt_pct
from ui.session import Session
from ui.tables import DataTable, RowsModel
from ui.timeline import FlowTimeline
from ui.views.common import (
    AlertList, Legend, SourceList, alert_sev, clock, flow_cols, flow_key, flow_text, flow_value,
    fmt_bytes,
)
from ui.widgets import ChipWidget, KpiCell, KpiStrip, Panel, SearchBox, Segmented, SeverityBar, Sparkline, mono_html


class OverviewView(QWidget):
    alertClicked = Signal(str)
    sourceClicked = Signal(str)
    flowClicked = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("page")
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(12)

        # totals ---------------------------------------------------------------
        self.k_flows = KpiCell(t("Flows scored"))
        self.k_threats = KpiCell(t("Threat flows"))
        self.k_alerts = KpiCell(t("Open alerts"))
        self.sev_bar = SeverityBar()
        self.k_alerts.extra.addWidget(self.sev_bar, 1, Qt.AlignVCenter)
        self.k_thru = KpiCell(t("Throughput"))
        self.spark = Sparkline()
        self.k_thru.extra.addStretch(1)
        self.k_thru.extra.addWidget(self.spark, 0, Qt.AlignBottom)
        self.k_peak = KpiCell(t("Peak risk"))
        self.peak_chip = ChipWidget()
        self.k_peak.extra.addWidget(self.peak_chip, 0, Qt.AlignVCenter)
        self.k_peak.extra.addStretch(1)
        root.addWidget(KpiStrip([self.k_flows, self.k_threats, self.k_alerts, self.k_thru, self.k_peak]))

        # timeline -------------------------------------------------------------
        tl = Panel(t("Flow timeline"), t("last 10 min, 5 s buckets, threat flows stacked on top"))
        tl.add_tool(Legend())
        self.timeline = FlowTimeline()
        self.timeline.setFixedHeight(176)
        self.timeline.empty_hint = t("Press Start. Demo mode needs no models or capture driver.")
        holder = QVBoxLayout()
        holder.setContentsMargins(12, 8, 14, 8)
        holder.addWidget(self.timeline)
        tl.body.addLayout(holder)
        root.addWidget(tl)

        # bottom row -------------------------------------------------------------
        row = QHBoxLayout()
        row.setSpacing(12)
        flows = Panel(t("Live flows"), t("newest first"))
        self.filter = Segmented([("all", t("All")), ("threats", t("Threats"))])
        self.search = SearchBox(t("Filter by IP or port"))
        flows.add_tool(self.filter)
        flows.add_tool(self.search)
        self.flow_model = RowsModel(flow_cols(), flow_value, flow_key, flow_text)
        self.flow_table = DataTable(self.flow_model, t("No flows yet"),
                                    t("Pick a source in the top bar and press Start."),
                                    show_selection=False)
        self.flow_table.setCursor(Qt.PointingHandCursor)
        self.flow_table.rowClicked.connect(self.flowClicked)
        self.flow_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        flows.body.addWidget(self.flow_table)
        row.addWidget(flows, 62)

        side = QVBoxLayout()
        side.setSpacing(12)
        self.alerts_panel = Panel(t("Alerts"), t("grouped per source, {s} s window",
                                                 s=config.ALERT_WINDOW_SECONDS))
        self.alert_list = AlertList()
        self.alert_list.clicked.connect(self.alertClicked)
        self.alerts_panel.body.addWidget(self.alert_list)
        side.addWidget(self.alerts_panel, 1)
        src = Panel(t("Top sources"), t("by threat flows"))
        self.source_list = SourceList(5)
        self.source_list.clicked.connect(self.sourceClicked)
        src.body.addWidget(self.source_list)
        side.addWidget(src, 0)
        row.addLayout(side, 38)
        root.addLayout(row, 1)

    # ------------------------------------------------------------------ #
    def refresh(self, s: Session, now: float) -> None:
        P = theme.current()
        rate = s.flow_rate(now)
        self.k_flows.set(num(s.total_flows), "",
                         t("{rate} flows / s right now", rate=mono_html(num(rate, 1))))
        pct = (100.0 * s.threat_flows / s.total_flows) if s.total_flows else 0.0
        self.k_threats.set(num(s.threat_flows), "",
                           t("{pct} of all flows, risk 25+", pct=mono_html(fmt_pct(pct))))

        open_alerts = s.open_alerts(now)
        counts = {k: 0 for k in ("crit", "high", "med")}
        for a in open_alerts:
            counts[alert_sev(a)] = counts.get(alert_sev(a), 0) + 1
        self.sev_bar.set_counts(counts["crit"], counts["high"], counts["med"])
        parts = []
        for key, name in (("crit", t("critical")), ("high", t("high")), ("med", t("medium"))):
            parts.append(f'{mono_html(str(counts[key]), key + "_ink", 600)} {name}')
        self.k_alerts.set(num(len(open_alerts)), "", " &nbsp; ".join(parts))

        thru = s.throughput(now)
        v, u = fmt_bytes(thru, per_second=True)
        tv, tu = fmt_bytes(s.total_bytes)
        self.k_thru.set(v, u, t("{total} this session", total=mono_html(f"{tv} {tu}")))
        self.spark.set_values(s.throughput_series(now, 40))

        if s.peak is not None and s.peak.risk > 0:
            self.k_peak.set(f"{s.peak.risk:.0f}", "/100",
                            t("{ip} at {time}", ip=mono_html(s.peak.res.src_ip), time=clock(s.peak.seen)))
            self.peak_chip.set_key(s.peak.sev)
        else:
            self.k_peak.set("0", "/100", t("no risky flow yet"))
            self.peak_chip.set_key(None)

        window_start = now - 120 * 5
        markers = [(a.first_seen, alert_sev(a), a.src_ip) for a in s.alerts
                   if a.first_seen >= window_start and alert_sev(a) in ("high", "crit")]
        self.timeline.set_data(s.timeline(now), markers, now)

        rows = s.newest(60, threats_only=self.filter.current() == "threats", needle=self.search.text())
        self.flow_table.sync(rows)

        alerts = sorted(s.alerts, key=lambda a: (not s.is_open(a, now), -a.last_seen))
        self.alert_list.set_alerts(alerts, now)
        self.alerts_panel.set_meta(t("{n} open, grouped per source over {s} s",
                                     n=len(open_alerts), s=config.ALERT_WINDOW_SECONDS))
        self.source_list.set_sources(s.top_sources(5))
        del P
