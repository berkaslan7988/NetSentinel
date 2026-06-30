"""NetSentinel - Alert model (Phase 5).

An alert is the aggregated summary of the threat flows coming from a single
source IP within a time window. This way a PortScan produces one tidy alert
instead of 500 lines per minute.

Alert is mutable: the AlertEngine updates the same object for new flows within
the window (flow_count grows, risk rises), and the UI/storage sees the same
reference.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Set

from alerts.scoring import Severity


@dataclass
class Alert:
    alert_id: str
    src_ip: str
    first_seen: float
    last_seen: float
    risk_score: float
    severity: Severity
    flow_count: int = 1
    attack_types: Set[str] = field(default_factory=set)
    # A sample destination (to show in the UI detail)
    sample_dst: str = ""
    sample_dst_port: int = 0

    def summary(self) -> str:
        types = ", ".join(sorted(self.attack_types)) if self.attack_types else "anomaly"
        span = max(0.0, self.last_seen - self.first_seen)
        return (
            f"[{self.severity.value:8}] {self.src_ip} - {types} | "
            f"risk {self.risk_score:.0f}/100 | "
            f"{self.flow_count} flows / {span:.0f}s "
            f"(e.g. -> {self.sample_dst}:{self.sample_dst_port})"
        )
