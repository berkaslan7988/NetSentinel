"""NetSentinel — Alert modeli (Faz 5).

Bir alarm, tek bir kaynak IP'den belirli bir zaman penceresinde gelen tehdit
akışlarının **birleştirilmiş** (aggregate) özetidir. Böylece PortScan gibi
saldırılarda dakikada 500 satır yerine tek, derli toplu bir alarm üretilir.

Alert mutable'dır: AlertEngine pencere içindeki yeni akışlarda aynı nesneyi
günceller (flow_count artar, risk yükselir), UI/storage aynı referansı görür.
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
    # Örnek bir hedef (UI detayında göstermek için)
    sample_dst: str = ""
    sample_dst_port: int = 0

    def summary(self) -> str:
        types = ", ".join(sorted(self.attack_types)) if self.attack_types else "anomali"
        span = max(0.0, self.last_seen - self.first_seen)
        return (
            f"[{self.severity.value:8}] {self.src_ip} — {types} | "
            f"risk {self.risk_score:.0f}/100 | "
            f"{self.flow_count} akış / {span:.0f}s "
            f"(örn -> {self.sample_dst}:{self.sample_dst_port})"
        )
