"""NetSentinel — AlertEngine (Faz 5).

DetectionResult akışını alır, risk skoru + severity hesaplar ve aynı kaynak
IP'den gelen tehditleri zaman penceresinde **birleştirir** (deduplication /
throttling). Tek bir saldırgandan dakikada yüzlerce satır yerine, akış sayısı
canlı büyüyen tek bir aggregate alarm üretir.

Ayrıca saldırgan IP profili tutar: bir IP sürekli tehdit üretiyorsa hem akış
sayısıyla severity yükselir hem de top-N saldırgan tablosunda öne çıkar (Faz 7).

Thread-safe: tek worker thread'inden beslenip UI thread'inden okunabilir.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

import config
from alerts.alert import Alert
from alerts.scoring import SEVERITY_ORDER, RiskScorer, Severity, severity_for
from detection.result import DetectionResult


@dataclass
class AttackerProfile:
    src_ip: str
    threat_count: int = 0
    max_risk: float = 0.0
    cumulative_risk: float = 0.0
    last_seen: float = 0.0
    attack_types: set = field(default_factory=set)


def _max_severity(a: Severity, b: Severity) -> Severity:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def _severity_from_count(flow_count: int) -> Severity:
    """Akış sayısına göre severity tabanı (PortScan/DoS gibi hacimli saldırılar)."""
    if flow_count >= 100:
        return Severity.CRITICAL
    if flow_count >= 30:
        return Severity.HIGH
    if flow_count >= 10:
        return Severity.MEDIUM
    return Severity.LOW


class AlertEngine:
    def __init__(
        self,
        on_alert: Optional[Callable[[Alert], None]] = None,
        scorer: Optional[RiskScorer] = None,
        window_seconds: float = None,
        min_risk: float = None,
    ) -> None:
        self.on_alert = on_alert
        self.scorer = scorer or RiskScorer()
        self.window_seconds = window_seconds if window_seconds is not None else config.ALERT_WINDOW_SECONDS
        self.min_risk = min_risk if min_risk is not None else config.ALERT_MIN_RISK

        self._active: Dict[str, Alert] = {}          # src_ip -> açık aggregate alarm
        self._profiles: Dict[str, AttackerProfile] = {}
        self._lock = threading.Lock()
        self._counter = 0
        self.alerts_emitted = 0

    # ----------------------------------------------------------------- #
    def process(self, res: DetectionResult, now: Optional[float] = None) -> Optional[Alert]:
        """Bir tahmini işler. Yeni bir aggregate alarm oluşturulduysa onu döndürür;
        mevcut bir alarma eklendiyse (dedup) None döndürür."""
        if now is None:
            now = time.time()
        score = self.scorer.score(res)
        sev = self.scorer.severity(score)

        if score < self.min_risk:
            return None  # gürültü — alarm üretme

        label = res.supervised_label if res.supervised_label == "ATTACK" else "anomali"

        with self._lock:
            self._update_profile(res.src_ip, score, label, now)
            existing = self._active.get(res.src_ip)

            if existing is not None and (now - existing.last_seen) <= self.window_seconds:
                # Aynı pencere: birleştir (yeni alarm üretme)
                existing.flow_count += 1
                existing.last_seen = now
                existing.risk_score = max(existing.risk_score, score)
                existing.attack_types.add(label)
                existing.sample_dst = res.dst_ip
                existing.sample_dst_port = res.dst_port
                existing.severity = self._effective_severity(
                    existing.risk_score, existing.flow_count
                )
                return None

            # Yeni alarm
            self._counter += 1
            alert = Alert(
                alert_id=f"A{self._counter:06d}",
                src_ip=res.src_ip,
                first_seen=now,
                last_seen=now,
                risk_score=score,
                severity=self._effective_severity(score, 1),
                flow_count=1,
                attack_types={label},
                sample_dst=res.dst_ip,
                sample_dst_port=res.dst_port,
            )
            self._active[res.src_ip] = alert
            self.alerts_emitted += 1

        # callback'i kilit DIŞINDA çağır
        if self.on_alert is not None:
            self.on_alert(alert)
        return alert

    # ----------------------------------------------------------------- #
    def _effective_severity(self, risk: float, flow_count: int) -> Severity:
        """Risk skorundan ve akış sayısından gelen severity'lerin maksimumu."""
        return _max_severity(
            severity_for(risk, self.scorer.thresholds),
            _severity_from_count(flow_count),
        )

    def _update_profile(self, ip: str, score: float, label: str, now: float) -> None:
        prof = self._profiles.get(ip)
        if prof is None:
            prof = AttackerProfile(src_ip=ip)
            self._profiles[ip] = prof
        prof.threat_count += 1
        prof.max_risk = max(prof.max_risk, score)
        prof.cumulative_risk += score
        prof.last_seen = now
        prof.attack_types.add(label)

    # ----------------------------------------------------------------- #
    def purge_expired(self, now: Optional[float] = None) -> int:
        """Penceresi dolan aktif alarmları kapatır (yeni tehditler yeni alarm açar)."""
        if now is None:
            now = time.time()
        with self._lock:
            expired = [ip for ip, a in self._active.items()
                       if (now - a.last_seen) > self.window_seconds]
            for ip in expired:
                del self._active[ip]
        return len(expired)

    def active_alerts(self) -> List[Alert]:
        with self._lock:
            return list(self._active.values())

    def top_attackers(self, n: int = 10) -> List[AttackerProfile]:
        with self._lock:
            return sorted(
                self._profiles.values(),
                key=lambda p: (p.threat_count, p.max_risk),
                reverse=True,
            )[:n]
