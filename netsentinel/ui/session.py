"""NetSentinel - dashboard session state (Qt-independent).

The UI thread drains the pipeline queues into a ``Session``; every view reads
from it. The session scores each flow with the same RiskScorer as the alert
engine, so a flow's risk in the tables is the number its alert would carry,
and it keeps the rolling aggregates the dashboard draws:

* a 10-minute timeline in 5 s buckets (benign flows + threat flows by severity),
* per-source activity and profiles (flows with risk >= ALERT_MIN_RISK),
* the newest flows (a bounded ring) and every alert seen this session.

Times are "seen" times: when the UI received a flow (or, for the demo's warm
start and tests, the time passed in), never the flow's own start time, which
can lag by the idle timeout or come from an old CSV.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

import config
from alerts.scoring import RiskScorer
from detection.result import DetectionResult

BUCKET_SECONDS = 5.0
WINDOW_BUCKETS = 120                      # 10 minutes
SEVERITIES = ("low", "med", "high", "crit")


def severity_key(risk: float) -> str:
    th = config.SEVERITY_THRESHOLDS
    if risk >= th["CRITICAL"]:
        return "crit"
    if risk >= th["HIGH"]:
        return "high"
    if risk >= th["MEDIUM"]:
        return "med"
    return "low"


@dataclass
class ScoredFlow:
    """A DetectionResult plus the dashboard's view of it."""
    res: DetectionResult
    risk: float
    sev: str
    seen: float
    seq: int

    @property
    def is_threat(self) -> bool:
        return self.risk >= config.ALERT_MIN_RISK

    def matches(self, needle: str) -> bool:
        if not needle:
            return True
        r = self.res
        hay = f"{r.src_ip}:{r.src_port} {r.dst_ip}:{r.dst_port} {r.protocol}".lower()
        return all(part in hay for part in needle.lower().split())


@dataclass
class Bucket:
    start: float
    benign: int = 0
    low: int = 0              # risk under the alert threshold but flagged by a model
    med: int = 0
    high: int = 0
    crit: int = 0
    bytes: int = 0

    @property
    def threats(self) -> int:
        return self.med + self.high + self.crit

    @property
    def total(self) -> int:
        return self.benign + self.low + self.threats

    @property
    def top(self) -> Optional[str]:
        for key in ("crit", "high", "med"):
            if getattr(self, key):
                return key
        return None


@dataclass
class SourceProfile:
    ip: str
    threat_flows: int = 0
    max_risk: float = 0.0
    cumulative_risk: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    known: int = 0            # flows the RandomForest called ATTACK
    anomaly: int = 0          # flows raised by IsolationForest / Autoencoder only
    peak: Optional[ScoredFlow] = None
    activity: Dict[int, int] = field(default_factory=dict)   # bucket index -> threat flows

    @property
    def sev(self) -> str:
        return severity_key(self.max_risk)


@dataclass
class TargetProfile:
    """A host that received threat flows."""
    ip: str
    threat_flows: int = 0
    max_risk: float = 0.0
    ports: Dict[int, int] = field(default_factory=dict)
    sources: set = field(default_factory=set)

    @property
    def sev(self) -> str:
        return severity_key(self.max_risk)

    def top_ports(self, n: int = 3) -> List[int]:
        return [p for p, _ in sorted(self.ports.items(), key=lambda kv: -kv[1])[:n]]


class Session:
    def __init__(self, scorer: Optional[RiskScorer] = None, max_flows: int = 2000) -> None:
        self.scorer = scorer or RiskScorer()
        self.max_flows = max_flows
        self.reset()

    # ----------------------------------------------------------------- #
    def reset(self, started_at: Optional[float] = None) -> None:
        self.started_at = started_at
        self.flows: Deque[ScoredFlow] = deque(maxlen=self.max_flows)
        self.alerts: List = []
        self._alert_ids: set = set()
        self.sources: Dict[str, SourceProfile] = {}
        self.targets: Dict[str, TargetProfile] = {}
        self.buckets: Dict[int, Bucket] = {}
        self.total_flows = 0
        self.threat_flows = 0
        self.total_bytes = 0
        self.peak: Optional[ScoredFlow] = None
        self.last_seen = 0.0
        self._seq = 0

    # ----------------------------------------------------------------- #
    @staticmethod
    def bucket_index(t: float) -> int:
        return int(t // BUCKET_SECONDS)

    def add_result(self, res: DetectionResult, seen: Optional[float] = None) -> ScoredFlow:
        if seen is None:
            seen = getattr(res, "seen_at", None) or time.time()
        risk = self.scorer.score(res)
        sev = severity_key(risk)
        self._seq += 1
        sf = ScoredFlow(res=res, risk=risk, sev=sev, seen=seen, seq=self._seq)
        self.flows.append(sf)
        self.total_flows += 1
        nbytes = int(res.total_bytes or 0)
        self.total_bytes += nbytes
        self.last_seen = max(self.last_seen, seen)
        if self.started_at is None:
            self.started_at = seen

        idx = self.bucket_index(seen)
        b = self.buckets.get(idx)
        if b is None:
            b = self.buckets[idx] = Bucket(start=idx * BUCKET_SECONDS)
            self._trim_buckets(idx)
        b.bytes += nbytes
        if sf.is_threat:
            setattr(b, sev, getattr(b, sev) + 1)
            self.threat_flows += 1
            self._profile(sf, idx)
        elif res.is_threat or (res.supervised_label == "ATTACK"):
            b.low += 1
        else:
            b.benign += 1

        if self.peak is None or risk > self.peak.risk:
            self.peak = sf
        return sf

    def _profile(self, sf: ScoredFlow, idx: int) -> None:
        ip = sf.res.src_ip
        prof = self.sources.get(ip)
        if prof is None:
            prof = self.sources[ip] = SourceProfile(ip=ip, first_seen=sf.seen)
        prof.threat_flows += 1
        prof.cumulative_risk += sf.risk
        prof.last_seen = sf.seen
        if sf.res.supervised_label == "ATTACK":
            prof.known += 1
        else:
            prof.anomaly += 1
        if prof.peak is None or sf.risk >= prof.peak.risk:
            prof.peak = sf
        prof.max_risk = max(prof.max_risk, sf.risk)
        prof.activity[idx] = prof.activity.get(idx, 0) + 1
        dst = sf.res.dst_ip
        tgt = self.targets.get(dst)
        if tgt is None:
            tgt = self.targets[dst] = TargetProfile(ip=dst)
        tgt.threat_flows += 1
        tgt.max_risk = max(tgt.max_risk, sf.risk)
        tgt.ports[sf.res.dst_port] = tgt.ports.get(sf.res.dst_port, 0) + 1
        tgt.sources.add(ip)
        if len(prof.activity) > WINDOW_BUCKETS * 2:
            for old in sorted(prof.activity)[: len(prof.activity) - WINDOW_BUCKETS]:
                del prof.activity[old]

    def _trim_buckets(self, newest: int) -> None:
        cutoff = newest - WINDOW_BUCKETS * 2
        for old in [k for k in self.buckets if k < cutoff]:
            del self.buckets[old]

    def add_alert(self, alert) -> None:
        if alert.alert_id in self._alert_ids:
            return
        self._alert_ids.add(alert.alert_id)
        self.alerts.append(alert)

    # ----------------------------------------------------------------- #
    # derived views
    # ----------------------------------------------------------------- #
    def timeline(self, now: float, n: int = WINDOW_BUCKETS) -> List[Bucket]:
        """The last ``n`` buckets, oldest first (empty buckets included)."""
        last = self.bucket_index(now)
        return [self.buckets.get(i) or Bucket(start=i * BUCKET_SECONDS)
                for i in range(last - n + 1, last + 1)]

    def flow_rate(self, now: float, span: float = 10.0) -> float:
        """Flows per second over the last ``span`` seconds."""
        n = 0
        for sf in reversed(self.flows):
            if sf.seen < now - span:
                break
            n += 1
        return n / span

    def throughput_series(self, now: float, n: int = 40) -> List[float]:
        """Bytes per second for the last ``n`` complete buckets."""
        return [b.bytes / BUCKET_SECONDS for b in self.timeline(now - BUCKET_SECONDS, n)]

    def throughput(self, now: float) -> float:
        series = self.throughput_series(now, 2)
        return sum(series) / len(series) if series else 0.0

    def is_open(self, alert, now: float) -> bool:
        return (now - alert.last_seen) <= config.ALERT_WINDOW_SECONDS

    def open_alerts(self, now: float) -> List:
        return [a for a in self.alerts if self.is_open(a, now)]

    def alerts_by_recency(self) -> List:
        return sorted(self.alerts, key=lambda a: a.last_seen, reverse=True)

    def top_sources(self, n: int = 10) -> List[SourceProfile]:
        return sorted(self.sources.values(),
                      key=lambda p: (p.threat_flows, p.max_risk), reverse=True)[:n]

    def top_targets(self, n: int = 10) -> List[TargetProfile]:
        return sorted(self.targets.values(),
                      key=lambda p: (p.threat_flows, p.max_risk), reverse=True)[:n]

    def source_activity(self, ip: str, now: float, n: int = WINDOW_BUCKETS) -> List[int]:
        prof = self.sources.get(ip)
        last = self.bucket_index(now)
        if prof is None:
            return [0] * n
        return [prof.activity.get(i, 0) for i in range(last - n + 1, last + 1)]

    def flows_from(self, ip: str, limit: int = 8) -> List[ScoredFlow]:
        out: List[ScoredFlow] = []
        for sf in reversed(self.flows):
            if sf.res.src_ip == ip:
                out.append(sf)
                if len(out) >= limit:
                    break
        return out

    def newest(self, limit: int, threats_only: bool = False, needle: str = "") -> List[ScoredFlow]:
        out: List[ScoredFlow] = []
        for sf in reversed(self.flows):
            if threats_only and not sf.is_threat:
                continue
            if needle and not sf.matches(needle):
                continue
            out.append(sf)
            if len(out) >= limit:
                break
        return out
