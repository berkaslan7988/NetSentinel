"""NetSentinel - demo traffic (Qt-independent, no models, no capture).

``DemoTraffic`` produces realistic synthetic DetectionResults: a small office
network (192.168.10.0/24) talking to the internet, plus a scripted 12-minute
cycle of attacks from documentation-range addresses (RFC 5737):

    80-140 s    port scan        203.0.113.9    -> 192.168.10.8   (many ports)
    170-200 s   FTP brute force  198.51.100.200 -> 192.168.10.8:21
    250-310 s   HTTP flood       198.51.100.77  -> 192.168.10.50:80
    350-390 s   SMB sweep        192.168.10.31  -> 192.168.10.x:445 (lateral movement)
    420-720 s   SSH brute force  203.0.113.45   -> 192.168.10.12:22
    480-720 s   web attack       192.0.2.140    -> 192.168.10.12:443
    520-560 s   DNS anomaly      192.168.10.58  -> 192.168.10.1:53  (anomaly only)
    every 40 s  beacon           192.168.10.23  -> 198.51.100.14:8443 (anomaly only)

Model outputs are drawn per traffic class so the real RiskScorer and
AlertEngine turn them into risk scores and alerts. Benign flows carry the
measured false-positive rates (IsolationForest ~2 %, Autoencoder ~1 %).

Output is deterministic: each virtual second is generated from its own seed,
so the same second always yields the same flows however the calls are split.

``DemoPipeline`` feeds that stream through the normal DetectionPipeline. It
warm-starts with ten minutes of history so the dashboard is populated at once.
"""
from __future__ import annotations

import math
import random
import threading
import time
from typing import List, Optional

from detection.result import DetectionResult
from ui.pipeline import DetectionPipeline

CYCLE = 720.0
AE_THRESHOLD = 0.3043        # models/ae_meta.json (99th percentile of benign error)
WARM_START = 600.0

_WORKSTATIONS = [f"192.168.10.{i}" for i in (17, 21, 23, 31, 34, 40, 44, 52, 58, 63)]
_SERVERS = ["192.168.10.8", "192.168.10.12", "192.168.10.50"]
_EXTERNAL = [
    "198.51.100.20", "198.51.100.61", "198.51.100.88", "198.51.100.14",
    "192.0.2.33", "192.0.2.71", "192.0.2.123", "198.51.100.140",
]
_GATEWAY = "192.168.10.1"

# (dst port, protocol, weight)
_BENIGN_SERVICES = [(443, "TCP", 62), (80, "TCP", 9), (53, "UDP", 17), (123, "UDP", 3),
                    (993, "TCP", 4), (445, "TCP", 3), (22, "TCP", 2)]


class _Kind:
    def __init__(self, name, proba, iso, ae):
        self.name = name
        self.proba = proba        # (low, high) RandomForest attack probability
        self.iso = iso            # P(IsolationForest flags it)
        self.ae = ae              # P(Autoencoder flags it)


BENIGN = _Kind("benign", (0.0, 0.08), 0.02, 0.01)
SCAN = _Kind("scan", (0.62, 0.74), 0.5, 0.0)
FTP = _Kind("ftp", (0.7, 0.86), 0.4, 0.2)
SWEEP = _Kind("sweep", (0.66, 0.8), 0.6, 0.3)
FLOOD = _Kind("flood", (0.95, 1.0), 0.9, 0.85)
BRUTE = _Kind("brute", (0.88, 0.99), 0.8, 0.7)
WEB = _Kind("web", (0.55, 0.72), 0.0, 0.6)
BEACON = _Kind("beacon", (0.02, 0.08), 1.0, 1.0)


class DemoTraffic:
    def __init__(self, seed: int = 7, mode: str = "hybrid", epoch: Optional[float] = None) -> None:
        self.seed = seed
        self.mode = mode
        # by default "now" lands 600 s into the cycle: every episode is in view
        self.epoch = epoch if epoch is not None else math.floor(time.time()) - WARM_START

    # ----------------------------------------------------------------- #
    def phase(self, t: float) -> float:
        return (t - self.epoch) % CYCLE

    def between(self, t0: float, t1: float) -> List[DetectionResult]:
        """Every flow whose timestamp falls in [t0, t1), in time order."""
        out: List[DetectionResult] = []
        for sec in range(int(math.floor(t0)), int(math.ceil(t1))):
            for res in self._second(sec):
                if t0 <= res.timestamp < t1:
                    out.append(res)
        out.sort(key=lambda r: r.timestamp)
        return out

    # ----------------------------------------------------------------- #
    def _second(self, sec: int) -> List[DetectionResult]:
        rng = random.Random(self.seed * 1_000_003 + sec)
        p = self.phase(sec)
        flows: List[DetectionResult] = []

        # benign background: ~21 flows/s with a slow swell
        lam = 21 + 5 * math.sin(sec / 47.0) + 3 * math.sin(sec / 13.0)
        for _ in range(_poisson(rng, lam)):
            flows.append(self._benign(rng, sec))

        if 80 <= p < 140:
            for _ in range(_poisson(rng, 1.0)):
                flows.append(self._attack(rng, sec, SCAN, "203.0.113.9", "192.168.10.8",
                                          rng.randint(1, 1024), (1, 2), (1, 1), (58, 120), (0.0, 0.01)))
        if 170 <= p < 200:
            for _ in range(_poisson(rng, 1.5)):
                flows.append(self._attack(rng, sec, FTP, "198.51.100.200", "192.168.10.8",
                                          21, (8, 14), (6, 12), (900, 2400), (1.0, 4.0)))
        if 350 <= p < 390:
            for _ in range(_poisson(rng, 1.2)):
                flows.append(self._attack(rng, sec, SWEEP, "192.168.10.31", f"192.168.10.{rng.randint(2, 60)}",
                                          445, (2, 4), (1, 3), (180, 640), (0.01, 0.4)))
        if 520 <= p < 560:
            for _ in range(_poisson(rng, 0.5)):
                flows.append(self._attack(rng, sec, BEACON, "192.168.10.58", "192.168.10.1",
                                          53, (1, 2), (1, 2), (300, 1400), (0.01, 0.2), proto="UDP"))
        if 250 <= p < 310:
            rate = 4 + 26 * math.sin(math.pi * (p - 250) / 60.0)
            for _ in range(_poisson(rng, rate)):
                flows.append(self._attack(rng, sec, FLOOD, "198.51.100.77", "192.168.10.50",
                                          80, (4, 8), (2, 6), (420, 1300), (0.2, 3.0)))
        if 420 <= p < 720:
            for _ in range(_poisson(rng, 2.3)):
                flows.append(self._attack(rng, sec, BRUTE, "203.0.113.45", "192.168.10.12",
                                          22, (12, 24), (10, 22), (2100, 5200), (2.0, 6.0)))
        if 480 <= p < 720:
            for _ in range(_poisson(rng, 0.4)):
                flows.append(self._attack(rng, sec, WEB, "192.0.2.140", "192.168.10.12",
                                          443, (6, 14), (5, 12), (1500, 9000), (0.3, 2.5)))
        if int(p) % 40 == 7:
            flows.append(self._attack(rng, sec, BEACON, "192.168.10.23", "198.51.100.14",
                                      8443, (3, 3), (3, 3), (860, 960), (0.3, 0.5)))
        return flows

    def _benign(self, rng: random.Random, sec: int) -> DetectionResult:
        port, proto, _ = rng.choices(_BENIGN_SERVICES, weights=[w for *_, w in _BENIGN_SERVICES])[0]
        src = rng.choice(_WORKSTATIONS)
        if port == 53:
            dst, fwd, bwd, size, dur = _GATEWAY, 1, 1, rng.randint(150, 420), rng.uniform(0.001, 0.05)
        elif port == 123:
            dst, fwd, bwd, size, dur = "192.0.2.123", 1, 1, 152, rng.uniform(0.01, 0.06)
        elif port == 445:
            dst, fwd, bwd = "192.168.10.8", rng.randint(6, 40), rng.randint(6, 60)
            size, dur = int(rng.lognormvariate(9.6, 1.0)), rng.uniform(0.2, 20)
        elif port == 22:
            src, dst = "192.168.10.44", "192.168.10.12"
            fwd, bwd = rng.randint(20, 80), rng.randint(20, 90)
            size, dur = int(rng.lognormvariate(9.0, 0.6)), rng.uniform(5, 60)
        else:
            dst = rng.choice(_EXTERNAL)
            fwd, bwd = rng.randint(4, 40), rng.randint(4, 64)
            size, dur = int(rng.lognormvariate(10.0, 1.2)), rng.uniform(0.05, 30)
        res = DetectionResult(
            src_ip=src, dst_ip=dst, src_port=rng.randint(49152, 65535) if port != 123 else 123,
            dst_port=port, protocol=proto, timestamp=sec + rng.random(),
            duration=dur, fwd_packets=fwd, bwd_packets=bwd, total_bytes=min(size, 2_500_000),
        )
        self._score(res, rng, BENIGN)
        return res

    def _attack(self, rng, sec, kind, src, dst, port, fwd, bwd, size, dur,
                proto: str = "TCP") -> DetectionResult:
        res = DetectionResult(
            src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 65535), dst_port=port,
            protocol=proto, timestamp=sec + rng.random(),
            duration=rng.uniform(*dur), fwd_packets=rng.randint(*fwd),
            bwd_packets=rng.randint(*bwd), total_bytes=rng.randint(*size),
        )
        self._score(res, rng, kind)
        return res

    def _score(self, res: DetectionResult, rng: random.Random, kind: _Kind) -> None:
        """Fill the model outputs the way DetectionEngine would for this mode."""
        sup = self.mode in ("supervised", "hybrid")
        unsup = self.mode in ("unsupervised", "hybrid")
        proba = rng.uniform(*kind.proba)
        iso = rng.random() < kind.iso
        ae = rng.random() < kind.ae
        if sup:
            res.supervised_proba = round(proba, 4)
            res.supervised_label = "ATTACK" if proba >= 0.5 else "BENIGN"
        if unsup:
            res.iso_anomaly = iso
            res.iso_score = round(rng.uniform(-0.12, -0.01) if iso else rng.uniform(0.02, 0.18), 4)
            res.ae_anomaly = ae
            factor = rng.uniform(1.1, 4.0) if ae else rng.uniform(0.05, 0.8)
            res.ae_error = round(AE_THRESHOLD * factor, 4)
        # same combination rule as DetectionEngine._combine
        sup_threat = res.supervised_label == "ATTACK"
        unsup_threat = bool(res.iso_anomaly) or bool(res.ae_anomaly)
        if self.mode == "supervised":
            res.is_threat, res.threat_score = sup_threat, res.supervised_proba or 0.0
        elif self.mode == "unsupervised":
            res.is_threat, res.threat_score = unsup_threat, 1.0 if unsup_threat else 0.0
        else:
            res.is_threat = sup_threat or unsup_threat
            res.threat_score = max(res.supervised_proba or 0.0, 1.0 if unsup_threat else 0.0)


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))
    limit, k, prod = math.exp(-lam), 0, rng.random()
    while prod > limit:
        k += 1
        prod *= rng.random()
    return k


# --------------------------------------------------------------------- #
class DemoPipeline(DetectionPipeline):
    """Synthetic traffic through the real scoring and alerting path."""

    kind = "demo"

    def __init__(self, mode: str = "hybrid", seed: int = 7, warm_seconds: float = WARM_START,
                 tick: float = 0.25) -> None:
        super().__init__()
        self.mode = mode
        self.seed = seed
        self.warm_seconds = warm_seconds
        self.tick = tick
        self.traffic: Optional[DemoTraffic] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        now = time.time()
        # a whole-second epoch keeps each generated second inside one phase of the cycle
        self.traffic = DemoTraffic(seed=self.seed, mode=self.mode, epoch=math.floor(now) - WARM_START)
        self.stats.started_at = now - self.warm_seconds
        for res in self.traffic.between(now - self.warm_seconds, now):
            self.emit(res, now=res.timestamp)
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(now,), name="Demo", daemon=True)
        self._thread.start()

    def _run(self, last: float) -> None:
        while not self._stop.wait(self.tick):
            now = time.time()
            for res in self.traffic.between(last, now):
                self.emit(res, now=res.timestamp)
            last = now

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
