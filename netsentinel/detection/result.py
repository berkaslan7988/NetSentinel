"""NetSentinel - DetectionResult (Phase 4).

A UI/storage-independent data structure carrying a flow's prediction result.
Produced by the DetectionEngine; consumed by Phase 5 (alerts) and Phase 7 (UI).

Signals:
  * supervised_label/proba : RandomForest - known-attack prediction.
  * iso_anomaly/iso_score  : IsolationForest - is it an outlier? (low score = anomalous)
  * ae_error/ae_anomaly    : Autoencoder reconstruction error vs threshold.
  * is_threat/threat_score : simple combined decision per the selected mode
    (0..1). Phase 5 turns this into a 0-100 risk score and severity.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    # --- flow identity ---
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: float

    # --- flow stats (for storage/reporting; filled by predict_flow) ---
    duration: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    total_bytes: int = 0

    # --- supervised ---
    supervised_label: Optional[str] = None      # "BENIGN" / "ATTACK"
    supervised_proba: Optional[float] = None     # attack probability 0..1

    # --- unsupervised: IsolationForest ---
    iso_anomaly: Optional[bool] = None
    iso_score: Optional[float] = None            # decision_function (negative = anomalous)

    # --- unsupervised: Autoencoder ---
    ae_error: Optional[float] = None
    ae_anomaly: Optional[bool] = None

    # --- combined decision (refined by Phase 5) ---
    is_threat: bool = False
    threat_score: float = 0.0                    # 0..1

    def summary(self) -> str:
        parts = [
            f"{self.protocol} {self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port}"
        ]
        if self.supervised_label is not None:
            parts.append(f"{self.supervised_label} ({self.supervised_proba:.2f})")
        if self.ae_error is not None:
            flag = "anomalous" if self.ae_anomaly else "normal"
            parts.append(f"AE err {self.ae_error:.3f} ({flag})")
        if self.iso_score is not None:
            flag = "anomalous" if self.iso_anomaly else "normal"
            parts.append(f"ISO {self.iso_score:.3f} ({flag})")
        verdict = "THREAT" if self.is_threat else "ok"
        parts.append(f"[{verdict} {self.threat_score:.2f}]")
        return " | ".join(parts)
