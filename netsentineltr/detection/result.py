"""NetSentinel — DetectionResult (Faz 4).

Bir akışın tahmin sonucunu taşıyan UI/storage-bağımsız veri yapısı.
DetectionEngine üretir; Faz 5 (alarm) ve Faz 7 (UI) tüketir.

Sinyaller:
  * supervised_label/proba : RandomForest — bilinen saldırı tahmini.
  * iso_anomaly/iso_score  : IsolationForest — outlier mi? (score düşük = anormal)
  * ae_error/ae_anomaly    : Autoencoder reconstruction error ve eşik kıyası.
  * is_threat/threat_score : seçilen moda göre birleşik basit karar
    (0..1). Faz 5 bunu 0-100 risk skoruna ve severity'ye dönüştürür.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    # --- akış kimliği ---
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: float

    # --- akış istatistikleri (storage/raporlama için; predict_flow doldurur) ---
    duration: float = 0.0
    fwd_packets: int = 0
    bwd_packets: int = 0
    total_bytes: int = 0

    # --- denetimli ---
    supervised_label: Optional[str] = None      # "BENIGN" / "ATTACK"
    supervised_proba: Optional[float] = None     # saldırı olasılığı 0..1

    # --- denetimsiz: IsolationForest ---
    iso_anomaly: Optional[bool] = None
    iso_score: Optional[float] = None            # decision_function (negatif = anormal)

    # --- denetimsiz: Autoencoder ---
    ae_error: Optional[float] = None
    ae_anomaly: Optional[bool] = None

    # --- birleşik karar (Faz 5 detaylandırır) ---
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
            flag = "anormal" if self.ae_anomaly else "normal"
            parts.append(f"AE err {self.ae_error:.3f} ({flag})")
        if self.iso_score is not None:
            flag = "anormal" if self.iso_anomaly else "normal"
            parts.append(f"ISO {self.iso_score:.3f} ({flag})")
        verdict = "THREAT" if self.is_threat else "ok"
        parts.append(f"[{verdict} {self.threat_score:.2f}]")
        return " | ".join(parts)
