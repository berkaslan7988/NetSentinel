"""NetSentinel — Risk skorlama (Faz 5).

Ham model çıktısını (DetectionResult) 0-100 birleşik risk skoruna ve severity
seviyesine çevirir.

Tasarım amacı — AE false positive selini bastırmak:
  * Denetimli (RF) baskındır (ağırlık 0.75). RF canlı/eğitim dağılım farkına
    dayanıklıdır; "normal" trafikte güvenle düşük olasılık verir.
  * Denetimsiz sinyaller (IsolationForest + Autoencoder) DESTEKLEYİCİDİR
    (ağırlık 0.25) ve **mutabakat** ile ölçülür:
        - ikisi de anomali  -> 1.0  (gerçek aday)
        - yalnız biri       -> 0.3  (büyük olasılıkla gürültü; tek AE bayrağı
                                       artık tek başına THREAT yapmaz)
        - hiçbiri           -> 0.0
  Böylece RF'in BENIGN dediği, yalnız AE'nin patladığı akışlar düşük riskte
  kalır ve alarm üretmez.

Örnek (kullanıcının canlı loglarından):
  RF=0.05, yalnız AE anomali  -> risk = 75*0.05 + 25*0.30 = 11.25  (LOW, alarm yok)
  RF=0.05, AE+ISO anomali     -> risk = 75*0.05 + 25*1.00 = 28.75  (MEDIUM)
  RF=0.95 (bilinen saldırı)   -> risk = 75*0.95 + ...      >= 71    (HIGH/CRITICAL)
"""
from __future__ import annotations

from enum import Enum

import config
from detection.result import DetectionResult


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Renk kodu (UI/terminal için) — yüksekten düşüğe
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def severity_for(score: float, thresholds: dict = None) -> Severity:
    """0-100 skoru severity seviyesine eşler."""
    th = thresholds or config.SEVERITY_THRESHOLDS
    if score >= th["CRITICAL"]:
        return Severity.CRITICAL
    if score >= th["HIGH"]:
        return Severity.HIGH
    if score >= th["MEDIUM"]:
        return Severity.MEDIUM
    return Severity.LOW


class RiskScorer:
    def __init__(
        self,
        w_supervised: float = None,
        w_unsupervised: float = None,
        unsup_both: float = None,
        unsup_one: float = None,
        thresholds: dict = None,
    ) -> None:
        self.w_sup = w_supervised if w_supervised is not None else config.RISK_WEIGHT_SUPERVISED
        self.w_unsup = w_unsupervised if w_unsupervised is not None else config.RISK_WEIGHT_UNSUPERVISED
        self.unsup_both = unsup_both if unsup_both is not None else config.RISK_UNSUP_BOTH
        self.unsup_one = unsup_one if unsup_one is not None else config.RISK_UNSUP_ONE
        self.thresholds = thresholds or config.SEVERITY_THRESHOLDS

    def unsup_signal(self, res: DetectionResult) -> float:
        """Denetimsiz mutabakat katkısı (0..1). Yalnız mevcut modelleri sayar."""
        n_anom = 0
        if res.iso_anomaly:   # None veya False -> sayma
            n_anom += 1
        if res.ae_anomaly:
            n_anom += 1
        if n_anom >= 2:
            return self.unsup_both
        if n_anom == 1:
            return self.unsup_one
        return 0.0

    def score(self, res: DetectionResult) -> float:
        """0-100 birleşik risk skoru."""
        sup = res.supervised_proba if res.supervised_proba is not None else 0.0
        unsup = self.unsup_signal(res)
        raw = self.w_sup * sup + self.w_unsup * unsup
        return round(max(0.0, min(1.0, raw)) * 100, 2)

    def severity(self, score: float) -> Severity:
        return severity_for(score, self.thresholds)
