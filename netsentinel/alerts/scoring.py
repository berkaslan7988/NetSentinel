"""NetSentinel - Risk scoring (Phase 5).

Turns raw model output (DetectionResult) into a 0-100 combined risk score and a
severity level.

Design goal - suppress the AE false-positive flood:
  * Supervised (RF) is dominant (weight 0.75). RF is robust to the live/training
    distribution gap; it confidently gives low probability on "normal" traffic.
  * Unsupervised signals (IsolationForest + Autoencoder) are SUPPORTING
    (weight 0.25), measured by AGREEMENT:
        - both anomalous -> 1.0  (a real candidate)
        - only one       -> 0.3  (likely noise; a single AE flag alone no longer
                                   makes a THREAT)
        - none           -> 0.0
  So flows where RF says BENIGN and only AE blows up stay low-risk and raise no
  alert.

Example (from the user's live logs):
  RF=0.05, only AE anomalous  -> risk = 75*0.05 + 25*0.30 = 11.25  (LOW, no alert)
  RF=0.05, AE+ISO anomalous   -> risk = 75*0.05 + 25*1.00 = 28.75  (MEDIUM)
  RF=0.95 (known attack)      -> risk = 75*0.95 + ...      >= 71    (HIGH/CRITICAL)
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


# Color order (for UI/terminal) - low to high
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def severity_for(score: float, thresholds: dict = None) -> Severity:
    """Maps a 0-100 score to a severity level."""
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
        """Unsupervised agreement contribution (0..1). Counts only present models."""
        n_anom = 0
        if res.iso_anomaly:   # None or False -> don't count
            n_anom += 1
        if res.ae_anomaly:
            n_anom += 1
        if n_anom >= 2:
            return self.unsup_both
        if n_anom == 1:
            return self.unsup_one
        return 0.0

    def score(self, res: DetectionResult) -> float:
        """0-100 combined risk score."""
        sup = res.supervised_proba if res.supervised_proba is not None else 0.0
        unsup = self.unsup_signal(res)
        raw = self.w_sup * sup + self.w_unsup * unsup
        return round(max(0.0, min(1.0, raw)) * 100, 2)

    def severity(self, score: float) -> Severity:
        return severity_for(score, self.thresholds)
