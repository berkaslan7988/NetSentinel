"""NetSentinel — DetectionEngine (Faz 4).

Faz 3'te eğitilen modelleri + scaler'ı **bir kez** yükler ve canlı akışları
tahmin eder. Capture -> Flow -> Feature -> **Detection** zincirinin son halkası.

Kritik kurallar (roadmap, Faz 4 tuzakları):
  * Modeller bir kez yüklenir, bellekte tutulur (her akışta diskten yükleme YOK).
  * Canlı feature vektörü, eğitimle **aynı** FEATURE_COLUMNS sırasında üretilir
    (FeatureExtractor.extract_vector) ve **aynı** scaler'dan geçirilir. Uyuşmazlık
    en sık canlı-çökme sebebidir.
  * Autoencoder opsiyoneldir (torch yoksa ya da model dosyası yoksa atlanır).

Modlar:
  * "supervised"   : yalnız RandomForest.
  * "unsupervised" : IsolationForest ve/veya Autoencoder.
  * "hybrid"       : ikisi birden; biri bile tehdit derse threat.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional, Sequence

import numpy as np

import config
from detection.result import DetectionResult
from features.columns import FEATURE_COLUMNS
from features.extractor import FeatureExtractor
from flows.flow import Flow

VALID_MODES = ("supervised", "unsupervised", "hybrid")


class DetectionEngine:
    def __init__(
        self,
        mode: str = "hybrid",
        model_dir: Optional[Path] = None,
        scaler_path: Optional[Path] = None,
        supervised_path: Optional[Path] = None,
        iso_path: Optional[Path] = None,
        ae_path: Optional[Path] = None,
        ae_meta_path: Optional[Path] = None,
        load_ae: bool = True,
    ) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode {mode} geçersiz; {VALID_MODES}")
        self.mode = mode
        self.extractor = FeatureExtractor()

        md = Path(model_dir) if model_dir else config.MODELS_DIR
        self._scaler_path = Path(scaler_path) if scaler_path else (md / "scaler.pkl")
        self._sup_path = Path(supervised_path) if supervised_path else (md / "supervised_rf.pkl")
        self._iso_path = Path(iso_path) if iso_path else (md / "isolation_forest.pkl")
        self._ae_path = Path(ae_path) if ae_path else (md / "autoencoder.pt")
        self._ae_meta_path = Path(ae_meta_path) if ae_meta_path else (md / "ae_meta.json")

        self.scaler = None
        self.supervised = None
        self.iso = None
        self.ae = None
        self.ae_threshold: Optional[float] = None
        self._load(load_ae=load_ae)

    # ----------------------------------------------------------------- #
    def _load(self, load_ae: bool) -> None:
        import joblib

        if self._scaler_path.exists():
            self.scaler = joblib.load(self._scaler_path)
        else:
            raise FileNotFoundError(
                f"scaler bulunamadı: {self._scaler_path}. Önce Faz 3 eğitimini çalıştır."
            )

        if self.mode in ("supervised", "hybrid") and self._sup_path.exists():
            self.supervised = joblib.load(self._sup_path)
        if self.mode in ("unsupervised", "hybrid") and self._iso_path.exists():
            self.iso = joblib.load(self._iso_path)

        if load_ae and self.mode in ("unsupervised", "hybrid"):
            self._try_load_ae()

        loaded = [n for n, m in (("RF", self.supervised), ("ISO", self.iso),
                                 ("AE", self.ae)) if m is not None]
        if not loaded:
            raise RuntimeError(
                f"'{self.mode}' modu için hiç model yüklenemedi. "
                f"models/ içinde uygun .pkl/.pt var mı?"
            )
        print(f"[DetectionEngine] mod={self.mode}, yüklenen modeller: {', '.join(loaded)}")

    def _try_load_ae(self) -> None:
        if not (self._ae_path.exists() and self._ae_meta_path.exists()):
            return
        try:
            import torch
            from training.autoencoder import build_model
        except Exception:
            print("[DetectionEngine] torch yok; Autoencoder atlanıyor.")
            return
        meta = json.loads(self._ae_meta_path.read_text())
        model = build_model(meta["input_dim"])
        model.load_state_dict(torch.load(self._ae_path, map_location="cpu"))
        model.eval()
        self.ae = model
        self.ae_threshold = float(meta["threshold"])

    # ----------------------------------------------------------------- #
    def _scale(self, vec: Sequence[float]) -> np.ndarray:
        arr = np.asarray(vec, dtype=np.float64).reshape(1, -1)
        return self.scaler.transform(arr)

    def predict_vector(
        self, vec: Sequence[float], identity: Optional[dict] = None
    ) -> DetectionResult:
        """78 elemanlı (FEATURE_COLUMNS sırasında) bir vektörden tahmin üretir."""
        if len(vec) != len(FEATURE_COLUMNS):
            raise ValueError(
                f"vektör uzunluğu {len(vec)}, beklenen {len(FEATURE_COLUMNS)}"
            )
        X = self._scale(vec)
        identity = identity or {}
        res = DetectionResult(
            src_ip=identity.get("src_ip", ""),
            dst_ip=identity.get("dst_ip", ""),
            src_port=identity.get("src_port", 0),
            dst_port=identity.get("dst_port", 0),
            protocol=identity.get("protocol", ""),
            timestamp=identity.get("timestamp", 0.0),
        )

        if self.supervised is not None:
            proba = float(self.supervised.predict_proba(X)[0, 1])
            res.supervised_proba = proba
            res.supervised_label = "ATTACK" if proba >= 0.5 else "BENIGN"

        if self.iso is not None:
            res.iso_score = float(self.iso.decision_function(X)[0])
            res.iso_anomaly = bool(self.iso.predict(X)[0] == -1)

        if self.ae is not None:
            import torch
            with torch.no_grad():
                t = torch.as_tensor(X, dtype=torch.float32)
                recon = self.ae(t)
                err = float(((recon - t) ** 2).mean().item())
            res.ae_error = err
            res.ae_anomaly = err > self.ae_threshold

        self._combine(res)
        return res

    def predict_flow(self, flow: Flow) -> DetectionResult:
        """Bir Flow'dan özellik çıkarıp tahmin üretir."""
        vec = self.extractor.extract_vector(flow)
        identity = {
            "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
            "src_port": flow.src_port, "dst_port": flow.dst_port,
            "protocol": flow.protocol, "timestamp": flow.start_time,
        }
        res = self.predict_vector(vec, identity)
        # Akış istatistiklerini ekle (storage/raporlama için)
        res.duration = flow.duration
        res.fwd_packets = flow.fwd_packet_count
        res.bwd_packets = flow.bwd_packet_count
        res.total_bytes = flow.total_bytes
        return res

    # ----------------------------------------------------------------- #
    def _combine(self, res: DetectionResult) -> None:
        """Moda göre basit birleşik karar. Faz 5 bunu 0-100 risk skoruna çevirir."""
        sup_threat = res.supervised_label == "ATTACK"
        unsup_threat = bool(res.iso_anomaly) or bool(res.ae_anomaly)

        if self.mode == "supervised":
            res.is_threat = sup_threat
            res.threat_score = res.supervised_proba or 0.0
        elif self.mode == "unsupervised":
            res.is_threat = unsup_threat
            res.threat_score = 1.0 if unsup_threat else 0.0
        else:  # hybrid
            res.is_threat = sup_threat or unsup_threat
            # basit: denetimli olasılık ile denetimsiz bayrağın maksimumu
            res.threat_score = max(
                res.supervised_proba or 0.0,
                1.0 if unsup_threat else 0.0,
            )
