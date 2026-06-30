"""NetSentinel — Denetimsiz model eğitimi (Faz 3).

IsolationForest'ı YALNIZCA BENIGN trafikle eğitir; saldırıyı outlier olarak
yakalar. Bu, projenin "sıfır-gün benzeri / etiketsiz" tespit iddiasının ilk
ayağıdır (Autoencoder sonraki adımda eklenecek).

Mantık:
  * Eğitim: sadece y_train == 0 (BENIGN) örnekleri. Model "normal"i öğrenir.
  * Tahmin: IsolationForest predict() -> +1 normal, -1 anomali. Bunu
    0=BENIGN / 1=ATTACK'a çeviririz.
  * `contamination`: beklenen anomali oranı (eşik ayarı).

CLI:
    python -m training.train_unsupervised --nrows 50000
    python -m training.train_unsupervised --contamination 0.1
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from training.prepare_data import prepare  # noqa: E402


def evaluate(model, X_test, y_test) -> dict:
    from sklearn.metrics import (
        classification_report, confusion_matrix, f1_score,
        precision_score, recall_score,
    )

    # predict: +1 normal, -1 anomali -> 1=ATTACK, 0=BENIGN
    raw = model.predict(X_test)
    y_pred = (raw == -1).astype(int)

    metrics = {
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
    }
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print("\n=== Denetimsiz (IsolationForest) Değerlendirme ===")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"],
                                zero_division=0))
    print(f"F1={metrics['f1']:.4f}  Precision={metrics['precision']:.4f}  "
          f"Recall={metrics['recall']:.4f}")
    print(f"Confusion matrix [TN={tn} FP={fp} FN={fn} TP={tp}]  "
          f"False Positive Rate=%{100 * fpr:.2f}")
    metrics["fpr"] = fpr
    metrics["confusion_matrix"] = cm.tolist()
    return metrics


def train(X_train, y_train, contamination=0.1, n_estimators=100, random_state=None):
    """SADECE BENIGN örneklerle IsolationForest eğitir."""
    from sklearn.ensemble import IsolationForest

    random_state = random_state if random_state is not None else config.RANDOM_STATE
    X_benign = X_train[y_train == 0]
    print(f"IsolationForest eğitiliyor (yalnız {len(X_benign)} BENIGN örnek, "
          f"contamination={contamination})...")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        n_jobs=-1,
        random_state=random_state,
    )
    model.fit(X_benign)
    return model


def main() -> int:
    import joblib

    parser = argparse.ArgumentParser(description="Denetimsiz IsolationForest eğitimi")
    parser.add_argument("--nrows", type=int, default=None)
    parser.add_argument("--files", nargs="*", default=None)
    parser.add_argument("--contamination", type=float, default=0.1)
    parser.add_argument("--n-estimators", type=int, default=100)
    args = parser.parse_args()

    X_train, X_test, y_train, y_test, scaler = prepare(
        files=args.files, nrows=args.nrows
    )
    model = train(X_train, y_train, contamination=args.contamination,
                  n_estimators=args.n_estimators)
    evaluate(model, X_test, y_test)

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, config.ISOFOREST_MODEL_PATH)
    joblib.dump(scaler, config.SCALER_PATH)
    print(f"\nKaydedildi:\n  {config.ISOFOREST_MODEL_PATH}\n  {config.SCALER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
