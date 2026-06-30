"""NetSentinel - Unsupervised model training (Phase 3).

Trains an IsolationForest on BENIGN traffic ONLY; catches attacks as outliers.
This is the first leg of the project's "zero-day-like / unlabeled" detection
claim (the Autoencoder is added next).

Logic:
  * Training: only y_train == 0 (BENIGN) samples. The model learns "normal".
  * Prediction: IsolationForest predict() -> +1 normal, -1 anomaly. We map this
    to 0=BENIGN / 1=ATTACK.
  * `contamination`: expected anomaly ratio (threshold tuning).

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

    # predict: +1 normal, -1 anomaly -> 1=ATTACK, 0=BENIGN
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

    print("\n=== Unsupervised (IsolationForest) Evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"],
                                zero_division=0))
    print(f"F1={metrics['f1']:.4f}  Precision={metrics['precision']:.4f}  "
          f"Recall={metrics['recall']:.4f}")
    print(f"Confusion matrix [TN={tn} FP={fp} FN={fn} TP={tp}]  "
          f"False Positive Rate={100 * fpr:.2f}%")
    metrics["fpr"] = fpr
    metrics["confusion_matrix"] = cm.tolist()
    return metrics


def train(X_train, y_train, contamination=0.1, n_estimators=100, random_state=None):
    """Trains IsolationForest on BENIGN samples ONLY."""
    from sklearn.ensemble import IsolationForest

    random_state = random_state if random_state is not None else config.RANDOM_STATE
    X_benign = X_train[y_train == 0]
    print(f"Training IsolationForest (BENIGN only, {len(X_benign)} samples, "
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

    parser = argparse.ArgumentParser(description="Unsupervised IsolationForest training")
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
    print(f"\nSaved:\n  {config.ISOFOREST_MODEL_PATH}\n  {config.SCALER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
