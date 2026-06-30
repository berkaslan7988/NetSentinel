"""NetSentinel — Denetimli model eğitimi (Faz 3).

CIC-IDS2017 üzerinde RandomForest sınıflandırıcı eğitir (bilinen saldırı tespiti).
Class imbalance `class_weight="balanced"` ile ele alınır. Accuracy'ye GÜVENMEZ —
F1/recall/ROC-AUC ve confusion matrix raporlar (veri %80+ BENIGN olduğu için
accuracy yanıltıcıdır).

Model + scaler joblib ile kaydedilir; Faz 4 inference bunları yükler.

CLI:
    python -m training.train_supervised                  # tüm CSV'ler
    python -m training.train_supervised --nrows 50000    # hızlı test
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from features.columns import FEATURE_COLUMNS  # noqa: E402
from training.prepare_data import prepare  # noqa: E402


def evaluate(model, X_test, y_test) -> dict:
    """F1/precision/recall/ROC-AUC + confusion matrix hesaplar ve basar."""
    from sklearn.metrics import (
        classification_report, confusion_matrix, f1_score,
        precision_score, recall_score, roc_auc_score,
    )

    y_pred = model.predict(X_test)
    try:
        y_proba = model.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, y_proba)
    except Exception:
        auc = float("nan")

    metrics = {
        "f1": f1_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "roc_auc": auc,
    }
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print("\n=== Denetimli (RandomForest) Değerlendirme ===")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))
    print(f"F1={metrics['f1']:.4f}  Precision={metrics['precision']:.4f}  "
          f"Recall={metrics['recall']:.4f}  ROC-AUC={metrics['roc_auc']:.4f}")
    print(f"Confusion matrix [TN={tn} FP={fp} FN={fn} TP={tp}]  "
          f"False Positive Rate=%{100 * fpr:.2f}")
    metrics["fpr"] = fpr
    metrics["confusion_matrix"] = cm.tolist()
    return metrics


def top_feature_importance(model, k: int = 15) -> None:
    """En ayırt edici k özelliği basar."""
    if not hasattr(model, "feature_importances_"):
        return
    order = np.argsort(model.feature_importances_)[::-1][:k]
    print(f"\n--- En önemli {k} özellik ---")
    for i in order:
        print(f"  {FEATURE_COLUMNS[i]:32s} {model.feature_importances_[i]:.4f}")


def train(X_train, y_train, n_estimators: int = 100, random_state: int = None):
    from sklearn.ensemble import RandomForestClassifier

    random_state = random_state if random_state is not None else config.RANDOM_STATE
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",   # class imbalance
        n_jobs=-1,
        random_state=random_state,
    )
    print(f"RandomForest eğitiliyor (n_estimators={n_estimators})...")
    model.fit(X_train, y_train)
    return model


def main() -> int:
    import joblib

    parser = argparse.ArgumentParser(description="Denetimli RF eğitimi")
    parser.add_argument("--nrows", type=int, default=None)
    parser.add_argument("--files", nargs="*", default=None)
    parser.add_argument("--n-estimators", type=int, default=100)
    args = parser.parse_args()

    X_train, X_test, y_train, y_test, scaler = prepare(
        files=args.files, nrows=args.nrows
    )
    model = train(X_train, y_train, n_estimators=args.n_estimators)
    evaluate(model, X_test, y_test)
    top_feature_importance(model)

    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, config.SUPERVISED_MODEL_PATH)
    joblib.dump(scaler, config.SCALER_PATH)
    print(f"\nKaydedildi:\n  {config.SUPERVISED_MODEL_PATH}\n  {config.SCALER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
