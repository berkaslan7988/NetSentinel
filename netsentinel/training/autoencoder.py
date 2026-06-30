"""NetSentinel - Autoencoder (PyTorch) training (Phase 3).

The second leg of unsupervised detection: a dense autoencoder trained on BENIGN
traffic only. The model learns what "normal" looks like; at inference a high
reconstruction error -> anomaly (zero-day-like detection).

Architecture:  78 -> 32 -> 8 -> 32 -> 78  (ReLU, linear output layer since the
input is standardized).

Threshold: the (default) 99th percentile of the BENIGN reconstruction-error
distribution. This value is saved; at inference error > threshold -> ATTACK.

NOTE: requires torch (`pip install torch`). Run on a machine with torch.

CLI:
    python -m training.autoencoder --epochs 20
    python -m training.autoencoder --nrows 50000 --percentile 99
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from features.columns import FEATURE_COLUMNS  # noqa: E402
from training.prepare_data import prepare  # noqa: E402

AE_MODEL_PATH = config.MODELS_DIR / "autoencoder.pt"
AE_META_PATH = config.MODELS_DIR / "ae_meta.json"

INPUT_DIM = len(FEATURE_COLUMNS)  # 78


def _require_torch():
    try:
        import torch  # noqa: F401
        return True
    except Exception:
        print("[ERROR] PyTorch is not installed. `pip install torch` required.")
        return False


def build_model(input_dim: int = INPUT_DIM):
    """78 -> 32 -> 8 -> 32 -> 78 dense autoencoder."""
    import torch.nn as nn

    return nn.Sequential(
        nn.Linear(input_dim, 32), nn.ReLU(),
        nn.Linear(32, 8), nn.ReLU(),
        nn.Linear(8, 32), nn.ReLU(),
        nn.Linear(32, input_dim),  # linear output
    )


def reconstruction_errors(model, X) -> np.ndarray:
    """Per-sample MSE reconstruction error (numpy array)."""
    import torch

    model.eval()
    with torch.no_grad():
        t = torch.as_tensor(X, dtype=torch.float32)
        recon = model(t)
        err = ((recon - t) ** 2).mean(dim=1)
    return err.cpu().numpy()


def train_autoencoder(X_benign, epochs=20, batch_size=256, lr=1e-3, seed=None):
    """Trains the AE on BENIGN samples only."""
    import torch
    from torch.utils.data import DataLoader, TensorDataset

    if seed is None:
        seed = config.RANDOM_STATE
    torch.manual_seed(seed)

    model = build_model(X_benign.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = torch.nn.MSELoss()

    ds = TensorDataset(torch.as_tensor(X_benign, dtype=torch.float32))
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

    print(f"Training AE: {len(X_benign)} BENIGN samples, {epochs} epochs...")
    model.train()
    for epoch in range(1, epochs + 1):
        total = 0.0
        for (batch,) in loader:
            opt.zero_grad()
            out = model(batch)
            loss = loss_fn(out, batch)
            loss.backward()
            opt.step()
            total += loss.item() * len(batch)
        if epoch == 1 or epoch % 5 == 0 or epoch == epochs:
            print(f"  epoch {epoch:3d}/{epochs}  loss={total / len(X_benign):.6f}")
    return model


def evaluate(model, X_test, y_test, threshold) -> dict:
    from sklearn.metrics import (
        classification_report, confusion_matrix, f1_score,
        precision_score, recall_score,
    )

    err = reconstruction_errors(model, X_test)
    y_pred = (err > threshold).astype(int)

    metrics = {
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
    }
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    print("\n=== Unsupervised (Autoencoder) Evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"],
                                zero_division=0))
    print(f"F1={metrics['f1']:.4f}  Precision={metrics['precision']:.4f}  "
          f"Recall={metrics['recall']:.4f}")
    print(f"Confusion matrix [TN={tn} FP={fp} FN={fn} TP={tp}]  "
          f"False Positive Rate={100 * fpr:.2f}%")
    metrics["fpr"] = fpr
    metrics["confusion_matrix"] = cm.tolist()
    return metrics


def main() -> int:
    if not _require_torch():
        return 1
    import joblib
    import torch

    parser = argparse.ArgumentParser(description="Autoencoder training")
    parser.add_argument("--nrows", type=int, default=None)
    parser.add_argument("--files", nargs="*", default=None)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--percentile", type=float, default=99.0,
                        help="BENIGN error percentile for the threshold")
    args = parser.parse_args()

    X_train, X_test, y_train, y_test, scaler = prepare(files=args.files, nrows=args.nrows)
    X_benign = X_train[y_train == 0]

    model = train_autoencoder(X_benign, epochs=args.epochs, batch_size=args.batch_size)

    # Threshold: a percentile of the BENIGN reconstruction-error distribution
    benign_err = reconstruction_errors(model, X_benign)
    threshold = float(np.percentile(benign_err, args.percentile))
    print(f"\nThreshold (BENIGN {args.percentile}th percentile) = {threshold:.6f}")

    evaluate(model, X_test, y_test, threshold)

    # Save
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), AE_MODEL_PATH)
    meta = {
        "input_dim": int(X_benign.shape[1]),
        "architecture": [INPUT_DIM, 32, 8, 32, INPUT_DIM],
        "threshold": threshold,
        "percentile": args.percentile,
    }
    AE_META_PATH.write_text(json.dumps(meta, indent=2))
    joblib.dump(scaler, config.SCALER_PATH)  # scaler consistent with training
    print(f"\nSaved:\n  {AE_MODEL_PATH}\n  {AE_META_PATH}\n  {config.SCALER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
