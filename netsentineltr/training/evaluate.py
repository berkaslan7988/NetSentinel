"""NetSentinel — Birleşik değerlendirme & rapor (Faz 3).

Kaydedilmiş modelleri (RandomForest, IsolationForest, opsiyonel Autoencoder)
aynı test setinde değerlendirir; her biri için confusion matrix PNG'si ve
hepsini özetleyen bir markdown rapor üretir (reports/ altına).

Tutarlılık: prepare() aynı --files/--nrows/random_state ile eğitimdeki
train/test ayrımını ve scaler'ı BİREBİR yeniden üretir; bu yüzden kayıtlı
modeller doğru test seti üzerinde değerlendirilir.

Accuracy'ye GÜVENMEZ: rapor F1/precision/recall/FPR ve confusion matrix verir.

CLI:
    python -m training.evaluate                  # tüm CSV'ler
    python -m training.evaluate --nrows 60000 --files Wednesday-workingHours.pcap_ISCX.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from training.prepare_data import prepare  # noqa: E402

REPORTS_DIR = config.BASE_DIR / "reports"


def _metrics(y_test, y_pred, y_proba=None) -> dict:
    from sklearn.metrics import (
        confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
    )

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    auc = float("nan")
    if y_proba is not None:
        try:
            auc = roc_auc_score(y_test, y_proba)
        except Exception:
            pass
    return {
        "f1": f1_score(y_test, y_pred, zero_division=0),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "roc_auc": auc,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "cm": cm,
    }


def _save_confusion_png(cm, title: str, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")  # başsız (GUI yok)
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay

    fig, ax = plt.subplots(figsize=(4.5, 4))
    ConfusionMatrixDisplay(cm, display_labels=["BENIGN", "ATTACK"]).plot(
        ax=ax, cmap="Blues", colorbar=False
    )
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def eval_supervised(X_test, y_test, results: dict) -> None:
    import joblib
    if not config.SUPERVISED_MODEL_PATH.exists():
        print("[atla] supervised_rf.pkl yok.")
        return
    model = joblib.load(config.SUPERVISED_MODEL_PATH)
    y_pred = model.predict(X_test)
    proba = None
    try:
        proba = model.predict_proba(X_test)[:, 1]
    except Exception:
        pass
    m = _metrics(y_test, y_pred, proba)
    results["RandomForest"] = m
    _save_confusion_png(m["cm"], "RandomForest", REPORTS_DIR / "cm_random_forest.png")
    print(f"RandomForest      F1={m['f1']:.4f}  FPR=%{100*m['fpr']:.2f}")


def eval_isoforest(X_test, y_test, results: dict) -> None:
    import joblib
    if not config.ISOFOREST_MODEL_PATH.exists():
        print("[atla] isolation_forest.pkl yok.")
        return
    model = joblib.load(config.ISOFOREST_MODEL_PATH)
    y_pred = (model.predict(X_test) == -1).astype(int)
    m = _metrics(y_test, y_pred)
    results["IsolationForest"] = m
    _save_confusion_png(m["cm"], "IsolationForest", REPORTS_DIR / "cm_isolation_forest.png")
    print(f"IsolationForest   F1={m['f1']:.4f}  FPR=%{100*m['fpr']:.2f}")


def eval_autoencoder(X_test, y_test, results: dict) -> None:
    import json
    ae_path = config.MODELS_DIR / "autoencoder.pt"
    ae_meta = config.MODELS_DIR / "ae_meta.json"
    if not (ae_path.exists() and ae_meta.exists()):
        print("[atla] autoencoder.pt / ae_meta.json yok.")
        return
    try:
        import torch  # noqa: F401
    except Exception:
        print("[atla] torch yok; Autoencoder değerlendirilemiyor.")
        return
    from training.autoencoder import build_model, reconstruction_errors
    import torch

    meta = json.loads(ae_meta.read_text())
    model = build_model(meta["input_dim"])
    model.load_state_dict(torch.load(ae_path, map_location="cpu"))
    err = reconstruction_errors(model, X_test)
    y_pred = (err > meta["threshold"]).astype(int)
    m = _metrics(y_test, y_pred)
    results["Autoencoder"] = m
    _save_confusion_png(m["cm"], "Autoencoder", REPORTS_DIR / "cm_autoencoder.png")
    print(f"Autoencoder       F1={m['f1']:.4f}  FPR=%{100*m['fpr']:.2f}")


def write_report(results: dict, meta: dict) -> Path:
    lines = [
        "# NetSentinel — Model Değerlendirme Raporu",
        "",
        f"- Test örneği: **{meta['n_test']}**  "
        f"(BENIGN={meta['n_benign']}, ATTACK={meta['n_attack']})",
        f"- Veri: {meta['files']}",
        "",
        "## Metrikler",
        "",
        "| Model | F1 | Precision | Recall | ROC-AUC | FPR |",
        "|---|---|---|---|---|---|",
    ]
    for name, m in results.items():
        auc = "-" if np.isnan(m["roc_auc"]) else f"{m['roc_auc']:.4f}"
        lines.append(
            f"| {name} | {m['f1']:.4f} | {m['precision']:.4f} | "
            f"{m['recall']:.4f} | {auc} | {100*m['fpr']:.2f}% |"
        )
    lines += [
        "",
        "## Confusion Matrix Görselleri",
        "",
    ]
    mapping = {
        "RandomForest": "cm_random_forest.png",
        "IsolationForest": "cm_isolation_forest.png",
        "Autoencoder": "cm_autoencoder.png",
    }
    for name in results:
        if name in mapping:
            lines.append(f"### {name}\n\n![{name}]({mapping[name]})\n")
    lines += [
        "## Not",
        "",
        "Accuracy raporlanmaz; veri ~%82 BENIGN olduğundan yanıltıcıdır. "
        "Denetimli model bilinen saldırılarda güçlüdür; denetimsiz modeller "
        "(IsolationForest / Autoencoder) sıfır-gün benzeri tespit için olup "
        "daha düşük recall / daha yüksek FPR ile gelir.",
    ]
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORTS_DIR / "evaluation_report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Birleşik model değerlendirme")
    parser.add_argument("--nrows", type=int, default=None)
    parser.add_argument("--files", nargs="*", default=None)
    parser.add_argument("--pdf", action="store_true",
                        help="Ek olarak PDF rapor üret (reportlab gerekir)")
    args = parser.parse_args()

    X_train, X_test, y_train, y_test, scaler = prepare(files=args.files, nrows=args.nrows)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    results: dict = {}
    print("\n--- Değerlendirme ---")
    eval_supervised(X_test, y_test, results)
    eval_isoforest(X_test, y_test, results)
    eval_autoencoder(X_test, y_test, results)

    if not results:
        print("Hiç model bulunamadı. Önce train_* scriptlerini çalıştır.")
        return 1

    meta = {
        "n_test": int(len(y_test)),
        "n_benign": int((y_test == 0).sum()),
        "n_attack": int((y_test == 1).sum()),
        "files": args.files or "tümü",
    }
    report = write_report(results, meta)
    print(f"\nRapor: {report}")
    print(f"PNG'ler: {REPORTS_DIR}")

    if args.pdf:
        try:
            from reporting.report_pdf import build_evaluation_pdf
            pdf = build_evaluation_pdf(
                REPORTS_DIR / "evaluation_report.pdf", results, meta, REPORTS_DIR
            )
            print(f"PDF: {pdf}")
        except Exception as exc:
            print(f"[uyarı] PDF üretilemedi ({exc}). `pip install reportlab`?")
    return 0


if __name__ == "__main__":
    sys.exit(main())
