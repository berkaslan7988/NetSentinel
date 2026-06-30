"""NetSentinel — Değerlendirme raporu PDF üretici (Faz 9).

training/evaluate.py'nin ürettiği metrikleri + confusion matrix PNG'lerini ve
(varsa) benchmark sonuçlarını tek bir PDF rapora derler. reportlab gerektirir
(`pip install reportlab`).

evaluate.py `--pdf` ile bu modülü çağırır; bağımsız da kullanılabilir.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

# Severity yerine model adına göre sabit PNG eşlemesi (evaluate ile aynı)
_PNG_MAP = {
    "RandomForest": "cm_random_forest.png",
    "IsolationForest": "cm_isolation_forest.png",
    "Autoencoder": "cm_autoencoder.png",
}


def build_evaluation_pdf(
    out_path: Path,
    results: Dict[str, dict],
    meta: dict,
    reports_dir: Path,
    benchmark: Optional[dict] = None,
) -> Path:
    """Metrik tablosu + confusion matrix görselleri + benchmark içeren PDF üretir."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    styles = getSampleStyleSheet()
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out_path), pagesize=A4,
                            title="NetSentinel — Değerlendirme Raporu")
    story = []

    story.append(Paragraph("NetSentinel — Değerlendirme Raporu", styles["Title"]))
    story.append(Paragraph(
        f"Test örneği: <b>{meta.get('n_test', '?')}</b> "
        f"(BENIGN={meta.get('n_benign', '?')}, ATTACK={meta.get('n_attack', '?')}) · "
        f"Veri: {meta.get('files', 'tümü')}", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Metrik tablosu
    story.append(Paragraph("Model Metrikleri", styles["Heading2"]))
    head = ["Model", "F1", "Precision", "Recall", "ROC-AUC", "FPR"]
    rows = [head]
    for name, m in results.items():
        auc = "-" if m.get("roc_auc") is None or _isnan(m.get("roc_auc")) else f"{m['roc_auc']:.4f}"
        rows.append([
            name, f"{m['f1']:.4f}", f"{m['precision']:.4f}",
            f"{m['recall']:.4f}", auc, f"{100 * m['fpr']:.2f}%",
        ])
    table = Table(rows, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f9a3f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef7ee")]),
    ]))
    story.append(table)
    story.append(Paragraph(
        "<i>Not: Accuracy raporlanmaz; veri ~%82 BENIGN olduğundan yanıltıcıdır.</i>",
        styles["Italic"]))
    story.append(Spacer(1, 0.5 * cm))

    # Benchmark (opsiyonel)
    if benchmark:
        story.append(Paragraph("Performans", styles["Heading2"]))
        story.append(Paragraph(
            f"Inference ortalama <b>{benchmark.get('mean_ms', 0):.2f} ms</b> "
            f"(p95 {benchmark.get('p95_ms', 0):.2f} ms, "
            f"p99 {benchmark.get('p99_ms', 0):.2f} ms) → "
            f"<b>{benchmark.get('throughput_fps', 0):.0f} akış/sn</b>.",
            styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

    # Confusion matrix görselleri
    story.append(Paragraph("Confusion Matrix", styles["Heading2"]))
    for name in results:
        png = reports_dir / _PNG_MAP.get(name, "")
        if png.exists():
            story.append(Paragraph(name, styles["Heading3"]))
            story.append(Image(str(png), width=8 * cm, height=7 * cm))
            story.append(Spacer(1, 0.3 * cm))

    doc.build(story)
    return out_path


def _isnan(x) -> bool:
    try:
        return x != x
    except Exception:
        return False
