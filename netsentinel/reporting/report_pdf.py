"""NetSentinel - Evaluation report PDF builder (Phase 9).

Compiles the metrics produced by training/evaluate.py + the confusion matrix
PNGs and (optionally) benchmark results into a single PDF report. Requires
reportlab (`pip install reportlab`).

evaluate.py calls this module via `--pdf`; it can also be used standalone.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

# Fixed PNG mapping by model name (same as evaluate)
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
    """Produces a PDF with a metrics table + confusion matrix images + benchmark."""
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
                            title="NetSentinel - Evaluation Report")
    story = []

    story.append(Paragraph("NetSentinel - Evaluation Report", styles["Title"]))
    story.append(Paragraph(
        f"Test samples: <b>{meta.get('n_test', '?')}</b> "
        f"(BENIGN={meta.get('n_benign', '?')}, ATTACK={meta.get('n_attack', '?')}) - "
        f"Data: {meta.get('files', 'all')}", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Metrics table
    story.append(Paragraph("Model Metrics", styles["Heading2"]))
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
        "<i>Note: accuracy is not reported; with ~82% BENIGN it is misleading.</i>",
        styles["Italic"]))
    story.append(Spacer(1, 0.5 * cm))

    # Benchmark (optional)
    if benchmark:
        story.append(Paragraph("Performance", styles["Heading2"]))
        story.append(Paragraph(
            f"Inference mean <b>{benchmark.get('mean_ms', 0):.2f} ms</b> "
            f"(p95 {benchmark.get('p95_ms', 0):.2f} ms, "
            f"p99 {benchmark.get('p99_ms', 0):.2f} ms) -> "
            f"<b>{benchmark.get('throughput_fps', 0):.0f} flows/s</b>.",
            styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

    # Confusion matrix images
    story.append(Paragraph("Confusion Matrices", styles["Heading2"]))
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
