"""Draw the README pipeline diagram as two static SVGs (light and dark).

    python tools/build_diagram.py

Writes assets/pipeline-light.svg and assets/pipeline-dark.svg in the console's
style. Instrument Sans is embedded as a tiny subset (only the glyphs used), so
the text renders the same everywhere. A Mermaid block would get GitHub's
pan/zoom controls drawn over it.
"""
from __future__ import annotations

import base64
import io
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parent.parent
FONTS = ROOT / "netsentinel" / "ui" / "fonts"
OUT = ROOT / "assets"

W, H = 1240, 228
BOX_W, GAP, BOX_Y, BOX_H = 180, 32, 54, 108

STAGES = [
    ("01", "CAPTURE", "Scapy sniffer", "light capture thread"),
    ("02", "FLOWS", "5-tuple flows", "idle / FIN timeouts"),
    ("03", "FEATURES", "78 features", "CIC-IDS2017 order"),
    ("04", "DETECT", "RF + IF + AE", "~9.3 ms per flow"),
    ("05", "ALERTS", "Risk 0–100", "per source, 60 s"),
    ("06", "CONSOLE", "Dashboard + DB", "drains every 250 ms"),
]
THREADS = [(0, 0, "capture thread"), (1, 4, "worker threads"), (5, 5, "UI thread")]
REPLAY = "Demo · CSV · DB replay"

THEMES = {
    "dark": dict(fill="#16171a", stroke="#34363c", label="#8a8c94", title="#ededef",
                 detail="#a3a5ad", wire="#5a5c64", med="#9a7cf4", high="#f0883e", crit="#f25a5f"),
    "light": dict(fill="#f6f6f7", stroke="#d2d3d8", label="#6a6c74", title="#141518",
                  detail="#55575e", wire="#a9abb2", med="#7a5af0", high="#e8742a", crit="#d9363a"),
}


def _font(file: str, text: str) -> str:
    font = TTFont(FONTS / file)
    opts = subset.Options()
    opts.layout_features = ["kern", "liga"]
    opts.name_IDs = []
    opts.notdef_outline = True
    sub = subset.Subsetter(opts)
    sub.populate(text=text)
    sub.subset(font)
    buf = io.BytesIO()
    font.save(buf)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _x(i: int) -> int:
    return i * (BOX_W + GAP)


def build(theme: str) -> str:
    c = THEMES[theme]
    labels = "".join(f"{n} · {lab}" for n, lab, _, _ in STAGES)
    titles = "".join(t for _, _, t, _ in STAGES)
    details = "".join(d for *_, d in STAGES) + "".join(t for *_, t in THREADS) + REPLAY
    fonts = (
        f"@font-face{{font-family:NSCond;src:url(data:font/ttf;base64,"
        f"{_font('InstrumentSansCondensed-SemiBold.ttf', labels)}) format('truetype')}}"
        f"@font-face{{font-family:NSSemi;src:url(data:font/ttf;base64,"
        f"{_font('InstrumentSans-SemiBold.ttf', titles)}) format('truetype')}}"
        f"@font-face{{font-family:NSText;src:url(data:font/ttf;base64,"
        f"{_font('InstrumentSans-Regular.ttf', details)}) format('truetype')}}"
    )
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
        f'role="img" aria-label="NetSentinel pipeline: capture, flows, features, detect, alerts, console">',
        f"<style>{fonts}"
        f".l{{font:12px NSCond,sans-serif;letter-spacing:.7px;fill:{c['label']}}}"
        f".t{{font:17px NSSemi,sans-serif;fill:{c['title']}}}"
        f".d{{font:13.5px NSText,sans-serif;fill:{c['detail']}}}"
        f".w{{fill:none;stroke:{c['wire']};stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round}}"
        f"</style>",
    ]
    mid = BOX_Y + BOX_H / 2
    for i, (num, lab, title, detail) in enumerate(STAGES):
        x = _x(i)
        parts.append(f'<rect x="{x + .5}" y="{BOX_Y + .5}" width="{BOX_W - 1}" height="{BOX_H - 1}" '
                     f'rx="8" fill="{c["fill"]}" stroke="{c["stroke"]}"/>')
        parts.append(f'<text class="l" x="{x + 16}" y="{BOX_Y + 27}">{num} · {lab}</text>')
        parts.append(f'<text class="t" x="{x + 16}" y="{BOX_Y + 56}">{title}</text>')
        parts.append(f'<text class="d" x="{x + 16}" y="{BOX_Y + 80}">{detail}</text>')
        if lab == "ALERTS":   # the only place color appears: the severity scale
            sx, sy = x + 16, BOX_Y + BOX_H - 14
            seg = (BOX_W - 32 - 4) / 3
            for k, key in enumerate(("med", "high", "crit")):
                parts.append(f'<rect x="{sx + k * (seg + 2):.1f}" y="{sy}" width="{seg:.1f}" height="4" '
                             f'rx="2" fill="{c[key]}"/>')
        if i < len(STAGES) - 1:
            x0, x1 = x + BOX_W + 6, _x(i + 1) - 6
            parts.append(f'<path class="w" d="M{x0} {mid}H{x1}M{x1 - 5} {mid - 5}L{x1} {mid}L{x1 - 5} {mid + 5}"/>')

    # replay sources join between Detect and Alerts
    jx = _x(4) - GAP / 2
    pill_w = 196
    parts.append(f'<rect x="{jx - pill_w / 2}" y="6.5" width="{pill_w}" height="26" rx="13" fill="none" '
                 f'stroke="{c["wire"]}" stroke-dasharray="4 3"/>')
    parts.append(f'<text class="d" x="{jx}" y="24" text-anchor="middle">{REPLAY}</text>')
    parts.append(f'<path class="w" stroke-dasharray="3 3" d="M{jx} 33V{mid - 8}"/>')
    parts.append(f'<path class="w" d="M{jx - 4.5} {mid - 12}L{jx} {mid - 7}L{jx + 4.5} {mid - 12}"/>')

    # threading model under the boxes
    by = BOX_Y + BOX_H + 22
    for a, b, text in THREADS:
        x0, x1 = _x(a) + 2, _x(b) + BOX_W - 2
        parts.append(f'<path class="w" d="M{x0} {by - 6}V{by}H{x1}V{by - 6}"/>')
        parts.append(f'<text class="d" x="{(x0 + x1) / 2}" y="{by + 26}" text-anchor="middle">{text}</text>')
    parts.append("</svg>")
    return "".join(parts)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    for name in THEMES:
        path = OUT / f"pipeline-{name}.svg"
        path.write_text(build(name), encoding="utf-8")
        print("wrote", path.relative_to(ROOT), path.stat().st_size // 1024, "KB")
