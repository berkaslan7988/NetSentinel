"""NetSentinel's visual system: palettes, bundled fonts and the global style sheet.

Identity: a quiet SOC console
-----------------------------
* Graphite surfaces, hairline rules, 8 px corners. No glow, no gradients.
* **Color means severity.** Violet (medium), orange (high) and red (critical)
  appear only on risk scores and alerts; everything else is ink and greys.
  Primary buttons are ink, not an accent color.
* Instrument Sans for the interface (a 87.5 % width cut for small uppercase
  labels) and IBM Plex Mono for every number, address and port.

Painted widgets read the active palette with ``current()`` at paint time, so a
theme switch only has to re-apply the style sheet and repaint.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from PySide6.QtGui import QColor, QFont, QFontDatabase

# --------------------------------------------------------------------------- fonts
UI = "Instrument Sans"
COND = "Instrument Sans Condensed"
MONO = "IBM Plex Mono"

_FALLBACK = {UI: "Segoe UI", COND: "Segoe UI", MONO: "Consolas"}
_available: set[str] = set()


def font_dir() -> Path:
    here = Path(__file__).resolve().parent / "fonts"
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass and not here.is_dir():
        return Path(meipass) / "ui" / "fonts"
    return here


def load_fonts() -> None:
    """Register the bundled fonts once (call after QApplication exists)."""
    if _available:
        return
    for path in sorted(font_dir().glob("*.ttf")):
        fid = QFontDatabase.addApplicationFont(str(path))
        if fid >= 0:
            _available.update(QFontDatabase.applicationFontFamilies(fid))


def _family(name: str) -> str:
    return name if name in _available else _FALLBACK[name]


def font(family: str, px: float, weight: int = 400, *, spacing: float = 0.0,
         upper: bool = False) -> QFont:
    """A QFont in pixel units (the design is specified in px)."""
    f = QFont(_family(family))
    f.setPixelSize(max(1, round(px)))
    f.setWeight(QFont.Weight(weight))
    f.setHintingPreference(QFont.PreferNoHinting)
    if spacing:
        f.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    if upper:
        f.setCapitalization(QFont.AllUppercase)
    return f


def ui(px: float = 13, weight: int = 400) -> QFont:
    return font(UI, px, weight)


def mono(px: float = 12, weight: int = 400) -> QFont:
    return font(MONO, px, weight)


def label_font(px: float = 11) -> QFont:
    """Small condensed label that sits above numbers. Pass text through
    ``i18n.upper`` (Turkish-aware) rather than relying on Qt capitalization."""
    return font(COND, px, 600, spacing=round(px * 0.06, 2))


def title_font() -> QFont:
    return font(UI, 13, 600)


# ------------------------------------------------------------------------ palettes
class Palette:
    """One theme. Two instances: DARK and LIGHT."""

    def __init__(self, name: str, **tokens: str) -> None:
        self.name = name
        self.is_dark = name == "dark"
        for key, value in tokens.items():
            setattr(self, key, value)

    def c(self, token: str, alpha: float | None = None) -> QColor:
        col = QColor(getattr(self, token))
        if alpha is not None:
            col.setAlphaF(alpha)
        return col


DARK = Palette(
    "dark",
    bg="#0f1012", panel="#16171a", panel2="#1c1d21", line="#26272c", line2="#34363c",
    grid="#222328", ink="#ededef", ink2="#b0b2b9", ink3="#8a8c94",
    benign="#3a3c43", track="#25262b", sel="#24262b", hover="#1b1c20",
    low="#8d8f99", med="#9a7cf4", high="#f0883e", crit="#f25a5f",
    low_ink="#8d8f99", med_ink="#a58bf6", high_ink="#f0883e", crit_ink="#f25a5f",
    med_tint="rgba(154,124,244,0.16)", high_tint="rgba(240,136,62,0.15)",
    crit_solid="#f25a5f", on_crit="#1a0d0e",
    btn="#ededef", on_btn="#111214", btn_hover="#ffffff",
    pip_on="#b0b2b9", pip_on_ink="#16171a",
)

LIGHT = Palette(
    "light",
    bg="#ececee", panel="#ffffff", panel2="#f6f6f7", line="#e4e4e7", line2="#d2d3d8",
    grid="#eeeef0", ink="#141518", ink2="#45474e", ink3="#6a6c74",
    benign="#c9cad0", track="#ececef", sel="#efeff2", hover="#f8f8f9",
    low="#8b8e98", med="#7a5af0", high="#e8742a", crit="#d9363a",
    low_ink="#6b6e78", med_ink="#6240d8", high_ink="#b4500a", crit_ink="#c62828",
    med_tint="rgba(122,90,240,0.11)", high_tint="rgba(232,116,42,0.13)",
    crit_solid="#c62828", on_crit="#ffffff",
    btn="#141518", on_btn="#ffffff", btn_hover="#2a2b31",
    pip_on="#45474e", pip_on_ink="#ffffff",
)

_current: Palette = DARK


def current() -> Palette:
    """The active palette; painted widgets read it at paint time."""
    return _current


def set_current(pal: Palette) -> None:
    global _current
    _current = pal


def by_name(name: str) -> Palette:
    return LIGHT if name == "light" else DARK


# ------------------------------------------------------------ severity language
SEV_KEYS = ("low", "med", "high", "crit")
_SEV_FROM_NAME = {"LOW": "low", "MEDIUM": "med", "HIGH": "high", "CRITICAL": "crit"}


def sev_key(sev) -> str:
    """'low' | 'med' | 'high' | 'crit' from a Severity, its value, or a key."""
    value = getattr(sev, "value", sev)
    return _SEV_FROM_NAME.get(str(value), str(value) if value in SEV_KEYS else "low")


def sev_for_risk(risk: float) -> str:
    import config

    th = config.SEVERITY_THRESHOLDS
    if risk >= th["CRITICAL"]:
        return "crit"
    if risk >= th["HIGH"]:
        return "high"
    if risk >= th["MEDIUM"]:
        return "med"
    return "low"


def sev_rank(key: str) -> int:
    return SEV_KEYS.index(key)


def sev_color(key: str, pal: Palette | None = None) -> QColor:
    """Fill color for marks (bars, dots, timeline segments)."""
    return QColor(getattr(pal or _current, key))


def sev_ink(key: str, pal: Palette | None = None) -> QColor:
    """Text color for a severity on a panel; low reads as muted ink."""
    pal = pal or _current
    return QColor(pal.ink3 if key == "low" else getattr(pal, f"{key}_ink"))


def _qcolor(spec: str) -> QColor:
    if spec.startswith("rgba("):
        r, g, b, a = (float(x) for x in spec[5:-1].split(","))
        col = QColor(int(r), int(g), int(b))
        col.setAlphaF(a)
        return col
    return QColor(spec)


def chip_colors(key: str, pal: Palette | None = None) -> tuple[QColor | None, QColor, QColor | None]:
    """(fill, text, outline) of a severity chip."""
    pal = pal or _current
    if key == "crit":
        return QColor(pal.crit_solid), QColor(pal.on_crit), None
    if key == "high":
        return _qcolor(pal.high_tint), QColor(pal.high_ink), None
    if key == "med":
        return _qcolor(pal.med_tint), QColor(pal.med_ink), None
    return None, QColor(pal.low_ink), QColor(pal.line2)


# ---------------------------------------------------------------- style sheet
def _asset(name: str, color: str) -> str:
    """Write a tiny SVG used by the style sheet; return a QSS-safe path."""
    from . import icons

    folder = Path(tempfile.gettempdir()) / "netsentinel-ui"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}-{color.lstrip('#')}.svg"
    if not path.exists():
        path.write_bytes(icons.svg_bytes(name, color, stroke_width=2.2))
    return path.as_posix()


def stylesheet(pal: Palette) -> str:
    """The global Qt Style Sheet. Fonts are set in code; this is surfaces and states."""
    chev = _asset("chevron-down", pal.ink3)
    return f"""
    QMainWindow, QWidget#root, QDialog {{ background: {pal.bg}; }}
    QWidget {{ color: {pal.ink}; }}
    QWidget#page, QWidget#transparent {{ background: transparent; }}
    QScrollArea#transparent {{ background: transparent; border: none; }}
    QScrollArea#transparent > QWidget > QWidget {{ background: transparent; }}
    QStackedWidget {{ background: transparent; }}

    QWidget#topbar {{ background: {pal.panel}; border-bottom: 1px solid {pal.line}; }}
    QWidget#footer {{ background: {pal.panel}; border-top: 1px solid {pal.line}; }}
    QFrame#panel {{ background: {pal.panel}; border: 1px solid {pal.line}; border-radius: 8px; }}
    QFrame#inset {{ background: {pal.panel2}; border: 1px solid {pal.line}; border-radius: 6px; }}
    QFrame#hrule {{ background: {pal.line}; border: none; min-height: 1px; max-height: 1px; }}
    QFrame#vrule {{ background: {pal.line}; border: none; min-width: 1px; max-width: 1px; }}

    QLabel {{ background: transparent; color: {pal.ink}; }}
    QLabel#ink2 {{ color: {pal.ink2}; }}
    QLabel#ink3, QLabel#label {{ color: {pal.ink3}; }}
    QLabel#notice {{ color: {pal.ink2}; }}

    QPushButton {{
        background: {pal.panel};
        border: 1px solid {pal.line2};
        border-radius: 6px;
        padding: 0 12px;
        min-height: 30px;
        color: {pal.ink};
        font-family: "{_family(UI)}";
        font-size: 12.5px;
        font-weight: 500;
    }}
    QPushButton:hover {{ border-color: {pal.ink3}; }}
    QPushButton:pressed {{ background: {pal.panel2}; }}
    QPushButton:disabled {{ color: {pal.ink3}; border-color: {pal.line}; }}
    QPushButton:focus {{ outline: none; }}
    QPushButton#primary {{
        background: {pal.btn};
        border: 1px solid {pal.btn};
        color: {pal.on_btn};
        font-weight: 600;
        padding: 0 14px 0 12px;
    }}
    QPushButton#primary:hover {{ background: {pal.btn_hover}; border-color: {pal.btn_hover}; }}
    QPushButton#primary:disabled {{ background: {pal.line2}; border-color: {pal.line2}; color: {pal.ink3}; }}
    QPushButton#ghost {{ background: transparent; border-color: transparent; color: {pal.ink2}; font-weight: 600; }}
    QPushButton#ghost:hover {{ background: {pal.panel2}; }}
    QPushButton#iconButton {{ padding: 0; min-width: 30px; max-width: 30px; }}
    QPushButton#textButton {{ padding: 0 9px; color: {pal.ink2};
        font-family: "{_family(MONO)}"; font-size: 11.5px; font-weight: 600; }}

    QWidget#segTrack {{ background: {pal.panel2}; border: 1px solid {pal.line2}; border-radius: 7px; }}
    QPushButton#seg {{
        background: transparent;
        border: 1px solid transparent;
        border-radius: 5px;
        padding: 0 10px;
        min-height: 24px;
        max-height: 24px;
        color: {pal.ink3};
        font-size: 12.5px;
        font-weight: 500;
    }}
    QPushButton#seg:hover {{ color: {pal.ink}; }}
    QPushButton#seg:checked {{ background: {pal.panel}; border: 1px solid {pal.line2}; color: {pal.ink}; font-weight: 600; }}
    QPushButton#seg:disabled {{ color: {pal.ink3}; }}
    QPushButton#seg:checked:disabled {{ color: {pal.ink2}; }}

    QLineEdit {{
        background: {pal.panel2};
        border: 1px solid {pal.line2};
        border-radius: 6px;
        padding: 0 8px;
        min-height: 28px;
        color: {pal.ink};
        selection-background-color: {pal.ink2};
        selection-color: {pal.panel};
        font-family: "{_family(UI)}";
        font-size: 12px;
    }}
    QLineEdit:focus {{ border-color: {pal.ink3}; }}
    QLineEdit#bare {{ background: transparent; border: none; padding: 0; min-height: 0; }}
    QWidget#searchBox {{ background: {pal.panel2}; border: 1px solid {pal.line2}; border-radius: 6px; }}

    QComboBox {{
        background: {pal.panel};
        border: 1px solid {pal.line2};
        border-radius: 6px;
        padding: 0 28px 0 10px;
        min-height: 30px;
        color: {pal.ink};
        font-family: "{_family(UI)}";
        font-size: 12.5px;
        font-weight: 600;
    }}
    QComboBox:hover {{ border-color: {pal.ink3}; }}
    QComboBox:disabled {{ color: {pal.ink3}; border-color: {pal.line}; }}
    QComboBox::drop-down {{ border: none; width: 24px; subcontrol-position: center right; }}
    QComboBox::down-arrow {{ image: url("{chev}"); width: 12px; height: 12px; }}
    QComboBox QAbstractItemView {{
        background: {pal.panel};
        border: 1px solid {pal.line2};
        padding: 4px;
        outline: none;
        color: {pal.ink};
        selection-background-color: {pal.sel};
        selection-color: {pal.ink};
    }}

    QTableView {{
        background: {pal.panel};
        border: none;
        gridline-color: transparent;
        selection-background-color: {pal.sel};
        selection-color: {pal.ink};
        outline: none;
    }}
    QTableView::item {{ border: none; padding: 0; }}
    QHeaderView {{ background: {pal.panel2}; border: none; }}
    QHeaderView::section {{
        background: {pal.panel2};
        color: {pal.ink3};
        border: none;
        border-bottom: 1px solid {pal.line};
        padding: 0 0 0 12px;
        min-height: 30px;
        max-height: 30px;
        font-family: "{_family(COND)}";
        font-size: 11px;
        font-weight: 600;
    }}
    QHeaderView::section:first {{ padding-left: 14px; }}
    QHeaderView::section:last {{ padding-right: 14px; }}
    QTableView QTableCornerButton::section {{ background: {pal.panel2}; border: none; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 3px 2px; }}
    QScrollBar::handle:vertical {{ background: {pal.line2}; border-radius: 3px; min-height: 30px; }}
    QScrollBar::handle:vertical:hover {{ background: {pal.ink3}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px 3px; }}
    QScrollBar::handle:horizontal {{ background: {pal.line2}; border-radius: 3px; min-width: 30px; }}
    QScrollBar::handle:horizontal:hover {{ background: {pal.ink3}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

    QToolTip {{
        background: {pal.ink};
        color: {pal.panel};
        border: none;
        padding: 6px 8px;
        font-family: "{_family(MONO)}";
        font-size: 11px;
    }}
    QMessageBox {{ background: {pal.panel}; }}
    """
