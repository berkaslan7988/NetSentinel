"""NetSentinel - shared building blocks for the console look.

Painted widgets read ``theme.current()`` at paint time, so a theme switch
(re-applied style sheet + repaint) needs no palette plumbing.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetricsF, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QAbstractButton, QButtonGroup, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from ui import brand, icons, theme
from ui.i18n import t, upper


def pal() -> theme.Palette:
    return theme.current()


def repolish(w: QWidget) -> None:
    w.style().unpolish(w)
    w.style().polish(w)
    w.update()


# ------------------------------------------------------------------- labels
def label(text: str = "", font: Optional[QFont] = None, obj: str = "") -> QLabel:
    lbl = QLabel(text)
    if font is not None:
        lbl.setFont(font)
    if obj:
        lbl.setObjectName(obj)
    return lbl


def small_label(text: str) -> QLabel:
    """Uppercase condensed label that sits above a number."""
    return label(upper(text), theme.label_font(11), "label")


class ElidedLabel(QLabel):
    """A QLabel that elides instead of widening its parent."""

    def __init__(self, text: str = "", font: Optional[QFont] = None, obj: str = "") -> None:
        super().__init__()
        self._full = text
        if font is not None:
            self.setFont(font)
        if obj:
            self.setObjectName(obj)
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.setMinimumWidth(10)
        self._apply()

    def setText(self, text: str) -> None:  # noqa: N802
        self._full = text
        self._apply()

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        self._apply()

    def _apply(self) -> None:
        elided = self.fontMetrics().elidedText(self._full, Qt.ElideRight, max(10, self.width()))
        super().setText(elided)
        self.setToolTip(self._full if elided != self._full else "")


def hrule() -> QFrame:
    f = QFrame()
    f.setObjectName("hrule")
    return f


def vrule() -> QFrame:
    f = QFrame()
    f.setObjectName("vrule")
    return f


def mono_html(text: str, token: str = "ink2", weight: int = 400) -> str:
    """Inline mono span for rich-text labels (colors follow the current theme)."""
    color = getattr(pal(), token) if not token.startswith("#") else token
    return (f'<span style="font-family:\'{theme.MONO}\'; color:{color}; '
            f'font-weight:{weight};">{text}</span>')


# ---------------------------------------------------------------- brand mark
class Mark(QWidget):
    def __init__(self, size: int = 24, parent=None) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        P = pal()
        brand.paint_mark(p, QRectF(0, 0, self.width(), self.height()),
                         QColor(P.ink), QColor(P.panel), QColor(P.crit))
        p.end()


# ------------------------------------------------------------------- panel
class Panel(QFrame):
    """A bordered panel with a 44 px header (title, meta, right-side tools)."""

    def __init__(self, title: str, meta: str = "", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)
        head = QWidget()
        head.setObjectName("transparent")
        head.setFixedHeight(43)
        self.head = QHBoxLayout(head)
        self.head.setContentsMargins(13, 0, 10, 0)
        self.head.setSpacing(12)
        self.title = label(title, theme.title_font())
        self.meta = ElidedLabel(meta, theme.ui(12), "ink3")
        self.head.addWidget(self.title)
        self.head.addWidget(self.meta, 1)
        outer.addWidget(head)
        outer.addWidget(hrule())
        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(0)
        outer.addLayout(self.body, 1)

    def set_meta(self, text: str) -> None:
        self.meta.setText(text)

    def add_tool(self, w: QWidget) -> None:
        self.head.addWidget(w, 0)


# --------------------------------------------------------------- segmented
class Segmented(QWidget):
    """A compact segmented control (exclusive checkable buttons)."""

    changed = Signal(str)

    def __init__(self, options: Sequence[Tuple[str, str]], current: Optional[str] = None,
                 parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("segTrack")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setFixedHeight(30)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(2)
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons = {}
        for key, text in options:
            b = QPushButton(text)
            b.setObjectName("seg")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.setFont(theme.ui(12, 500))
            b.clicked.connect(lambda _=False, k=key: self._pick(k))
            self._group.addButton(b)
            self._buttons[key] = b
            lay.addWidget(b)
        self.set_current(current or options[0][0])

    def _pick(self, key: str) -> None:
        self._current = key
        self.changed.emit(key)

    def set_current(self, key: str) -> None:
        self._current = key
        if key in self._buttons:
            self._buttons[key].setChecked(True)

    def current(self) -> str:
        return self._current

    def setEnabled(self, on: bool) -> None:  # noqa: N802
        for b in self._buttons.values():
            b.setEnabled(on)


# ----------------------------------------------------------------- top tabs
class TabButton(QAbstractButton):
    """A view tab in the top bar: text, an optional count badge, a 2 px underline."""

    def __init__(self, text: str, parent=None) -> None:
        super().__init__(parent)
        self.setText(text)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self._badge: Optional[Tuple[int, str]] = None
        self._hover = False
        self.setFixedHeight(52)
        self._sync_width()

    def set_badge(self, count: int, sev: Optional[str]) -> None:
        new = (count, sev or "med") if count > 0 else None
        if new != self._badge:
            self._badge = new
            self._sync_width()
            self.update()

    def _badge_w(self) -> float:
        if not self._badge:
            return 0.0
        fm = QFontMetricsF(theme.mono(10, 600))
        return max(18.0, fm.horizontalAdvance(str(self._badge[0])) + 10)

    def _sync_width(self) -> None:
        fm = QFontMetricsF(theme.ui(13, 600))
        w = fm.horizontalAdvance(self.text()) + 24
        if self._badge:
            w += self._badge_w() + 7
        self.setFixedWidth(int(w + 0.99))

    def enterEvent(self, e) -> None:  # noqa: N802
        self._hover = True
        self.update()

    def leaveEvent(self, e) -> None:  # noqa: N802
        self._hover = False
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(self.width(), 52)

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        on = self.isChecked()
        f = theme.ui(13, 600 if on else 500)
        p.setFont(f)
        p.setPen(QColor(P.ink if (on or self._hover) else P.ink3))
        fm = QFontMetricsF(f)
        tw = fm.horizontalAdvance(self.text())
        x = 12.0
        p.drawText(QRectF(x, 0, tw + 2, self.height()), Qt.AlignVCenter | Qt.AlignLeft, self.text())
        if self._badge:
            count, sev = self._badge
            bw = self._badge_w()
            r = QRectF(x + tw + 7, (self.height() - 18) / 2, bw, 18)
            fill, ink, _ = theme.chip_colors(sev, P)
            if sev != "crit":
                fill, ink = theme.sev_color(sev, P), QColor(P.panel)
            p.setPen(Qt.NoPen)
            p.setBrush(fill)
            p.drawRoundedRect(r, 9, 9)
            p.setPen(ink)
            p.setFont(theme.mono(10, 600))
            p.drawText(r, Qt.AlignCenter, str(count))
        if on:
            p.fillRect(QRectF(0, self.height() - 2, self.width(), 2), QColor(P.ink))
        p.end()


class IconButton(QPushButton):
    """Square 30 px button showing a theme-tinted SVG icon."""

    def __init__(self, icon_name: str, tip: str = "", parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("iconButton")
        self._icon = icon_name
        self.setToolTip(tip)
        self.setAccessibleName(tip)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(30, 30)
        self.setIconSize(QSize(16, 16))
        self.refresh()

    def refresh(self) -> None:
        self.setIcon(icons.icon(self._icon, pal().ink2, 16, 1.7))


class SearchBox(QWidget):
    """A search field with a leading icon."""

    textChanged = Signal(str)

    def __init__(self, placeholder: str, width: int = 210, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("searchBox")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setFixedSize(width, 30)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(9, 0, 8, 0)
        lay.setSpacing(7)
        self._icon = QLabel()
        lay.addWidget(self._icon)
        self.edit = QLineEdit()
        self.edit.setObjectName("bare")
        self.edit.setPlaceholderText(placeholder)
        self.edit.setAccessibleName(placeholder)
        self.edit.setFont(theme.ui(12))
        self.edit.setClearButtonEnabled(False)
        self.edit.textChanged.connect(self.textChanged)
        lay.addWidget(self.edit, 1)
        self.refresh()

    def refresh(self) -> None:
        self._icon.setPixmap(icons.pixmap("search", pal().ink3, 14, 1.9))

    def text(self) -> str:
        return self.edit.text()


# ---------------------------------------------------------- painted pieces
CHIP_H = 20.0


def chip_text(key: str) -> str:
    return {"crit": t("CRIT"), "high": t("HIGH"), "med": t("MED"), "low": t("LOW")}[key]


def chip_width() -> float:
    fm = QFontMetricsF(theme.mono(10, 600))
    longest = max(fm.horizontalAdvance(chip_text(k)) for k in theme.SEV_KEYS)
    return max(44.0, longest + 14)


def paint_chip(p: QPainter, x: float, cy: float, key: str, width: Optional[float] = None) -> float:
    """Severity chip centred vertically on ``cy``; returns its width."""
    P = pal()
    w = width or chip_width()
    r = QRectF(x, cy - CHIP_H / 2, w, CHIP_H)
    fill, ink, outline = theme.chip_colors(key, P)
    p.save()
    p.setRenderHint(QPainter.Antialiasing, True)
    if fill is not None:
        p.setPen(Qt.NoPen)
        p.setBrush(fill)
        p.drawRoundedRect(r, 4, 4)
    if outline is not None:
        p.setPen(QPen(outline, 1))
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), 4, 4)
    f = theme.mono(10, 600)
    f.setLetterSpacing(QFont.AbsoluteSpacing, 0.4)
    p.setFont(f)
    p.setPen(ink)
    p.drawText(r, Qt.AlignCenter, chip_text(key))
    p.restore()
    return w


PIP_W, PIP_H, PIP_GAP = 24.0, 18.0, 3.0


def paint_pips(p: QPainter, x: float, cy: float, flags: Sequence[Optional[bool]]) -> None:
    """RF / IF / AE pips: filled when that model flagged the flow, outlined if not,
    dotted outline when the model was not loaded (None)."""
    P = pal()
    p.save()
    p.setRenderHint(QPainter.Antialiasing, True)
    f = theme.mono(10, 600)
    for i, (name, flag) in enumerate(zip(("RF", "IF", "AE"), flags)):
        r = QRectF(x + i * (PIP_W + PIP_GAP), cy - PIP_H / 2, PIP_W, PIP_H)
        if flag:
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(P.pip_on))
            p.drawRoundedRect(r, 4, 4)
            p.setPen(QColor(P.pip_on_ink))
        else:
            pen = QPen(QColor(P.line2), 1)
            if flag is None:
                pen.setStyle(Qt.DotLine)
            p.setPen(pen)
            p.setBrush(Qt.NoBrush)
            p.drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), 4, 4)
            p.setPen(QColor(P.ink3))
        f.setWeight(QFont.Weight(600 if flag else 500))
        p.setFont(f)
        p.drawText(r, Qt.AlignCenter, name)
    p.restore()


PIPS_W = 3 * PIP_W + 2 * PIP_GAP


def paint_bar(p: QPainter, r: QRectF, frac: float, color: QColor, height: float = 4.0) -> None:
    P = pal()
    track = QRectF(r.x(), r.center().y() - height / 2, r.width(), height)
    p.save()
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(P.track))
    p.drawRoundedRect(track, height / 2, height / 2)
    frac = max(0.0, min(1.0, frac))
    if frac > 0:
        w = max(height, track.width() * frac)
        p.setBrush(color)
        p.drawRoundedRect(QRectF(track.x(), track.y(), w, height), height / 2, height / 2)
    p.restore()


def paint_risk(p: QPainter, r: QRectF, risk: float, sev: str, bar_w: float = 64.0) -> None:
    """Risk bar + number, right-aligned in ``r``."""
    num_w = 24.0
    bar = QRectF(r.right() - num_w - 9 - bar_w, r.y(), bar_w, r.height())
    color = theme.sev_color(sev) if sev != "low" else pal().c("low")
    paint_bar(p, bar, max(0.03, risk / 100.0), color)
    p.save()
    p.setFont(theme.mono(12, 600))
    p.setPen(theme.sev_ink(sev))
    p.drawText(QRectF(r.right() - num_w, r.y(), num_w, r.height()),
               Qt.AlignVCenter | Qt.AlignRight, f"{risk:.0f}")
    p.restore()


def paint_dot(p: QPainter, cx: float, cy: float, sev: str, r: float = 3.0) -> None:
    P = pal()
    p.save()
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(P.line2) if sev == "low" else theme.sev_color(sev))
    p.drawEllipse(QPointF(cx, cy), r, r)
    p.restore()


def paint_empty(p: QPainter, rect: QRectF, title: str, hint: str = "") -> None:
    P = pal()
    p.save()
    p.setFont(theme.ui(13, 600))
    p.setPen(QColor(P.ink2))
    fm = QFontMetricsF(p.font())
    cy = rect.center().y() - (10 if hint else 0)
    p.drawText(QRectF(rect.x(), cy - fm.height() / 2, rect.width(), fm.height()), Qt.AlignCenter, title)
    if hint:
        p.setFont(theme.ui(12))
        p.setPen(QColor(P.ink3))
        p.drawText(QRectF(rect.x() + 20, cy + 12, rect.width() - 40, 40),
                   Qt.AlignHCenter | Qt.AlignTop | Qt.TextWordWrap, hint)
    p.restore()


class ChipWidget(QWidget):
    def __init__(self, key: str = "low", parent=None) -> None:
        super().__init__(parent)
        self._key = key
        self.setFixedHeight(22)
        self.setFixedWidth(int(chip_width() + 1))

    def set_key(self, key: Optional[str]) -> None:
        self._key = key
        self.setVisible(key is not None)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        if not self._key:
            return
        p = QPainter(self)
        paint_chip(p, 0, self.height() / 2, self._key)
        p.end()


class Sparkline(QWidget):
    def __init__(self, width: int = 96, height: int = 28, token: str = "ink2", parent=None) -> None:
        super().__init__(parent)
        self.setFixedSize(width, height)
        self._values: List[float] = []
        self._token = token

    def set_values(self, values: Iterable[float]) -> None:
        self._values = list(values)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        vals = self._values
        if len(vals) < 2:
            return
        lo, hi = min(vals), max(vals)
        span = (hi - lo) or 1.0
        w, h = self.width() - 2, self.height() - 3
        path = QPainterPath()
        for i, v in enumerate(vals):
            pt = QPointF(1 + i * w / (len(vals) - 1), 1.5 + h - (v - lo) / span * h)
            path.moveTo(pt) if i == 0 else path.lineTo(pt)
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        pen = QPen(pal().c(self._token), 1.4)
        pen.setJoinStyle(Qt.RoundJoin)
        p.setPen(pen)
        p.drawPath(path)
        p.end()


class SeverityBar(QWidget):
    """Proportional crit / high / med segments (open alerts at a glance)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setFixedHeight(6)
        self.setMinimumWidth(60)
        self.setMaximumWidth(140)
        self._counts = (0, 0, 0)

    def set_counts(self, crit: int, high: int, med: int) -> None:
        self._counts = (crit, high, med)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        P = pal()
        total = sum(self._counts)
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        p.setPen(Qt.NoPen)
        if not total:
            p.setBrush(QColor(P.track))
            p.drawRoundedRect(QRectF(0, 0, self.width(), 6), 2, 2)
            p.end()
            return
        parts = [(n, k) for n, k in zip(self._counts, ("crit", "high", "med")) if n]
        gap = 2.0
        avail = self.width() - gap * (len(parts) - 1)
        x = 0.0
        for n, key in parts:
            w = avail * n / total
            p.setBrush(theme.sev_color(key, P))
            p.drawRoundedRect(QRectF(x, 0, w, 6), 2, 2)
            x += w + gap
        p.end()


# --------------------------------------------------------------------- KPIs
class KpiCell(QWidget):
    """Label, a large mono value (+ unit), an optional extra, and a sub-line."""

    def __init__(self, caption: str, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("transparent")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 11)
        lay.setSpacing(0)
        lay.addWidget(small_label(caption))
        lay.addSpacing(8)
        row = QHBoxLayout()
        row.setSpacing(12)
        row.setContentsMargins(0, 0, 0, 0)
        self.value = label("0", theme.mono(26, 500))
        self.unit = label("", theme.ui(12), "ink3")
        vbox = QHBoxLayout()
        vbox.setSpacing(5)
        vbox.addWidget(self.value, 0, Qt.AlignBottom)
        vbox.addWidget(self.unit, 0, Qt.AlignBottom)
        row.addLayout(vbox)
        self.extra = QHBoxLayout()
        self.extra.setContentsMargins(0, 0, 0, 0)
        row.addLayout(self.extra, 1)
        lay.addLayout(row)
        lay.addSpacing(8)
        self.sub = QLabel()
        self.sub.setFont(theme.ui(12))
        self.sub.setObjectName("ink3")
        self.sub.setTextFormat(Qt.RichText)
        lay.addWidget(self.sub)

    def set(self, value: str, unit: str = "", sub: str = "") -> None:
        self.value.setText(value)
        self.unit.setText(unit)
        self.unit.setVisible(bool(unit))
        self.sub.setText(sub)


class KpiStrip(QFrame):
    def __init__(self, cells: Sequence[KpiCell], parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(1, 1, 1, 1)
        lay.setSpacing(0)
        for i, cell in enumerate(cells):
            if i:
                lay.addWidget(vrule())
            lay.addWidget(cell, 1)
