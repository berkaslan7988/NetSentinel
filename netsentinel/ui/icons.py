"""Line icons drawn from inline SVG and tinted per theme.

Unicode symbols (▶ ■ ⏸ ◐ …) depend on whichever font is installed and can render
as empty boxes, so every glyph the dashboard needs is a 24 x 24 path here.
"""
from __future__ import annotations

from PySide6.QtCore import QByteArray, QRectF, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_FILL = 'fill="currentColor" stroke="none"'

_PATHS: dict[str, str] = {
    "play": f'<path d="M7 4.6v14.8a1 1 0 0 0 1.52.85l12-7.4a1 1 0 0 0 0-1.7l-12-7.4A1 1 0 0 0 7 4.6z" {_FILL}/>',
    "stop": f'<rect x="5" y="5" width="14" height="14" rx="2.5" {_FILL}/>',
    "chevron-down": '<path d="m6 9 6 6 6-6"/>',
    "chevron-right": '<path d="m9 6 6 6-6 6"/>',
    "arrow-right": '<path d="M4 12h15"/><path d="m13 6 6 6-6 6"/>',
    "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.8-4.8"/>',
    "contrast": f'<circle cx="12" cy="12" r="8.5"/><path d="M12 3.5a8.5 8.5 0 0 1 0 17z" {_FILL}/>',
    "bars": '<path d="M4.5 16.5v-6"/><path d="M9.5 19.5v-15"/><path d="M14.5 16.5v-9"/><path d="M19.5 13.5v-3"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "x": '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    "file": '<path d="M14 3H6.5A1.5 1.5 0 0 0 5 4.5v15A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V8z"/>'
            '<path d="M14 3v5h5"/>',
    "info": '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5"/><path d="M12 7.6v.1"/>',
}


def svg_bytes(name: str, color: str, stroke_width: float = 1.8) -> bytes:
    body = _PATHS[name].replace("currentColor", color)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" '
        f'fill="none" stroke="{color}" stroke-width="{stroke_width}" '
        f'stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
    ).encode("utf-8")


def pixmap(name: str, color: str, size: int = 16, stroke_width: float = 1.8,
           dpr: float = 2.0) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg_bytes(name, color, stroke_width)))
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    renderer.render(p, QRectF(0, 0, size * dpr, size * dpr))
    p.end()
    pm.setDevicePixelRatio(dpr)
    return pm


def icon(name: str, color: str, size: int = 16, stroke_width: float = 1.8) -> QIcon:
    ic = QIcon()
    ic.addPixmap(pixmap(name, color, size, stroke_width), QIcon.Normal)
    return ic


def paint(p: QPainter, name: str, color: str, rect: QRectF, stroke_width: float = 1.8) -> None:
    """Draw an icon straight onto a painter (used by custom-painted widgets)."""
    QSvgRenderer(QByteArray(svg_bytes(name, color, stroke_width))).render(p, rect)


ICON_SIZE = QSize(14, 14)
