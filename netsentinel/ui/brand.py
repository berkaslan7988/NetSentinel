"""The NetSentinel mark: an ink tile with a flat baseline and one red spike.

Anomaly detection drawn as a single stroke. ``paint_mark`` follows the active
theme (ink tile, panel-coloured baseline); ``app_icon`` uses fixed colours so
the taskbar icon reads on any desktop.
"""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap


def paint_mark(p: QPainter, rect: QRectF, tile: QColor, line: QColor, spike: QColor) -> None:
    """Draw the mark into ``rect`` (any square size; designed on a 24 grid)."""
    p.save()
    p.setRenderHint(QPainter.Antialiasing, True)
    p.translate(rect.topLeft())
    s = rect.width() / 24.0
    p.scale(s, s)
    p.setPen(Qt.NoPen)
    p.setBrush(tile)
    p.drawRoundedRect(QRectF(0, 0, 24, 24), 6, 6)
    pen = QPen(line, 2.0)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawLine(QPointF(4.5, 15.5), QPointF(9.2, 15.5))
    p.drawLine(QPointF(14.8, 15.5), QPointF(19.5, 15.5))
    pen.setColor(spike)
    p.setPen(pen)
    path = QPainterPath(QPointF(9.2, 15.5))
    path.lineTo(12, 6.5)
    path.lineTo(14.8, 15.5)
    p.drawPath(path)
    p.restore()


def render(size: int) -> QImage:
    img = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.transparent)
    p = QPainter(img)
    paint_mark(p, QRectF(0, 0, size, size), QColor("#141518"), QColor("#ffffff"), QColor("#f25a5f"))
    p.end()
    return img


def app_icon() -> QIcon:
    ic = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        ic.addPixmap(QPixmap.fromImage(render(size)))
    return ic
