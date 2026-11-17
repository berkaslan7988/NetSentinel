"""NetSentinel - dense, painted data tables.

``RowsModel`` holds plain Python row objects; each view says how to turn a row
into cell values. ``CellDelegate`` paints every cell kind (addresses, chips,
model-signal pips, risk bars, sparklines) so the tables match the console look
in both themes, and ``DataTable`` wires it up: 31 px rows, hairline rules,
whole-row hover, an empty state, and selection that survives refreshes.
"""
from __future__ import annotations

from typing import Any, Callable, Hashable, List, Optional, Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetricsF, QPainter
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QStyle, QStyledItemDelegate, QTableView

from ui import icons, theme
from ui.i18n import t, upper
from ui.widgets import (
    PIPS_W, chip_width, paint_bar, paint_chip, paint_dot, paint_empty, paint_pips, paint_risk, pal,
)

ROW_H = 31
ROLE_VALUE = Qt.UserRole + 1


class Col:
    def __init__(self, key: str, title: str, kind: str = "text", width: int = 0,
                 stretch: int = 0, align=Qt.AlignLeft) -> None:
        self.key, self.title, self.kind = key, title, kind
        self.width, self.stretch, self.align = width, stretch, align


class RowsModel(QAbstractTableModel):
    def __init__(self, cols: Sequence[Col], value: Callable[[Any, str], Any],
                 key: Callable[[Any], Hashable], text: Optional[Callable[[Any, str], str]] = None,
                 parent=None) -> None:
        super().__init__(parent)
        self.cols = list(cols)
        self._value = value
        self._key = key
        self._text = text
        self.rows: List[Any] = []
        self._keys: List[Hashable] = []

    # -- Qt API ------------------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.cols)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row, col = self.rows[index.row()], self.cols[index.column()]
        if role == ROLE_VALUE:
            return self._value(row, col.key)
        if role == Qt.DisplayRole:
            if self._text is not None:
                return self._text(row, col.key)
            v = self._value(row, col.key)
            return v if isinstance(v, str) else None
        if role == Qt.TextAlignmentRole:
            return int(col.align | Qt.AlignVCenter)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation != Qt.Horizontal or section >= len(self.cols):
            return None
        col = self.cols[section]
        if role == Qt.DisplayRole:
            return upper(col.title)
        if role == Qt.TextAlignmentRole:
            return int(col.align | Qt.AlignVCenter)
        return None

    # -- updates -----------------------------------------------------------
    def row_at(self, r: int) -> Any:
        return self.rows[r] if 0 <= r < len(self.rows) else None

    def index_of(self, key: Hashable) -> int:
        try:
            return self._keys.index(key)
        except ValueError:
            return -1

    def key_of(self, row: Any) -> Hashable:
        return self._key(row)

    def sync(self, rows: List[Any]) -> int:
        """Replace the rows. Rows prepended to the previous list are inserted (so
        selection and scroll survive); returns how many rows were prepended,
        or -1 when the model had to be reset."""
        keys = [self._key(r) for r in rows]
        old = self._keys
        if keys == old:
            self.rows = rows
            if rows:
                self.dataChanged.emit(self.index(0, 0), self.index(len(rows) - 1, len(self.cols) - 1))
            return 0
        k = keys.index(old[0]) if old and old[0] in keys else -1
        if k > 0 and keys[k:] == old[: len(keys) - k]:
            self.beginInsertRows(QModelIndex(), 0, k - 1)
            self.rows = rows[:k] + self.rows
            self._keys = keys[:k] + old
            self.endInsertRows()
            extra = len(self.rows) - len(rows)
            if extra > 0:
                self.beginRemoveRows(QModelIndex(), len(rows), len(self.rows) - 1)
                self.rows = self.rows[: len(rows)]
                self._keys = self._keys[: len(rows)]
                self.endRemoveRows()
            self.rows = rows
            if rows:
                self.dataChanged.emit(self.index(k, 0), self.index(len(rows) - 1, len(self.cols) - 1))
            return k
        self.beginResetModel()
        self.rows = rows
        self._keys = keys
        self.endResetModel()
        return -1


class CellDelegate(QStyledItemDelegate):
    def __init__(self, table: "DataTable") -> None:
        super().__init__(table)
        self.table = table

    def sizeHint(self, option, index):  # noqa: N802
        s = super().sizeHint(option, index)
        s.setHeight(ROW_H)
        return s

    def paint(self, p: QPainter, option, index) -> None:
        P = pal()
        model: RowsModel = index.model()
        col = model.cols[index.column()]
        rect = QRectF(option.rect)
        selected = bool(option.state & QStyle.State_Selected) and self.table.show_selection
        hovered = index.row() == self.table.hover_row
        p.save()
        if selected:
            p.fillRect(rect, QColor(P.sel))
        elif hovered:
            p.fillRect(rect, QColor(P.hover))
        p.fillRect(QRectF(rect.x(), rect.bottom(), rect.width(), 1), QColor(P.line))
        if selected and index.column() == 0:
            p.fillRect(QRectF(rect.x(), rect.y(), 2, rect.height()), QColor(P.ink))
        first = index.column() == 0
        last = index.column() == len(model.cols) - 1
        inner = rect.adjusted(14 if first else 12, 0, -(14 if last else 0), 0)
        value = index.data(ROLE_VALUE)
        try:
            self._paint_cell(p, col, inner, value)
        finally:
            p.restore()

    # ------------------------------------------------------------------ #
    def _text(self, p, rect, text, font, color, align=Qt.AlignLeft) -> None:
        p.setFont(font)
        p.setPen(color)
        fm = QFontMetricsF(font)
        p.drawText(rect, align | Qt.AlignVCenter, fm.elidedText(text, Qt.ElideRight, rect.width()))

    def _paint_cell(self, p: QPainter, col: Col, r: QRectF, v) -> None:
        P = pal()
        kind = col.kind
        if v is None:
            return
        if kind == "time":
            text, sev = v
            paint_dot(p, r.x() + 3, r.center().y(), sev)
            self._text(p, r.adjusted(15, 0, 0, 0), text, theme.mono(12), QColor(P.ink3))
        elif kind == "addr":
            ip, port, arrow = v
            x = r.x()
            if arrow:
                icons.paint(p, "arrow-right", P.ink3, QRectF(x, r.center().y() - 6, 12, 12), 2.0)
                x += 20
            f = theme.mono(12)
            fm = QFontMetricsF(f)
            p.setFont(f)
            p.setPen(QColor(P.ink))
            avail = r.right() - x
            ip_w = fm.horizontalAdvance(ip)
            if ip_w >= avail:
                p.drawText(QRectF(x, r.y(), avail, r.height()), Qt.AlignVCenter,
                           fm.elidedText(ip, Qt.ElideRight, avail))
                return
            p.drawText(QRectF(x, r.y(), ip_w + 1, r.height()), Qt.AlignVCenter, ip)
            if port not in (None, ""):
                p.setPen(QColor(P.ink3))
                p.drawText(QRectF(x + ip_w, r.y(), avail - ip_w, r.height()), Qt.AlignVCenter,
                           fm.elidedText(f":{port}", Qt.ElideRight, avail - ip_w))
        elif kind in ("text", "mono"):
            font_fn = theme.mono if kind == "mono" else theme.ui
            if isinstance(v, tuple):
                text, token, weight = (list(v) + [None, 400])[:3]
            else:
                text, token, weight = v, None, 400
            color = QColor(getattr(P, token)) if isinstance(token, str) else (token or QColor(P.ink))
            self._text(p, r, str(text), font_fn(12, weight or 400), color, col.align)
        elif kind == "verdict":
            if v == "ATTACK":
                self._text(p, r, t("ATTACK"), theme.ui(12, 600), QColor(P.crit_ink))
            else:
                self._text(p, r, t(v) if v == "BENIGN" else v, theme.ui(12), QColor(P.ink3))
        elif kind == "pips":
            paint_pips(p, r.x(), r.center().y(), v)
        elif kind == "risk":
            risk, sev = v
            paint_risk(p, r, risk, sev, bar_w=min(64.0, max(24.0, r.width() - 40)))
        elif kind == "chip":
            paint_chip(p, r.x(), r.center().y(), v)
        elif kind == "bar":
            frac, sev, text = v
            num_w = 46.0
            paint_bar(p, QRectF(r.x(), r.y(), max(10.0, r.width() - num_w - 10), r.height()),
                      frac, theme.sev_color(sev))
            self._text(p, QRectF(r.right() - num_w, r.y(), num_w, r.height()), text,
                       theme.mono(12), QColor(P.ink2), Qt.AlignRight)
        elif kind == "spark":
            values, sev = v
            self._spark(p, r, values, sev)

    def _spark(self, p: QPainter, r: QRectF, values: Sequence[int], sev: str) -> None:
        P = pal()
        if not values:
            return
        top = max(values) or 1
        n = len(values)
        h = 16.0
        y0 = r.center().y() + h / 2
        w = r.width() / n
        p.setPen(Qt.NoPen)
        p.fillRect(QRectF(r.x(), y0, r.width(), 1), QColor(P.line2))
        color = theme.sev_color(sev, P)
        for i, val in enumerate(values):
            if val <= 0:
                continue
            bh = max(1.5, h * (val / top) ** 0.6)
            p.fillRect(QRectF(r.x() + i * w, y0 - bh, max(1.0, w - 0.6), bh), color)


class DataTable(QTableView):
    """A QTableView set up for the console look."""

    rowClicked = Signal(object)

    def __init__(self, model: RowsModel, empty_title: str = "", empty_hint: str = "",
                 show_selection: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.show_selection = show_selection
        self.hover_row = -1
        self.empty_title, self.empty_hint = empty_title, empty_hint
        self.setModel(model)
        self.setItemDelegate(CellDelegate(self))
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setFocusPolicy(Qt.StrongFocus if show_selection else Qt.NoFocus)
        self.setMouseTracking(True)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setFrameShape(QTableView.NoFrame)
        vh = self.verticalHeader()
        vh.setVisible(False)
        vh.setSectionResizeMode(QHeaderView.Fixed)
        vh.setDefaultSectionSize(ROW_H)
        hh = self.horizontalHeader()
        hh.setFont(theme.label_font(11))
        hh.setHighlightSections(False)
        hh.setSectionsClickable(False)
        hh.setFixedHeight(30)
        hh.setMinimumSectionSize(24)
        for i, col in enumerate(model.cols):
            if col.stretch:
                hh.setSectionResizeMode(i, QHeaderView.Stretch)
            else:
                hh.setSectionResizeMode(i, QHeaderView.Fixed)
                hh.resizeSection(i, col.width or self._auto_width(col))
        self.clicked.connect(self._on_click)

    def _auto_width(self, col: Col) -> int:
        if col.kind == "pips":
            return int(PIPS_W + 24)
        if col.kind == "chip":
            return int(chip_width() + 26)
        return 100

    def _on_click(self, index) -> None:
        row = self.model().row_at(index.row())
        if row is not None:
            self.rowClicked.emit(row)

    # hover ------------------------------------------------------------------
    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        row = self.indexAt(e.position().toPoint()).row()
        if row != self.hover_row:
            self.hover_row = row
            self.viewport().update()
        super().mouseMoveEvent(e)

    def leaveEvent(self, e) -> None:  # noqa: N802
        self.hover_row = -1
        self.viewport().update()
        super().leaveEvent(e)

    # selection by key ---------------------------------------------------------
    def selected_row(self):
        idx = self.selectionModel().selectedRows()
        return self.model().row_at(idx[0].row()) if idx else None

    def select_key(self, key: Hashable) -> bool:
        r = self.model().index_of(key)
        if r < 0:
            return False
        self.selectRow(r)
        return True

    def sync(self, rows: List[Any]) -> None:
        """Update rows, keeping the selection and the visible rows steady."""
        model: RowsModel = self.model()
        sel = self.selected_row()
        sel_key = model.key_of(sel) if sel is not None else None
        bar = self.verticalScrollBar()
        before = bar.value()
        added = model.sync(rows)
        if added > 0 and before > 0:
            bar.setValue(before + added * ROW_H)
        if added < 0 and sel_key is not None:
            self.select_key(sel_key)

    def paintEvent(self, e) -> None:  # noqa: N802
        super().paintEvent(e)
        if self.model().rowCount() == 0 and self.empty_title:
            p = QPainter(self.viewport())
            paint_empty(p, QRectF(self.viewport().rect()), self.empty_title, self.empty_hint)
            p.end()
