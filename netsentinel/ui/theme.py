"""NetSentinel - Terminal / "hacker" theme (Phase 7).

Phosphor green, dark background, monospace aesthetic. (DESIGN_NOTES.md: NOT
NetScope-style.) Qt-independent: holds only color constants and a QSS string, so
it can be imported/tested without PySide6.
"""
from __future__ import annotations

# --- Palette ---
BG = "#0a0e0a"            # near black, slightly green
BG_PANEL = "#0f140f"      # panel background
BG_ALT = "#121812"        # alternate row
GRID = "#1c2a1c"          # grid/lines
FG = "#33ff66"            # main phosphor green
FG_DIM = "#1f9a3f"        # dim green
FG_BRIGHT = "#7dffa0"     # bright accent
ACCENT = "#00ffcc"        # cyan neon (chart accent)
MUTED = "#5a6f5a"         # gray-green secondary text

# --- Severity colors ---
SEVERITY_COLORS = {
    "LOW": "#7dff7d",       # light green
    "MEDIUM": "#ffd633",    # yellow
    "HIGH": "#ff8c1a",      # orange
    "CRITICAL": "#ff3344",  # red
}

# BENIGN / ATTACK row colors (live table)
BENIGN_COLOR = "#33ff66"
ATTACK_COLOR = "#ff3344"

# --- Chart colors (pyqtgraph) ---
GRAPH_THROUGHPUT = "#00ffcc"
GRAPH_ANOMALY = "#ff8c1a"

FONT_FAMILY = "Cascadia Code, JetBrains Mono, Consolas, Courier New, monospace"


def stylesheet() -> str:
    """Application-wide QSS. MainWindow.setStyleSheet(theme.stylesheet())."""
    return f"""
    QWidget {{
        background-color: {BG};
        color: {FG};
        font-family: {FONT_FAMILY};
        font-size: 12px;
    }}
    QMainWindow, QDialog {{ background-color: {BG}; }}

    QLabel#title {{
        color: {FG_BRIGHT};
        font-size: 18px;
        font-weight: bold;
        letter-spacing: 2px;
    }}
    QLabel#statValue {{ color: {FG_BRIGHT}; font-size: 22px; font-weight: bold; }}
    QLabel#statLabel {{ color: {MUTED}; font-size: 10px; letter-spacing: 1px; }}

    QFrame#card, QFrame#panel {{
        background-color: {BG_PANEL};
        border: 1px solid {GRID};
        border-radius: 4px;
    }}

    QTableWidget {{
        background-color: {BG_PANEL};
        gridline-color: {GRID};
        border: 1px solid {GRID};
        selection-background-color: {GRID};
        selection-color: {FG_BRIGHT};
    }}
    QHeaderView::section {{
        background-color: {BG_ALT};
        color: {FG_DIM};
        border: none;
        border-bottom: 1px solid {GRID};
        padding: 4px;
        text-transform: uppercase;
    }}
    QTableWidget::item {{ border-bottom: 1px solid {BG_ALT}; }}

    QPushButton {{
        background-color: {BG_PANEL};
        color: {FG};
        border: 1px solid {FG_DIM};
        border-radius: 3px;
        padding: 6px 14px;
    }}
    QPushButton:hover {{ border-color: {FG}; color: {FG_BRIGHT}; }}
    QPushButton:pressed {{ background-color: {GRID}; }}
    QPushButton:disabled {{ color: {MUTED}; border-color: {GRID}; }}
    QPushButton#danger {{ border-color: {SEVERITY_COLORS['CRITICAL']};
                          color: {SEVERITY_COLORS['CRITICAL']}; }}

    QComboBox {{
        background-color: {BG_PANEL};
        border: 1px solid {FG_DIM};
        border-radius: 3px;
        padding: 4px 8px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {BG_PANEL};
        selection-background-color: {GRID};
        color: {FG};
    }}

    QListWidget {{ background-color: {BG_PANEL}; border: 1px solid {GRID}; }}
    QScrollBar:vertical {{ background: {BG}; width: 10px; }}
    QScrollBar::handle:vertical {{ background: {FG_DIM}; border-radius: 4px; }}
    """


def banner() -> str:
    """An ASCII touch for the title bar."""
    return "< N E T S E N T I N E L >  // real-time intrusion detection"
