"""NetSentinel - Dashboard entry point (Phase 7).

A live control panel in the phosphor-green terminal aesthetic, built on
PySide6 + pyqtgraph. Runs in live capture mode or CSV/DB replay mode.

Usage (run as ADMINISTRATOR on Windows for live mode):
    python dashboard.py

WARNING: live mode must only be run on your own / authorized network. Replay mode
   works over a CSV/DB and needs no network access (ideal for a demo/GIF).
"""
from __future__ import annotations

import sys


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("[ERROR] PySide6 is not installed. `pip install PySide6 pyqtgraph`.")
        return 1

    from ui import theme
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setStyleSheet(theme.stylesheet())
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
