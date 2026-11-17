"""NetSentinel - dashboard entry point.

A real-time SOC console on PySide6. Sources: Demo (synthetic traffic, no models
or capture driver needed), Live capture, or a CSV / database replay.

Usage:
    python dashboard.py                 # pick a source in the top bar
    python dashboard.py --demo          # start the demo straight away
    python dashboard.py --theme light --lang tr

WARNING: live capture must only be run on your own / authorized network, as
administrator on Windows (Npcap required). Demo and replay need neither.
"""
from __future__ import annotations

import argparse
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="NetSentinel dashboard")
    ap.add_argument("--demo", action="store_true", help="start the synthetic demo traffic")
    ap.add_argument("--theme", choices=("dark", "light"), help="override the saved theme")
    ap.add_argument("--lang", choices=("en", "tr"), help="interface language")
    args, qt_args = ap.parse_known_args(argv)

    try:
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("[ERROR] PySide6 is not installed. `pip install -r requirements.txt`.")
        return 1

    from ui import theme
    from ui.brand import app_icon
    from ui.main_window import MainWindow

    app = QApplication([sys.argv[0], *qt_args])
    app.setApplicationName("NetSentinel")
    app.setWindowIcon(app_icon())
    theme.load_fonts()
    app.setFont(theme.ui(13))
    win = MainWindow(autostart_demo=args.demo, theme_name=args.theme, lang=args.lang)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
