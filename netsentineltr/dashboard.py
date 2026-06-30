"""NetSentinel — Dashboard giriş noktası (Faz 7).

Fosfor yeşil terminal estetiğinde, PySide6 + pyqtgraph tabanlı canlı kontrol
paneli. Canlı yakalama ya da CSV/DB replay modunda çalışır.

Kullanım (Windows'ta canlı mod için YÖNETİCİ terminal):
    python dashboard.py

⚠️ Canlı mod yalnızca kendi/yetkili ağında çalıştırılmalı. Replay modu CSV/DB
   üzerinden çalışır, ağ erişimi gerektirmez (demo/GIF için ideal).
"""
from __future__ import annotations

import sys


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("[HATA] PySide6 yüklü değil. `pip install PySide6 pyqtgraph` çalıştır.")
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
