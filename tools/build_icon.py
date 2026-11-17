"""Render the NetSentinel mark into packaging/netsentinel.ico (16-256 px).

    python tools/build_icon.py
"""
import io
import os
import sys

repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(repo, "netsentinel"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image  # noqa: E402
from PySide6.QtCore import QBuffer, QIODevice  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402

from ui.brand import render  # noqa: E402

app = QGuiApplication(sys.argv[:1])
buf = QBuffer()
buf.open(QIODevice.WriteOnly)
render(256).save(buf, "PNG")
img = Image.open(io.BytesIO(bytes(buf.data())))
out = os.path.join(repo, "netsentinel", "packaging", "netsentinel.ico")
img.save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("wrote", os.path.relpath(out, repo))
