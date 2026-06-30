# -*- mode: python ; coding: utf-8 -*-
"""NetSentinel - PyInstaller spec (Phase 9).

Packages dashboard.py into a single Windows .exe and bundles the trained models
(models/) so the .exe runs without a Python install.

Build:
    pip install pyinstaller
    pyinstaller packaging/netsentinel.spec

Output: dist/NetSentinel.exe

Notes:
  * Live capture requires Npcap installed on the target machine (cannot be
    embedded in the exe).
  * Models are bundled; rebuild the exe if you retrain.
"""
import os

block_cipher = None

# the spec lives in packaging/; the project root is one level up
ROOT = os.path.abspath(os.path.join(os.getcwd()))

datas = []
# Bundle the trained models (if present)
for fname in ("scaler.pkl", "supervised_rf.pkl", "isolation_forest.pkl",
              "autoencoder.pt", "ae_meta.json"):
    fpath = os.path.join("models", fname)
    if os.path.exists(fpath):
        datas.append((fpath, "models"))

a = Analysis(
    ["..\\dashboard.py"],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "sklearn.ensemble._forest",
        "sklearn.tree._utils",
        "scipy._lib.array_api_compat.numpy.fft",
        "pyqtgraph.graphicsItems.ViewBox.axisCtrlTemplate_pyside6",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "pandas"],  # not needed in the dashboard (training/eval are separate)
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="NetSentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=True,   # show live-mode logs in the terminal
    icon=None,
)
