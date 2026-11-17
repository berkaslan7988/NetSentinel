# -*- mode: python ; coding: utf-8 -*-
"""NetSentinel - PyInstaller spec.

Packages dashboard.py into a single Windows .exe with the bundled fonts, the
app icon and, if present, the trained models, so it runs without Python.

Build (from the netsentinel/ folder):
    pip install pyinstaller
    pyinstaller packaging/netsentinel.spec --noconfirm

Output: dist/NetSentinel.exe

Notes:
  * Demo mode works with no models and no Npcap.
  * Live capture needs Npcap on the target machine (it cannot be embedded).
  * Models are bundled when they exist; rebuild the exe after retraining.
"""
import glob
import os

block_cipher = None

# SPECPATH is the folder holding this spec (packaging/); the app root is one up.
ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))

datas = []
for fname in ("scaler.pkl", "supervised_rf.pkl", "isolation_forest.pkl",
              "autoencoder.pt", "ae_meta.json"):
    fpath = os.path.join(ROOT, "models", fname)
    if os.path.exists(fpath):
        datas.append((fpath, "models"))
# Instrument Sans + IBM Plex Mono and their OFL licences (ui/theme.py loads them)
for fpath in glob.glob(os.path.join(ROOT, "ui", "fonts", "*")):
    datas.append((fpath, os.path.join("ui", "fonts")))

a = Analysis(
    [os.path.join(ROOT, "dashboard.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "sklearn.ensemble._forest",
        "sklearn.tree._utils",
        "scipy._lib.array_api_compat.numpy.fft",
        "PySide6.QtSvg",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "pandas"],  # training/eval only; CSV replay needs the source install
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
    icon=os.path.join(SPECPATH, "netsentinel.ico"),
)
