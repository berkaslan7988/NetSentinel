# -*- mode: python ; coding: utf-8 -*-
"""NetSentinel — PyInstaller spec (Faz 9).

dashboard.py'yi tek bir Windows .exe'sine paketler ve eğitilmiş modelleri
(models/) bundle eder; böylece .exe Python kurulu olmadan çalışır.

Derleme:
    pip install pyinstaller
    pyinstaller packaging/netsentinel.spec

Çıktı: dist/NetSentinel.exe

Notlar:
  * Canlı yakalama için hedef makinede Npcap kurulu olmalı (exe'ye gömülemez).
  * Modeller bundle edilir; yeniden eğitirsen exe'yi tekrar derle.
"""
import os

block_cipher = None

# spec dosyası packaging/ içinde; proje kökü bir üst dizin
ROOT = os.path.abspath(os.path.join(os.getcwd()))

datas = []
# Eğitilmiş modelleri bundle et (varsa)
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
    excludes=["matplotlib", "pandas"],  # dashboard'da gerekmez (eğitim/değerlendirme ayrı)
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
    console=True,   # canlı modda terminal logları görünsün
    icon=None,
)
