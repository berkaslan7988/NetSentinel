@echo off
REM NetSentinel - Windows .exe derleme scripti (Faz 9)
REM Proje kokunden calistir:  packaging\build_windows.bat

echo ============================================
echo  NetSentinel - PyInstaller ile .exe derleme
echo ============================================

where pyinstaller >nul 2>nul
if errorlevel 1 (
    echo [i] PyInstaller kuruluyor...
    pip install pyinstaller
)

echo [i] Derleniyor...
pyinstaller packaging\netsentinel.spec --noconfirm

if exist dist\NetSentinel.exe (
    echo.
    echo [OK] dist\NetSentinel.exe olusturuldu.
    echo      Canli mod icin hedef makinede Npcap gerekli.
) else (
    echo [HATA] Derleme basarisiz. Yukaridaki ciktiyi kontrol et.
)
