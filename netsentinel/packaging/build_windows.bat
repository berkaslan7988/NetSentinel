@echo off
REM NetSentinel - Windows .exe build script (Phase 9)
REM Run from the project root:  packaging\build_windows.bat

echo ============================================
echo  NetSentinel - building the .exe with PyInstaller
echo ============================================

where pyinstaller >nul 2>nul
if errorlevel 1 (
    echo [i] Installing PyInstaller...
    pip install pyinstaller
)

echo [i] Building...
pyinstaller packaging\netsentinel.spec --noconfirm

if exist dist\NetSentinel.exe (
    echo.
    echo [OK] dist\NetSentinel.exe created.
    echo      Live mode requires Npcap on the target machine.
) else (
    echo [ERROR] Build failed. Check the output above.
)
