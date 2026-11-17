# NetSentinel - Packaging

Builds the dashboard as a single Windows `.exe`.

## Build

From the `netsentinel/` folder:

```bash
packaginguild_windows.bat
```

This runs PyInstaller (installing it if needed) with `packaging/netsentinel.spec`
and writes `dist/NetSentinel.exe`. The exe carries:

- the bundled fonts in `ui/fonts/` (Instrument Sans, IBM Plex Mono) and their OFL licences,
- the app icon `packaging/netsentinel.ico` (regenerate with `python tools/build_icon.py`
  from the repository root),
- the trained models from `models/`, when they exist.

## Notes

- **Demo mode** (`NetSentinel.exe --demo`) needs no models, no Npcap and no admin rights.
- **Live capture** needs [Npcap](https://npcap.com/) on the target machine (WinPcap-compatible
  mode). It cannot be embedded in the exe.
- **CSV replay** needs pandas, which the exe leaves out to stay small; run it from source.
- Rebuild the exe after retraining so the current models are bundled.
- The console window stays open (`console=True`) so live detection logs are visible.
