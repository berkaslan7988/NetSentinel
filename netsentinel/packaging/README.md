# NetSentinel - Packaging

For distributing the NetSentinel dashboard as a single Windows `.exe`.

## Build

From the project root:

```bash
packaging\build_windows.bat
```

This runs `pyinstaller` (installing it if needed) with `packaging/netsentinel.spec`
and produces `dist/NetSentinel.exe`. The trained models (`models/`) are bundled
into the exe.

## Important notes

- **Npcap cannot be embedded in the exe.** Live capture mode requires
  [Npcap](https://npcap.com/) installed on the target machine (WinPcap-compatible
  mode).
- **Replay mode** needs no Npcap - it runs over a CIC-IDS2017 CSV or a saved DB,
  ideal for a demo.
- If you retrain the models (`training/`), rebuild the exe so the current models
  get bundled.
- The console window is kept open (`console=True`) so live detection logs are
  visible.

## Optional: installer wizard

If you want an Inno Setup installer (like NetScope), write a `.iss` script that
packages `dist/NetSentinel.exe`.
