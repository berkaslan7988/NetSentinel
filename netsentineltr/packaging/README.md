# NetSentinel — Paketleme

NetSentinel dashboard'unu tek bir Windows `.exe` olarak dağıtmak için.

## Derleme

Proje kökünden:

```bash
packaging\build_windows.bat
```

Bu, `pyinstaller`'ı (gerekirse kurarak) `packaging/netsentinel.spec` ile çalıştırır
ve `dist/NetSentinel.exe` üretir. Eğitilmiş modeller (`models/`) exe'ye gömülür.

## Önemli notlar

- **Npcap exe'ye gömülemez.** Canlı yakalama modu, hedef makinede
  [Npcap](https://npcap.com/)'in kurulu olmasını gerektirir (WinPcap uyumlu modda).
- **Replay modu** Npcap gerektirmez — CIC-IDS2017 CSV'si ya da kaydedilmiş DB
  üzerinden çalışır, demo için idealdir.
- Modelleri yeniden eğitirsen (`training/`), exe'yi tekrar derle ki güncel modeller
  gömülsün.
- Konsol penceresi açık bırakılır (`console=True`) ki canlı tespit logları görünsün.

## Opsiyonel: kurulum sihirbazı

NetScope'taki gibi bir Inno Setup kurulum dosyası eklemek istersen,
`dist/NetSentinel.exe`'yi paketleyen bir `.iss` scripti yazılabilir.
