"""NetSentinel — Veri hazırlama (Faz 3).

CIC-IDS2017 CSV'lerini yükler, temizler, binary etiketler, FEATURE_COLUMNS ile
hizalar, stratified train/test'e böler ve StandardScaler'ı SADECE train'e fit
eder (data leakage'ı önlemek için). Sonuçları diske kaydeder.

Kritik tasarım:
  * Kolon isimleri strip edilir (CSV'de baştaki boşluklar var: " Destination Port").
  * Özellikler `features.columns.FEATURE_COLUMNS` sırasına reindex edilir — canlı
    inference (FeatureExtractor) ile BİREBİR aynı feature uzayı. Uyuşmazlık
    modelin canlıda çökmesinin 1 numaralı sebebidir.
  * Inf (Flow Bytes/s vb. süre 0 olunca) -> NaN -> temizlenir.
  * Scaler yalnız train'e fit edilir; test sadece transform.

CLI:
    python -m training.prepare_data                 # tüm CSV'ler
    python -m training.prepare_data --nrows 50000   # dosya başına ilk N satır (hızlı)
    python -m training.prepare_data --files Wednesday-workingHours.pcap_ISCX.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd

# Paket olarak da, script olarak da çalışsın diye yol ayarı
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from features.columns import FEATURE_COLUMNS, LABEL_COLUMN  # noqa: E402

BENIGN_LABEL = "BENIGN"


# --------------------------------------------------------------------- #
def list_csv_files(data_dir: Path, files: Optional[List[str]] = None) -> List[Path]:
    if files:
        paths = [data_dir / f for f in files]
    else:
        paths = sorted(data_dir.glob("*.csv"))
    missing = [p for p in paths if not p.exists()]
    if missing:
        raise FileNotFoundError(f"CSV bulunamadı: {[str(m) for m in missing]}")
    if not paths:
        raise FileNotFoundError(f"{data_dir} içinde CSV yok.")
    return paths


def load_raw(
    data_dir: Path, files: Optional[List[str]] = None, nrows: Optional[int] = None
) -> pd.DataFrame:
    """CSV'leri yükleyip birleştirir; kolon isimlerini strip eder."""
    frames = []
    for path in list_csv_files(data_dir, files):
        df = pd.read_csv(path, nrows=nrows, low_memory=False)
        df.columns = df.columns.str.strip()  # " Destination Port" -> "Destination Port"
        frames.append(df)
        print(f"  yüklendi: {path.name}  ({len(df)} satır)")
    combined = pd.concat(frames, ignore_index=True)
    print(f"  toplam: {len(combined)} satır, {combined.shape[1]} kolon")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Inf -> NaN, NaN satırları at, tam tekrarları at."""
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan)
    # Sadece özellik + label kolonlarında NaN kontrolü
    cols = [c for c in FEATURE_COLUMNS if c in df.columns] + [LABEL_COLUMN]
    df = df.dropna(subset=[c for c in cols if c in df.columns])
    df = df.drop_duplicates()
    print(f"  temizlik: {before} -> {len(df)} satır ({before - len(df)} atıldı)")
    return df


def split_features_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """FEATURE_COLUMNS sırasında X ve binary y (BENIGN=0, ATTACK=1) döndürür."""
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise KeyError(
            f"CSV'de eksik özellik kolonları: {missing}\n"
            "Kolon isimleri CIC-IDS2017 ile eşleşmiyor olabilir."
        )
    X = df[FEATURE_COLUMNS].astype(np.float64)
    y = (df[LABEL_COLUMN].astype(str).str.strip() != BENIGN_LABEL).astype(np.int64).values
    return X, y


def prepare(
    data_dir: Path = None,
    files: Optional[List[str]] = None,
    nrows: Optional[int] = None,
    test_size: float = None,
    random_state: int = None,
):
    """Uçtan uca hazırlık. (X_train, X_test, y_train, y_test, scaler) döndürür."""
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    data_dir = data_dir or config.CIC_DATA_DIR
    test_size = test_size if test_size is not None else config.TEST_SIZE
    random_state = random_state if random_state is not None else config.RANDOM_STATE

    print("[1/4] CSV yükleniyor...")
    df = load_raw(data_dir, files=files, nrows=nrows)
    print("[2/4] Temizleniyor...")
    df = clean(df)
    print("[3/4] Özellik/etiket ayrılıyor...")
    X, y = split_features_labels(df)
    n_attack = int(y.sum())
    print(f"  BENIGN={len(y) - n_attack}  ATTACK={n_attack}  "
          f"(attack oranı %{100 * n_attack / len(y):.1f})")

    print("[4/4] Split + scaling (scaler yalnız train'e fit)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y, test_size=test_size, random_state=random_state, stratify=y
    )
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)  # leakage yok: fit sadece train
    X_test = scaler.transform(X_test)
    print(f"  train={len(X_train)}  test={len(X_test)}")
    return X_train, X_test, y_train, y_test, scaler


def main() -> int:
    import joblib

    parser = argparse.ArgumentParser(description="CIC-IDS2017 veri hazırlama")
    parser.add_argument("--data-dir", default=str(config.CIC_DATA_DIR))
    parser.add_argument("--files", nargs="*", default=None,
                        help="Yalnız belirli CSV dosyaları (isim)")
    parser.add_argument("--nrows", type=int, default=None,
                        help="Dosya başına ilk N satır (hızlı test için)")
    parser.add_argument("--out", default=str(config.PROCESSED_DIR))
    args = parser.parse_args()

    X_train, X_test, y_train, y_test, scaler = prepare(
        data_dir=Path(args.data_dir), files=args.files, nrows=args.nrows
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        out / "dataset.npz",
        X_train=X_train, X_test=X_test, y_train=y_train, y_test=y_test,
    )
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, config.SCALER_PATH)
    print(f"\nKaydedildi:\n  {out / 'dataset.npz'}\n  {config.SCALER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
