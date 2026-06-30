"""NetSentinel - Data preparation (Phase 3).

Loads the CIC-IDS2017 CSVs, cleans them, builds binary labels, aligns to
FEATURE_COLUMNS, splits into stratified train/test, and fits the StandardScaler
ONLY on train (to avoid data leakage). Saves the results to disk.

Critical design:
  * Column names are stripped (the CSVs have leading spaces: " Destination Port").
  * Features are reindexed to `features.columns.FEATURE_COLUMNS` order - the SAME
    feature space as live inference (FeatureExtractor). A mismatch is the #1
    cause of a model crashing in production.
  * Inf (Flow Bytes/s etc. when duration is 0) -> NaN -> dropped.
  * The scaler is fit on train only; test is transform-only.

CLI:
    python -m training.prepare_data                 # all CSVs
    python -m training.prepare_data --nrows 50000   # first N rows per file (fast)
    python -m training.prepare_data --files Wednesday-workingHours.pcap_ISCX.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd

# Make it runnable both as a package and as a script
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
        raise FileNotFoundError(f"CSV not found: {[str(m) for m in missing]}")
    if not paths:
        raise FileNotFoundError(f"No CSV in {data_dir}.")
    return paths


def load_raw(
    data_dir: Path, files: Optional[List[str]] = None, nrows: Optional[int] = None
) -> pd.DataFrame:
    """Loads and concatenates the CSVs; strips column names."""
    frames = []
    for path in list_csv_files(data_dir, files):
        df = pd.read_csv(path, nrows=nrows, low_memory=False)
        df.columns = df.columns.str.strip()  # " Destination Port" -> "Destination Port"
        frames.append(df)
        print(f"  loaded: {path.name}  ({len(df)} rows)")
    combined = pd.concat(frames, ignore_index=True)
    print(f"  total: {len(combined)} rows, {combined.shape[1]} columns")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Inf -> NaN, drop NaN rows, drop exact duplicates."""
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan)
    # Check NaN only in feature + label columns
    cols = [c for c in FEATURE_COLUMNS if c in df.columns] + [LABEL_COLUMN]
    df = df.dropna(subset=[c for c in cols if c in df.columns])
    df = df.drop_duplicates()
    print(f"  cleaning: {before} -> {len(df)} rows ({before - len(df)} dropped)")
    return df


def split_features_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """Returns X in FEATURE_COLUMNS order and binary y (BENIGN=0, ATTACK=1)."""
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise KeyError(
            f"Missing feature columns in CSV: {missing}\n"
            "Column names may not match CIC-IDS2017."
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
    """End-to-end prep. Returns (X_train, X_test, y_train, y_test, scaler)."""
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    data_dir = data_dir or config.CIC_DATA_DIR
    test_size = test_size if test_size is not None else config.TEST_SIZE
    random_state = random_state if random_state is not None else config.RANDOM_STATE

    print("[1/4] Loading CSVs...")
    df = load_raw(data_dir, files=files, nrows=nrows)
    print("[2/4] Cleaning...")
    df = clean(df)
    print("[3/4] Splitting features/labels...")
    X, y = split_features_labels(df)
    n_attack = int(y.sum())
    print(f"  BENIGN={len(y) - n_attack}  ATTACK={n_attack}  "
          f"(attack ratio {100 * n_attack / len(y):.1f}%)")

    print("[4/4] Split + scaling (scaler fit on train only)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y, test_size=test_size, random_state=random_state, stratify=y
    )
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)  # no leakage: fit on train only
    X_test = scaler.transform(X_test)
    print(f"  train={len(X_train)}  test={len(X_test)}")
    return X_train, X_test, y_train, y_test, scaler


def main() -> int:
    import joblib

    parser = argparse.ArgumentParser(description="CIC-IDS2017 data preparation")
    parser.add_argument("--data-dir", default=str(config.CIC_DATA_DIR))
    parser.add_argument("--files", nargs="*", default=None,
                        help="Only specific CSV files (by name)")
    parser.add_argument("--nrows", type=int, default=None,
                        help="First N rows per file (for quick testing)")
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
    print(f"\nSaved:\n  {out / 'dataset.npz'}\n  {config.SCALER_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
