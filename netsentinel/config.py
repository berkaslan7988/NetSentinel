"""NetSentinel - Central configuration.

Every module reads its settings from here. Grows as the project evolves.
"""
from pathlib import Path

APP_VERSION = "2.0.0"

# --- Paths ---
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
CIC_DATA_DIR = DATA_DIR / "cic-ids-2017"      # raw CIC-IDS2017 CSV files
PROCESSED_DIR = DATA_DIR / "processed"        # prepared train/test arrays

# --- Model training (Phase 3) ---
RANDOM_STATE = 42
TEST_SIZE = 0.30                              # stratified train/test split
# Saved model files
SCALER_PATH = MODELS_DIR / "scaler.pkl"
SUPERVISED_MODEL_PATH = MODELS_DIR / "supervised_rf.pkl"
ISOFOREST_MODEL_PATH = MODELS_DIR / "isolation_forest.pkl"

# --- Packet capture (Phase 0-1) ---
# None = Scapy picks the default interface. Set a name for a specific one.
CAPTURE_INTERFACE = None
# BPF filter (e.g. "ip" for IP traffic only). Empty = everything.
CAPTURE_FILTER = "ip"
# Prototype sniff duration (seconds)
CAPTURE_DEMO_DURATION = 10

# --- Flow management (Phase 1) ---
FLOW_ACTIVE_TIMEOUT = 120  # s - force-close a flow longer than this
FLOW_IDLE_TIMEOUT = 15     # s - close a flow idle for this long
FLOW_CLEANUP_INTERVAL = 5  # s - expiry scan period

# --- Alerting & scoring (Phase 5) ---
# Combined risk score weights (supervised dominant; unsupervised supporting).
RISK_WEIGHT_SUPERVISED = 0.75
RISK_WEIGHT_UNSUPERVISED = 0.25
# Unsupervised agreement contribution: both anomalous=1.0, one=0.3, none=0.
RISK_UNSUP_BOTH = 1.0
RISK_UNSUP_ONE = 0.3
# Severity thresholds (0-100 risk score)
SEVERITY_THRESHOLDS = {"LOW": 0, "MEDIUM": 25, "HIGH": 50, "CRITICAL": 75}
# Alert emission threshold: below this risk no alert is raised (noise suppression).
ALERT_MIN_RISK = 25
# Window in which alerts from the same source IP are aggregated (s).
ALERT_WINDOW_SECONDS = 60

# --- Storage (Phase 6) ---
DB_PATH = DATA_DIR / "netsentinel.db"
DB_BATCH_SIZE = 50          # flush after this many buffered records
DB_FLUSH_INTERVAL = 2.0     # ...or after this many seconds (whichever first)

# --- Logging ---
LOG_LEVEL = "INFO"
