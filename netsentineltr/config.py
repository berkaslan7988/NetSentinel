"""NetSentinel — Merkezi konfigürasyon.

Tüm modüller bu dosyadan ayar okur. Faz ilerledikçe genişleyecek.
"""
from pathlib import Path

# --- Yollar ---
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
CIC_DATA_DIR = DATA_DIR / "cic-ids-2017"      # ham CIC-IDS2017 CSV'leri
PROCESSED_DIR = DATA_DIR / "processed"        # hazırlanmış train/test dizileri

# --- Model eğitimi (Faz 3) ---
RANDOM_STATE = 42
TEST_SIZE = 0.30                              # stratified train/test ayrımı
# Kaydedilen model dosyaları
SCALER_PATH = MODELS_DIR / "scaler.pkl"
SUPERVISED_MODEL_PATH = MODELS_DIR / "supervised_rf.pkl"
ISOFOREST_MODEL_PATH = MODELS_DIR / "isolation_forest.pkl"

# --- Paket yakalama (Faz 0-1) ---
# None = Scapy varsayılan arayüzü seçer. Belirli bir arayüz için adını yaz.
CAPTURE_INTERFACE = None
# BPF filtresi (örn. "ip" sadece IP trafiği). Boş = her şey.
CAPTURE_FILTER = "ip"
# Prototip sniff süresi (saniye)
CAPTURE_DEMO_DURATION = 10

# --- Akış yönetimi (Faz 1) ---
FLOW_ACTIVE_TIMEOUT = 120  # sn — akış bu süreyi aşarsa zorla kapat
FLOW_IDLE_TIMEOUT = 15     # sn — bu süre paket gelmezse kapat
FLOW_CLEANUP_INTERVAL = 5  # sn — expiry tarama periyodu

# --- Alarm & skorlama (Faz 5) ---
# Birleşik risk skoru ağırlıkları (denetimli baskın; denetimsiz destekleyici).
RISK_WEIGHT_SUPERVISED = 0.75
RISK_WEIGHT_UNSUPERVISED = 0.25
# Denetimsiz mutabakat katkısı: ikisi de anomali=1.0, biri=0.3, hiç=0.
RISK_UNSUP_BOTH = 1.0
RISK_UNSUP_ONE = 0.3
# Severity eşikleri (0-100 risk skoru)
SEVERITY_THRESHOLDS = {"LOW": 0, "MEDIUM": 25, "HIGH": 50, "CRITICAL": 75}
# Alarm üretme eşiği: bu riskin altı alarm üretmez (gürültü bastırma).
ALERT_MIN_RISK = 25
# Aynı kaynak IP'den gelen alarmların birleştirildiği pencere (sn).
ALERT_WINDOW_SECONDS = 60

# --- Depolama (Faz 6) ---
DB_PATH = DATA_DIR / "netsentinel.db"
DB_BATCH_SIZE = 50          # bu kadar kayıt birikince toplu yaz
DB_FLUSH_INTERVAL = 2.0     # ya da bu kadar sn geçince (hangisi önce)

# --- Logging ---
LOG_LEVEL = "INFO"
