"""NetSentinel — CIC-IDS2017 özellik kolonları (Faz 2).

CIC-IDS2017 / CICFlowMeter CSV'lerinin kolon isimleri ve **sırası** (78 özellik
+ Label). Liste Hugging Face veri seti şemasından doğrulanmıştır.

FeatureExtractor bu sırayı birebir üretir; offline eğitim (Faz 3) ve canlı
inference (Faz 4) aynı feature uzayında olmalı — isim/sıra uyuşmazlığı modelin
canlıda çökmesinin 1 numaralı sebebidir (roadmap, Faz 2 tuzağı).

Not: Orijinal CSV'lerde bazı kolon isimlerinde başta boşluk vardır
(örn. " Destination Port"). Faz 3'te CSV yüklenirken `df.columns.str.strip()`
ile normalize edilmeli; bu modül boşluksuz kanonik isimleri tutar.
"""
from __future__ import annotations

# 78 özellik, CIC-IDS2017 sırasıyla (Label hariç).
FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

LABEL_COLUMN = "Label"

# Tutarlılık kontrolü (import anında bozulma fark edilsin)
assert len(FEATURE_COLUMNS) == 78, f"Beklenen 78 kolon, bulunan {len(FEATURE_COLUMNS)}"
assert len(set(FEATURE_COLUMNS)) == 78, "Kolon isimlerinde tekrar var"
