"""NetSentinel - FeatureExtractor (Phase 2).

Converts a closed `Flow` into a 78-feature vector compatible with CIC-IDS2017.
The output matches `features.columns.FEATURE_COLUMNS` exactly in name and order.

Units (CIC standard):
  * Flow Duration and all IAT values  -> MICROSECONDS
  * "Packet length"                    -> L4 payload length (PacketRecord.payload_len)
  * Rates (Bytes/s, Packets/s)         -> per second

Statistics use sample (ddof=1) std/variance - matches CIC output (verified by
hand: [31,6,6] -> std 14.433757, var 208.333333).

Fidelity notes (DESIGN_NOTES.md):
  * Exact: counts, payload length stats, IAT, rates, flag counters, down/up,
    segment size, subflow, init window, act_data_pkt_fwd, min_seg_size_forward.
  * Approximate (CICFlowMeter quirks): header length (principled IP+L4),
    bulk features (0 - also ~always 0 in the dataset), active/idle (5s threshold),
    Average Packet Size (total payload / packet count).
"""
from __future__ import annotations

import statistics
from typing import Dict, List

from features.columns import FEATURE_COLUMNS
from flows.flow import Flow, PacketRecord

_S_TO_US = 1_000_000.0  # seconds -> microseconds


# --------------------------------------------------------------------- #
# Statistics helpers robust to empty lists
# --------------------------------------------------------------------- #
def _mean(xs: List[float]) -> float:
    return statistics.fmean(xs) if xs else 0.0


def _std(xs: List[float]) -> float:
    return statistics.stdev(xs) if len(xs) > 1 else 0.0


def _var(xs: List[float]) -> float:
    return statistics.variance(xs) if len(xs) > 1 else 0.0


def _max(xs: List[float]) -> float:
    return max(xs) if xs else 0.0


def _min(xs: List[float]) -> float:
    return min(xs) if xs else 0.0


def _diffs_us(timestamps: List[float]) -> List[float]:
    """Consecutive differences of sorted timestamps (microseconds)."""
    ts = sorted(timestamps)
    return [(b - a) * _S_TO_US for a, b in zip(ts, ts[1:])]


def _active_idle_us(timestamps: List[float], threshold_s: float):
    """CIC-style active/idle segmentation.

    When the gap between consecutive packets exceeds `threshold_s`, the active
    segment up to that point is recorded as 'active' and the gap as 'idle'. The
    final segment (with no trailing idle) is NOT added to active - CIC behavior.
    Values in us.
    """
    ts = sorted(timestamps)
    active: List[float] = []
    idle: List[float] = []
    if len(ts) < 2:
        return active, idle
    seg_start = ts[0]
    last = ts[0]
    for t in ts[1:]:
        gap = t - last
        if gap > threshold_s:
            active.append((last - seg_start) * _S_TO_US)
            idle.append(gap * _S_TO_US)
            seg_start = t
        last = t
    return active, idle


class FeatureExtractor:
    """Flow -> CIC-IDS2017 compatible feature dict/vector."""

    def __init__(self, active_timeout_s: float = 5.0) -> None:
        # CICFlowMeter default activity threshold is 5 s.
        self.active_timeout_s = active_timeout_s

    # ----------------------------------------------------------------- #
    def extract(self, flow: Flow) -> Dict[str, float]:
        """Produces a named feature dict from a flow (78 keys, correct order)."""
        fwd = flow.fwd_packets
        bwd = flow.bwd_packets

        fwd_lens = [p.payload_len for p in fwd]
        bwd_lens = [p.payload_len for p in bwd]
        all_lens = fwd_lens + bwd_lens

        dur_s = flow.duration
        dur_us = dur_s * _S_TO_US

        # IATs (us)
        flow_iat = _diffs_us([p.timestamp for p in fwd + bwd])
        fwd_iat = _diffs_us([p.timestamp for p in fwd])
        bwd_iat = _diffs_us([p.timestamp for p in bwd])

        # Flag counters (the flow already accumulates them)
        fc = flow.flag_counts

        # Per-direction PSH/URG flag counts (per packet)
        fwd_psh = sum(1 for p in fwd if "P" in p.flags)
        bwd_psh = sum(1 for p in bwd if "P" in p.flags)
        fwd_urg = sum(1 for p in fwd if "U" in p.flags)
        bwd_urg = sum(1 for p in bwd if "U" in p.flags)

        # Header length sums
        fwd_hdr = sum(p.header_len for p in fwd)
        bwd_hdr = sum(p.header_len for p in bwd)

        # Rates (per second; 0 if duration is 0)
        flow_bps = (flow.total_bytes / dur_s) if dur_s > 0 else 0.0
        flow_pps = (flow.total_packets / dur_s) if dur_s > 0 else 0.0
        fwd_pps = (len(fwd) / dur_s) if dur_s > 0 else 0.0
        bwd_pps = (len(bwd) / dur_s) if dur_s > 0 else 0.0

        # Init window (only meaningful for TCP; -1 otherwise)
        is_tcp = flow.protocol == "TCP"
        init_win_fwd = fwd[0].window if (is_tcp and fwd) else -1
        init_win_bwd = bwd[0].window if (is_tcp and bwd) else -1

        # act_data_pkt_fwd: number of fwd packets carrying payload
        act_data_fwd = sum(1 for p in fwd if p.payload_len > 0)
        # min_seg_size_forward: smallest fwd header size
        min_seg_fwd = _min([p.header_len for p in fwd]) if fwd else 0

        # Active / idle
        active, idle = _active_idle_us(
            [p.timestamp for p in fwd + bwd], self.active_timeout_s
        )

        # Down/Up ratio (integer)
        down_up = (len(bwd) // len(fwd)) if fwd else 0

        # Average Packet Size (approx: total payload / packet count)
        avg_pkt_size = (flow.total_bytes / flow.total_packets) if flow.total_packets else 0.0

        feats: Dict[str, float] = {
            "Destination Port": flow.dst_port,
            "Flow Duration": dur_us,
            "Total Fwd Packets": len(fwd),
            "Total Backward Packets": len(bwd),
            "Total Length of Fwd Packets": sum(fwd_lens),
            "Total Length of Bwd Packets": sum(bwd_lens),
            "Fwd Packet Length Max": _max(fwd_lens),
            "Fwd Packet Length Min": _min(fwd_lens),
            "Fwd Packet Length Mean": _mean(fwd_lens),
            "Fwd Packet Length Std": _std(fwd_lens),
            "Bwd Packet Length Max": _max(bwd_lens),
            "Bwd Packet Length Min": _min(bwd_lens),
            "Bwd Packet Length Mean": _mean(bwd_lens),
            "Bwd Packet Length Std": _std(bwd_lens),
            "Flow Bytes/s": flow_bps,
            "Flow Packets/s": flow_pps,
            "Flow IAT Mean": _mean(flow_iat),
            "Flow IAT Std": _std(flow_iat),
            "Flow IAT Max": _max(flow_iat),
            "Flow IAT Min": _min(flow_iat),
            "Fwd IAT Total": sum(fwd_iat),
            "Fwd IAT Mean": _mean(fwd_iat),
            "Fwd IAT Std": _std(fwd_iat),
            "Fwd IAT Max": _max(fwd_iat),
            "Fwd IAT Min": _min(fwd_iat),
            "Bwd IAT Total": sum(bwd_iat),
            "Bwd IAT Mean": _mean(bwd_iat),
            "Bwd IAT Std": _std(bwd_iat),
            "Bwd IAT Max": _max(bwd_iat),
            "Bwd IAT Min": _min(bwd_iat),
            "Fwd PSH Flags": fwd_psh,
            "Bwd PSH Flags": bwd_psh,
            "Fwd URG Flags": fwd_urg,
            "Bwd URG Flags": bwd_urg,
            "Fwd Header Length": fwd_hdr,
            "Bwd Header Length": bwd_hdr,
            "Fwd Packets/s": fwd_pps,
            "Bwd Packets/s": bwd_pps,
            "Min Packet Length": _min(all_lens),
            "Max Packet Length": _max(all_lens),
            "Packet Length Mean": _mean(all_lens),
            "Packet Length Std": _std(all_lens),
            "Packet Length Variance": _var(all_lens),
            "FIN Flag Count": fc["FIN"],
            "SYN Flag Count": fc["SYN"],
            "RST Flag Count": fc["RST"],
            "PSH Flag Count": fc["PSH"],
            "ACK Flag Count": fc["ACK"],
            "URG Flag Count": fc["URG"],
            "CWE Flag Count": fc["CWR"],
            "ECE Flag Count": fc["ECE"],
            "Down/Up Ratio": down_up,
            "Average Packet Size": avg_pkt_size,
            "Avg Fwd Segment Size": _mean(fwd_lens),
            "Avg Bwd Segment Size": _mean(bwd_lens),
            "Fwd Header Length.1": fwd_hdr,  # duplicated column in CIC
            "Fwd Avg Bytes/Bulk": 0,
            "Fwd Avg Packets/Bulk": 0,
            "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0,
            "Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": len(fwd),
            "Subflow Fwd Bytes": sum(fwd_lens),
            "Subflow Bwd Packets": len(bwd),
            "Subflow Bwd Bytes": sum(bwd_lens),
            "Init_Win_bytes_forward": init_win_fwd,
            "Init_Win_bytes_backward": init_win_bwd,
            "act_data_pkt_fwd": act_data_fwd,
            "min_seg_size_forward": min_seg_fwd,
            "Active Mean": _mean(active),
            "Active Std": _std(active),
            "Active Max": _max(active),
            "Active Min": _min(active),
            "Idle Mean": _mean(idle),
            "Idle Std": _std(idle),
            "Idle Max": _max(idle),
            "Idle Min": _min(idle),
        }
        return feats

    # ----------------------------------------------------------------- #
    def extract_vector(self, flow: Flow) -> List[float]:
        """Same data as a flat list in FEATURE_COLUMNS order."""
        feats = self.extract(flow)
        return [float(feats[c]) for c in FEATURE_COLUMNS]
