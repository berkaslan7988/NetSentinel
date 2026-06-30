"""Unit tests for features.extractor.

A known flow is built via the FlowManager, and the extracted features are
compared against hand-computed values. No Scapy/network needed.
"""
import statistics

import pytest

from capture.sniffer import PacketSummary
from features.columns import FEATURE_COLUMNS, LABEL_COLUMN
from features.extractor import FeatureExtractor
from flows.manager import FlowManager


def psum(src, dst, sp, dp, ts, payload, flags="", window=0, header=20, proto="TCP"):
    return PacketSummary(
        timestamp=ts, src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp,
        protocol=proto, length=payload + header, tcp_flags=flags,
        payload_len=payload, header_len=header, window=window,
    )


def build_known_flow():
    """Builds and closes a known 4-packet TCP flow.

    initiator = 10.0.0.1 (forward)
      t=0.0  fwd  payload 0    flags S   win 8192   (SYN)
      t=1.0  bwd  payload 0    flags SA  win 64240  (SYN-ACK)
      t=1.5  fwd  payload 100  flags PA  win 8192
      t=2.0  bwd  payload 200  flags A   win 64240
    """
    closed = []
    fm = FlowManager(on_flow_closed=closed.append)
    fm.process_packet(psum("10.0.0.1", "10.0.0.2", 1234, 80, 0.0, 0, "S", 8192))
    fm.process_packet(psum("10.0.0.2", "10.0.0.1", 80, 1234, 1.0, 0, "SA", 64240))
    fm.process_packet(psum("10.0.0.1", "10.0.0.2", 1234, 80, 1.5, 100, "PA", 8192))
    fm.process_packet(psum("10.0.0.2", "10.0.0.1", 80, 1234, 2.0, 200, "A", 64240))
    fm.flush_all()
    assert len(closed) == 1
    return closed[0]


# --------------------------------------------------------------------- #
# Column structure
# --------------------------------------------------------------------- #
def test_extract_has_all_78_columns_in_order():
    flow = build_known_flow()
    feats = FeatureExtractor().extract(flow)
    assert list(feats.keys()) == FEATURE_COLUMNS
    assert len(feats) == 78
    assert LABEL_COLUMN not in feats  # Label is not part of the features


def test_extract_vector_length_and_floats():
    flow = build_known_flow()
    vec = FeatureExtractor().extract_vector(flow)
    assert len(vec) == 78
    assert all(isinstance(x, float) for x in vec)


# --------------------------------------------------------------------- #
# Hand-computed values
# --------------------------------------------------------------------- #
def test_counts_and_lengths():
    f = FeatureExtractor().extract(build_known_flow())
    assert f["Destination Port"] == 80
    assert f["Total Fwd Packets"] == 2
    assert f["Total Backward Packets"] == 2
    assert f["Total Length of Fwd Packets"] == 100
    assert f["Total Length of Bwd Packets"] == 200


def test_packet_length_stats():
    f = FeatureExtractor().extract(build_known_flow())
    assert f["Fwd Packet Length Max"] == 100
    assert f["Fwd Packet Length Min"] == 0
    assert f["Fwd Packet Length Mean"] == 50
    assert f["Fwd Packet Length Std"] == pytest.approx(statistics.stdev([0, 100]))
    assert f["Bwd Packet Length Mean"] == 100
    assert f["Min Packet Length"] == 0
    assert f["Max Packet Length"] == 200
    assert f["Packet Length Mean"] == pytest.approx(75.0)
    assert f["Packet Length Variance"] == pytest.approx(statistics.variance([0, 0, 100, 200]))


def test_duration_and_rates_microseconds():
    f = FeatureExtractor().extract(build_known_flow())
    assert f["Flow Duration"] == pytest.approx(2_000_000)  # 2 s -> us
    assert f["Flow Bytes/s"] == pytest.approx(150.0)       # 300 B / 2 s
    assert f["Flow Packets/s"] == pytest.approx(2.0)        # 4 pkt / 2 s
    assert f["Fwd Packets/s"] == pytest.approx(1.0)
    assert f["Bwd Packets/s"] == pytest.approx(1.0)


def test_iat_microseconds():
    f = FeatureExtractor().extract(build_known_flow())
    # all times: 0, 1, 1.5, 2 -> diffs 1.0, 0.5, 0.5 s
    assert f["Flow IAT Mean"] == pytest.approx(2_000_000 / 3)
    assert f["Flow IAT Max"] == pytest.approx(1_000_000)
    assert f["Flow IAT Min"] == pytest.approx(500_000)
    # fwd times 0, 1.5 -> single diff 1.5 s
    assert f["Fwd IAT Total"] == pytest.approx(1_500_000)
    assert f["Fwd IAT Std"] == 0.0  # single value
    # bwd times 1, 2 -> single diff 1.0 s
    assert f["Bwd IAT Total"] == pytest.approx(1_000_000)


def test_flag_counts():
    f = FeatureExtractor().extract(build_known_flow())
    # flags: S, SA, PA, A
    assert f["SYN Flag Count"] == 2
    assert f["ACK Flag Count"] == 3
    assert f["PSH Flag Count"] == 1
    assert f["FIN Flag Count"] == 0
    assert f["RST Flag Count"] == 0
    assert f["Fwd PSH Flags"] == 1   # only the fwd PA packet
    assert f["Bwd PSH Flags"] == 0


def test_header_window_and_misc():
    f = FeatureExtractor().extract(build_known_flow())
    assert f["Fwd Header Length"] == 40            # 2 * 20
    assert f["Fwd Header Length.1"] == 40          # CIC duplicate column
    assert f["Bwd Header Length"] == 40
    assert f["Init_Win_bytes_forward"] == 8192
    assert f["Init_Win_bytes_backward"] == 64240
    assert f["act_data_pkt_fwd"] == 1              # only the fwd packet with payload>0
    assert f["min_seg_size_forward"] == 20
    assert f["Down/Up Ratio"] == 1                 # 2 // 2
    assert f["Average Packet Size"] == pytest.approx(75.0)  # 300 / 4
    assert f["Avg Fwd Segment Size"] == 50
    assert f["Avg Bwd Segment Size"] == 100
    assert f["Subflow Fwd Bytes"] == 100


def test_bulk_features_zero():
    f = FeatureExtractor().extract(build_known_flow())
    for col in ("Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
                "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate"):
        assert f[col] == 0


def test_no_idle_for_short_flow():
    f = FeatureExtractor().extract(build_known_flow())
    # all gaps are below the 5s threshold -> no active/idle
    for col in ("Active Mean", "Active Max", "Idle Mean", "Idle Max"):
        assert f[col] == 0.0


# --------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------- #
def test_active_idle_split_on_large_gap():
    closed = []
    fm = FlowManager(on_flow_closed=closed.append, active_timeout=1000.0)
    # active 0..1 s, then a 10 s gap, then a single packet
    fm.process_packet(psum("1.1.1.1", "2.2.2.2", 5, 6, 0.0, 10, "PA"))
    fm.process_packet(psum("1.1.1.1", "2.2.2.2", 5, 6, 1.0, 10, "PA"))
    fm.process_packet(psum("1.1.1.1", "2.2.2.2", 5, 6, 11.0, 10, "PA"))
    fm.flush_all()
    f = FeatureExtractor(active_timeout_s=5.0).extract(closed[0])
    assert f["Active Max"] == pytest.approx(1_000_000)   # 0..1 s segment
    assert f["Idle Max"] == pytest.approx(10_000_000)    # 10 s gap


def test_single_packet_flow_no_crash():
    closed = []
    fm = FlowManager(on_flow_closed=closed.append)
    fm.process_packet(psum("1.1.1.1", "2.2.2.2", 5, 80, 7.0, 0, "S", 8192))
    fm.flush_all()
    f = FeatureExtractor().extract(closed[0])
    assert f["Flow Duration"] == 0
    assert f["Flow Bytes/s"] == 0.0          # no division by zero
    assert f["Flow IAT Mean"] == 0.0
    assert f["Fwd Packet Length Std"] == 0.0
    assert len(f) == 78


def test_udp_init_win_is_minus_one():
    closed = []
    fm = FlowManager(on_flow_closed=closed.append)
    fm.process_packet(psum("1.1.1.1", "8.8.8.8", 5353, 53, 0.0, 40, "", 0, 8, "UDP"))
    fm.process_packet(psum("8.8.8.8", "1.1.1.1", 53, 5353, 0.1, 80, "", 0, 8, "UDP"))
    fm.flush_all()
    f = FeatureExtractor().extract(closed[0])
    assert f["Init_Win_bytes_forward"] == -1   # not TCP
    assert f["Init_Win_bytes_backward"] == -1
