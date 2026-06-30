"""Unit tests for flows.manager and flows.flow.

PacketSummary objects are built by hand - no Scapy/network needed. This sustains
NetScope's "pure, UI/hardware-independent, testable layer" approach.
"""
from capture.sniffer import PacketSummary
from flows.flow import CloseReason, Direction, Flow, PacketRecord
from flows.manager import FlowManager, canonical_key


def pkt(src_ip, dst_ip, src_port, dst_port, ts, length=100, flags="",
        proto="TCP", header_len=20, window=0):
    # payload_len = length: byte stats use this value.
    return PacketSummary(
        timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=proto, length=length, tcp_flags=flags,
        payload_len=length, header_len=header_len, window=window,
    )


def collect():
    """Returns a list collecting closed flows + the callback that appends to it."""
    closed = []
    return closed, closed.append


# --------------------------------------------------------------------- #
# Canonical key / direction
# --------------------------------------------------------------------- #
def test_bidirectional_same_key():
    a = pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0)
    b = pkt("10.0.0.2", "10.0.0.1", 80, 1234, ts=0.1)
    assert canonical_key(a) == canonical_key(b)


def test_different_flows_different_keys():
    a = pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0)
    c = pkt("10.0.0.1", "10.0.0.3", 1234, 80, ts=0.0)
    assert canonical_key(a) != canonical_key(c)


def test_fwd_bwd_direction_assignment():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb)
    # initiator = 10.0.0.1
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0, length=100))
    fm.process_packet(pkt("10.0.0.2", "10.0.0.1", 80, 1234, ts=0.1, length=500))
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.2, length=100))
    fm.flush_all()
    assert len(closed) == 1
    flow = closed[0]
    assert flow.fwd_packet_count == 2  # 10.0.0.1 -> 10.0.0.2
    assert flow.bwd_packet_count == 1  # 10.0.0.2 -> 10.0.0.1
    assert flow.fwd_bytes == 200
    assert flow.bwd_bytes == 500
    assert flow.total_bytes == 700


# --------------------------------------------------------------------- #
# Flow count / duration
# --------------------------------------------------------------------- #
def test_two_separate_flows_counted():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1111, 80, ts=0.0))
    fm.process_packet(pkt("10.0.0.1", "10.0.0.3", 2222, 80, ts=0.0))
    assert fm.active_flow_count == 2
    fm.flush_all()
    assert len(closed) == 2


def test_flow_duration():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=10.0))
    fm.process_packet(pkt("10.0.0.2", "10.0.0.1", 80, 1234, ts=13.5))
    fm.flush_all()
    assert closed[0].duration == 3.5


# --------------------------------------------------------------------- #
# Close rules
# --------------------------------------------------------------------- #
def test_rst_closes_flow_immediately():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0, flags="S"))
    fm.process_packet(pkt("10.0.0.2", "10.0.0.1", 80, 1234, ts=0.1, flags="R"))
    assert len(closed) == 1
    assert closed[0].close_reason is CloseReason.RST
    assert fm.active_flow_count == 0


def test_fin_closes_flow():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0, flags="S"))
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.5, flags="FA"))
    assert len(closed) == 1
    assert closed[0].close_reason is CloseReason.FIN


def test_idle_timeout_closes_flow():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb, idle_timeout=15.0, active_timeout=120.0)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0))
    # scan after 20 s -> idle (>15s)
    n = fm.check_timeouts(now=20.0)
    assert n == 1
    assert closed[0].close_reason is CloseReason.IDLE_TIMEOUT


def test_idle_timeout_not_triggered_too_early():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb, idle_timeout=15.0)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0))
    assert fm.check_timeouts(now=10.0) == 0  # only 10s in
    assert fm.active_flow_count == 1


def test_active_timeout_closes_long_flow():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb, idle_timeout=15.0, active_timeout=120.0)
    # feed every 5 s so it doesn't go idle but exceeds 120s
    for t in range(0, 130, 5):
        fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=float(t)))
    # the active-timeout check inside process_packet should have closed the flow
    assert len(closed) == 1
    assert closed[0].close_reason is CloseReason.ACTIVE_TIMEOUT


# --------------------------------------------------------------------- #
# Flag counters & Flow metrics
# --------------------------------------------------------------------- #
def test_flag_counts_accumulate():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0, flags="S"))
    fm.process_packet(pkt("10.0.0.2", "10.0.0.1", 80, 1234, ts=0.1, flags="SA"))
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.2, flags="A"))
    fm.flush_all()
    fc = closed[0].flag_counts
    assert fc["SYN"] == 2
    assert fc["ACK"] == 2


def test_flow_iat_mean():
    flow = Flow("a", "b", 1, 2, "TCP", start_time=0.0, last_time=0.0)
    for t in (0.0, 1.0, 3.0):  # IATs: 1.0, 2.0 -> mean 1.5
        flow.add_packet(PacketRecord(timestamp=t, payload_len=50), Direction.FORWARD)
    assert flow.iat_mean == 1.5


def test_single_packet_flow_zero_duration_no_crash():
    flow = Flow("a", "b", 1, 2, "TCP", start_time=5.0, last_time=5.0)
    flow.add_packet(PacketRecord(timestamp=5.0, payload_len=50), Direction.FORWARD)
    assert flow.duration == 0.0
    assert flow.bytes_per_second == 0.0   # division-by-zero guard
    assert flow.packets_per_second == 0.0
    assert flow.iat_mean == 0.0


def test_flush_uses_flush_reason():
    closed, cb = collect()
    fm = FlowManager(on_flow_closed=cb)
    fm.process_packet(pkt("10.0.0.1", "10.0.0.2", 1234, 80, ts=0.0))
    fm.flush_all()
    assert closed[0].close_reason is CloseReason.FLUSH
