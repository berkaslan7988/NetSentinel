"""NetSentinel - FlowManager (Phase 1).

Aggregates raw packet summaries (PacketSummary) into bidirectional flows (Flow)
and closes them under these rules:

  * Active timeout - force-close a flow that lasts longer than `active_timeout` s.
  * Idle timeout   - close a flow that receives no packet for `idle_timeout` s.
  * TCP FIN/RST    - close a flow immediately when these flags are seen.

Each closed flow is handed to the `on_flow_closed(flow)` callback.

Design notes (roadmap Section 2 & pitfalls):
  * Thread-safe: the flow dictionary is managed under a single lock.
  * Against memory leaks: `start_cleanup()` launches a background thread that
    periodically closes idle/active flows. Otherwise flows that never close pile
    up in the dictionary.
  * Time source: flow times come from the packet's own timestamp (for
    consistency in offline pcap tests). For idle scanning a "now" can be
    injected; live mode uses time.time().
  * Callbacks are invoked OUTSIDE the lock (to avoid re-entry/deadlock).
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from capture.sniffer import PacketSummary
from flows.flow import CloseReason, Direction, Flow, PacketRecord

# Direction-independent flow key:
# (protocol, frozenset{(ip1,port1),(ip2,port2)}) - A->B and B->A yield the same key.
FlowKey = Tuple[str, frozenset]

# Flags that close a TCP flow
_FIN = "F"
_RST = "R"


def canonical_key(pkt: PacketSummary) -> FlowKey:
    """Builds a direction-independent flow key from a packet."""
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    return (pkt.protocol, frozenset((a, b)))


class FlowManager:
    def __init__(
        self,
        on_flow_closed: Callable[[Flow], None],
        active_timeout: float = 120.0,
        idle_timeout: float = 15.0,
    ) -> None:
        self.on_flow_closed = on_flow_closed
        self.active_timeout = active_timeout
        self.idle_timeout = idle_timeout

        self._flows: Dict[FlowKey, Flow] = {}
        self._lock = threading.Lock()

        self._cleanup_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self.flows_closed = 0

    # ------------------------------------------------------------------ #
    # Packet processing
    # ------------------------------------------------------------------ #
    def process_packet(self, pkt: PacketSummary) -> None:
        """Adds a single packet to its flow; closes the flow if needed."""
        key = canonical_key(pkt)
        closed: List[Flow] = []

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                # First packet -> the initiator is this packet's source (forward).
                flow = Flow(
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port if pkt.src_port is not None else 0,
                    dst_port=pkt.dst_port if pkt.dst_port is not None else 0,
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp,
                    last_time=pkt.timestamp,
                )
                self._flows[key] = flow

            direction = (
                Direction.FORWARD if pkt.src_ip == flow.src_ip else Direction.BACKWARD
            )
            flow.add_packet(
                PacketRecord(
                    timestamp=pkt.timestamp,
                    payload_len=pkt.payload_len,
                    flags=pkt.tcp_flags,
                    header_len=pkt.header_len,
                    window=pkt.window,
                ),
                direction,
            )

            # Close decisions (priority: FIN/RST > active timeout)
            reason: Optional[CloseReason] = None
            if _RST in pkt.tcp_flags:
                reason = CloseReason.RST
            elif _FIN in pkt.tcp_flags:
                reason = CloseReason.FIN
            elif flow.duration >= self.active_timeout:
                reason = CloseReason.ACTIVE_TIMEOUT

            if reason is not None:
                self._close_locked(key, reason, closed)

        # Invoke callbacks outside the lock
        for f in closed:
            self.on_flow_closed(f)

    # ------------------------------------------------------------------ #
    # Timeout scanning
    # ------------------------------------------------------------------ #
    def check_timeouts(self, now: Optional[float] = None) -> int:
        """Closes flows hit by idle or active timeout.

        If `now` is not given, time.time() is used (live mode). Tests pass a
        specific time to inject. Returns the number of closed flows.
        """
        if now is None:
            now = time.time()

        closed: List[Flow] = []
        with self._lock:
            for key, flow in list(self._flows.items()):
                if now - flow.last_time >= self.idle_timeout:
                    self._close_locked(key, CloseReason.IDLE_TIMEOUT, closed)
                elif now - flow.start_time >= self.active_timeout:
                    self._close_locked(key, CloseReason.ACTIVE_TIMEOUT, closed)

        for f in closed:
            self.on_flow_closed(f)
        return len(closed)

    def flush_all(self) -> int:
        """Closes all remaining open flows (call on shutdown). Returns the count."""
        closed: List[Flow] = []
        with self._lock:
            for key in list(self._flows.keys()):
                self._close_locked(key, CloseReason.FLUSH, closed)
        for f in closed:
            self.on_flow_closed(f)
        return len(closed)

    # ------------------------------------------------------------------ #
    # Background cleanup thread
    # ------------------------------------------------------------------ #
    def start_cleanup(self, interval: float = 5.0) -> None:
        """Starts the background thread that periodically scans for timeouts."""
        if self._cleanup_thread is not None:
            return
        self._stop_event.clear()

        def _loop() -> None:
            while not self._stop_event.wait(interval):
                try:
                    self.check_timeouts()
                except Exception:  # keep the thread from dying silently
                    pass

        self._cleanup_thread = threading.Thread(
            target=_loop, name="FlowCleanup", daemon=True
        )
        self._cleanup_thread.start()

    def stop_cleanup(self) -> None:
        self._stop_event.set()
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=2.0)
            self._cleanup_thread = None

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def _close_locked(
        self, key: FlowKey, reason: CloseReason, sink: List[Flow]
    ) -> None:
        """Must be called UNDER the lock. Removes the flow, appends to sink."""
        flow = self._flows.pop(key, None)
        if flow is None:
            return
        flow.close_reason = reason
        self.flows_closed += 1
        sink.append(flow)
