"""NetSentinel - Flow model (Phase 1).

A flow = a sequence of bidirectional packets sharing the same 5-tuple key
(src_ip, dst_ip, src_port, dst_port, protocol).

Direction definition: the side that sends the flow's first packet is the
"forward" (fwd) side; the opposite direction is "backward" (bwd). This matches
CICFlowMeter / CIC-IDS2017 and is the basis of Phase 2 feature extraction.

The Flow object is independent of UI and capture; it holds plain data plus
computed properties, so it can be tested without hardware/network.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Direction(Enum):
    """A packet's direction within the flow."""
    FORWARD = "fwd"
    BACKWARD = "bwd"


class CloseReason(Enum):
    """Why a flow was closed."""
    FIN = "fin"                      # TCP FIN seen
    RST = "rst"                      # TCP RST seen
    ACTIVE_TIMEOUT = "active_timeout"  # flow lived too long
    IDLE_TIMEOUT = "idle_timeout"    # no packet for a while
    FLUSH = "flush"                  # force-flushed on shutdown


# Single flag letter -> counter key (matches CIC-IDS2017 flag counters)
FLAG_LETTERS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


@dataclass
class PacketRecord:
    """Minimal record of a single packet held within a flow.

    payload_len : L4 payload length (CIC "packet length" - basis of byte stats).
    header_len  : IP + TCP/UDP header bytes.
    window      : TCP window size (for Init_Win_bytes_*), 0 if not TCP.
    """
    timestamp: float
    payload_len: int
    flags: str = ""
    header_len: int = 0
    window: int = 0


@dataclass
class Flow:
    """A bidirectional network flow.

    The src_* fields belong to the flow's initiator; therefore
    forward = initiator -> other end, backward = other end -> initiator.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float
    last_time: float

    fwd_packets: List[PacketRecord] = field(default_factory=list)
    bwd_packets: List[PacketRecord] = field(default_factory=list)

    # Aggregate TCP flag counters over the whole flow (FIN/SYN/RST/PSH/ACK/URG...)
    flag_counts: dict = field(default_factory=lambda: {v: 0 for v in FLAG_LETTERS.values()})

    close_reason: CloseReason | None = None

    # ------------------------------------------------------------------ #
    # Adding packets
    # ------------------------------------------------------------------ #
    def add_packet(self, record: PacketRecord, direction: Direction) -> None:
        """Adds a packet to the flow and updates counters/timestamps."""
        if direction is Direction.FORWARD:
            self.fwd_packets.append(record)
        else:
            self.bwd_packets.append(record)

        if record.timestamp > self.last_time:
            self.last_time = record.timestamp

        for letter in record.flags:
            name = FLAG_LETTERS.get(letter)
            if name is not None:
                self.flag_counts[name] += 1

    # ------------------------------------------------------------------ #
    # Computed properties
    # ------------------------------------------------------------------ #
    @property
    def duration(self) -> float:
        """Flow duration (seconds)."""
        return max(0.0, self.last_time - self.start_time)

    @property
    def fwd_packet_count(self) -> int:
        return len(self.fwd_packets)

    @property
    def bwd_packet_count(self) -> int:
        return len(self.bwd_packets)

    @property
    def total_packets(self) -> int:
        return self.fwd_packet_count + self.bwd_packet_count

    @property
    def fwd_bytes(self) -> int:
        return sum(p.payload_len for p in self.fwd_packets)

    @property
    def bwd_bytes(self) -> int:
        return sum(p.payload_len for p in self.bwd_packets)

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def bytes_per_second(self) -> float:
        d = self.duration
        return self.total_bytes / d if d > 0 else 0.0

    @property
    def packets_per_second(self) -> float:
        d = self.duration
        return self.total_packets / d if d > 0 else 0.0

    def inter_arrival_times(self) -> List[float]:
        """Inter-arrival times (IAT) between consecutive packets across both
        directions. The basis of the Flow IAT Mean/Std/Max/Min features (Phase 2)."""
        ts = sorted(
            p.timestamp for p in (self.fwd_packets + self.bwd_packets)
        )
        return [t2 - t1 for t1, t2 in zip(ts, ts[1:])]

    @property
    def iat_mean(self) -> float:
        iats = self.inter_arrival_times()
        return statistics.fmean(iats) if iats else 0.0

    # ------------------------------------------------------------------ #
    def summary(self) -> str:
        """One-line 'Flow closed: ...' style summary (for terminal logs)."""
        reason = self.close_reason.value if self.close_reason else "open"
        return (
            f"{self.protocol} {self.src_ip}:{self.src_port} <-> "
            f"{self.dst_ip}:{self.dst_port} | "
            f"{self.total_packets} pkts "
            f"(fwd {self.fwd_packet_count}/bwd {self.bwd_packet_count}), "
            f"{self.total_bytes} B, {self.duration:.2f}s [{reason}]"
        )
