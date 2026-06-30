"""NetSentinel - Capture Layer (Phase 0 prototype).

Captures live packets with Scapy's AsyncSniffer. The capture thread is kept
LIGHT: each packet is only summarized and handed to a callback, no heavy work
(the critical design rule from the roadmap - Section 2).

`summarize_packet` is a pure function and can be tested with Scapy packet
objects; it does not require live capture.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

try:
    from scapy.all import AsyncSniffer
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except Exception:  # so the module still imports without Scapy (e.g. CI)
    AsyncSniffer = None  # type: ignore
    IP = TCP = UDP = IPv6 = None  # type: ignore
    SCAPY_AVAILABLE = False


# Protocol number -> name mapping (common ones)
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _int_or(value, default: int) -> int:
    """Converts a Scapy field to int; returns default if None (e.g. an
    in-memory packet that hasn't been built yet)."""
    return int(value) if value is not None else default


@dataclass
class PacketSummary:
    """Lightweight summary of a single packet. The input type fed to Flow
    in Phase 1.

    tcp_flags: Scapy-style flag letters (e.g. "SA" = SYN+ACK). Empty for
    non-TCP packets. FlowManager uses it for FIN/RST closing, and the
    FeatureExtractor (Phase 2) for flag counters.

    Extra fields for Phase 2 (CIC-IDS2017 compatibility):
      payload_len : L4 payload length - this is the CIC "packet length".
      header_len  : IP + TCP/UDP header bytes (Header Length features).
      window      : TCP window size (Init_Win_bytes_*), 0 if not TCP.
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int            # full frame length (for terminal display)
    tcp_flags: str = ""
    payload_len: int = 0
    header_len: int = 0
    window: int = 0

    def __str__(self) -> str:
        sp = self.src_port if self.src_port is not None else "-"
        dp = self.dst_port if self.dst_port is not None else "-"
        flags = f" [{self.tcp_flags}]" if self.tcp_flags else ""
        return (
            f"[{self.protocol:5}] {self.src_ip}:{sp} -> "
            f"{self.dst_ip}:{dp}  {self.length} B{flags}"
        )


def summarize_packet(pkt) -> Optional[PacketSummary]:
    """Reduces a Scapy packet to a PacketSummary.

    Returns None if there is no IP/IPv6 layer (ARP, raw L2, etc. are skipped).
    Pure function: no side effects, easy to test.
    """
    ip_header_len = 0
    if IP is not None and pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst, proto_num = ip.src, ip.dst, ip.proto
        ip_header_len = _int_or(getattr(ip, "ihl", 5), 5) * 4  # IPv4 header (ihl words)
    elif IPv6 is not None and pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        src, dst, proto_num = ip.src, ip.dst, ip.nh  # nh = next header
        ip_header_len = 40  # IPv6 fixed main header
    else:
        return None

    src_port = dst_port = None
    tcp_flags = ""
    window = 0
    l4_header_len = 0
    payload_len = 0
    if TCP is not None and pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = str(tcp.flags)  # e.g. "SA", "FA", "R"
        window = _int_or(tcp.window, 0)
        l4_header_len = _int_or(getattr(tcp, "dataofs", 5), 5) * 4  # TCP data offset (words)
        payload_len = len(tcp.payload)
        proto_name = "TCP"
    elif UDP is not None and pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        l4_header_len = 8  # fixed UDP header
        payload_len = len(udp.payload)
        proto_name = "UDP"
    else:
        proto_name = _PROTO_NAMES.get(int(proto_num), str(proto_num))
        payload_len = len(ip.payload)

    return PacketSummary(
        timestamp=float(getattr(pkt, "time", 0.0)),
        src_ip=str(src),
        dst_ip=str(dst),
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto_name,
        length=len(pkt),
        tcp_flags=tcp_flags,
        payload_len=payload_len,
        header_len=ip_header_len + l4_header_len,
        window=window,
    )


class Sniffer:
    """A thin wrapper over Scapy's AsyncSniffer.

    Each captured packet goes through `summarize_packet` and the result is
    handed to the `on_packet` callback. Keeping that callback light is the
    caller's responsibility (e.g. just push onto a queue).
    """

    def __init__(
        self,
        on_packet: Callable[[PacketSummary], None],
        iface: Optional[str] = None,
        bpf_filter: str = "ip",
    ) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is not installed. `pip install scapy` and Npcap (Windows) required."
            )
        self.on_packet = on_packet
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._sniffer: Optional[AsyncSniffer] = None

    def _handle(self, pkt) -> None:
        summary = summarize_packet(pkt)
        if summary is not None:
            self.on_packet(summary)

    def start(self) -> None:
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter or None,
            prn=self._handle,
            store=False,  # don't buffer packets in memory
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
