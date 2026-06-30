"""NetSentinel — Capture Layer (Faz 0 prototipi).

Scapy AsyncSniffer ile canlı paket yakalar. Yakalama thread'i HAFİF tutulur:
her paket sadece özetlenip bir callback'e verilir, ağır iş yapılmaz
(roadmap'teki kritik tasarım kuralı — Bölüm 2).

Bu modüldeki `summarize_packet` saf (pure) bir fonksiyondur ve Scapy paket
nesneleriyle test edilebilir; canlı yakalama gerektirmez.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

try:
    from scapy.all import AsyncSniffer
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except Exception:  # Scapy yoksa (örn. CI ortamı) modül yine import edilebilsin
    AsyncSniffer = None  # type: ignore
    IP = TCP = UDP = IPv6 = None  # type: ignore
    SCAPY_AVAILABLE = False


# Protokol numarası -> isim eşlemesi (yaygın olanlar)
_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _int_or(value, default: int) -> int:
    """Scapy alanını int'e çevirir; None ise (örn. henüz build edilmemiş
    in-memory paket) default döner."""
    return int(value) if value is not None else default


@dataclass
class PacketSummary:
    """Tek bir paketin hafif özeti. Faz 1'de Flow'a beslenecek girdi tipi.

    tcp_flags: Scapy biçiminde flag harfleri (örn. "SA" = SYN+ACK). TCP
    olmayan paketlerde boş string. FlowManager bunu FIN/RST kapatması için,
    FeatureExtractor (Faz 2) flag sayaçları için kullanır.

    Faz 2 için ek alanlar (CIC-IDS2017 uyumu):
      payload_len : L4 yük (payload) uzunluğu — CIC "packet length" budur.
      header_len  : IP + TCP/UDP başlık baytları (Header Length özellikleri).
      window      : TCP pencere boyutu (Init_Win_bytes_*), TCP değilse 0.
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int            # tam çerçeve uzunluğu (terminal gösterimi için)
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
    """Bir Scapy paketini PacketSummary'ye indirger.

    IP/IPv6 katmanı yoksa None döner (ARP, raw L2 vb. atlanır).
    Saf fonksiyon: yan etkisi yok, kolayca test edilebilir.
    """
    ip_header_len = 0
    if IP is not None and pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst, proto_num = ip.src, ip.dst, ip.proto
        ip_header_len = _int_or(getattr(ip, "ihl", 5), 5) * 4  # IPv4 başlık (ihl kelime)
    elif IPv6 is not None and pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        src, dst, proto_num = ip.src, ip.dst, ip.nh  # nh = next header
        ip_header_len = 40  # IPv6 sabit ana başlık
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
        tcp_flags = str(tcp.flags)  # örn. "SA", "FA", "R"
        window = _int_or(tcp.window, 0)
        l4_header_len = _int_or(getattr(tcp, "dataofs", 5), 5) * 4  # TCP data offset (kelime)
        payload_len = len(tcp.payload)
        proto_name = "TCP"
    elif UDP is not None and pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        l4_header_len = 8  # UDP başlık sabit
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
    """Scapy AsyncSniffer üzerine ince bir sarmalayıcı.

    Her yakalanan paket `summarize_packet`'ten geçirilir ve sonuç
    `on_packet` callback'ine verilir. Callback'i hafif tutmak çağıranın
    sorumluluğundadır (örn. sadece bir queue'ya at).
    """

    def __init__(
        self,
        on_packet: Callable[[PacketSummary], None],
        iface: Optional[str] = None,
        bpf_filter: str = "ip",
    ) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy yüklü değil. `pip install scapy` ve Npcap (Windows) gerekli."
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
            store=False,  # paketleri bellekte biriktirme
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
