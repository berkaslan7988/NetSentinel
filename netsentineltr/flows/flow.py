"""NetSentinel — Flow modeli (Faz 1).

Bir akış (flow) = aynı 5'li anahtara (src_ip, dst_ip, src_port, dst_port,
protocol) sahip, çift yönlü (bidirectional) paketler dizisi.

Yön (direction) tanımı: akışı **ilk paketi gönderen** taraf "forward" (fwd)
kabul edilir; karşı yön "backward" (bwd). Bu, CICFlowMeter / CIC-IDS2017
mantığıyla uyumludur ve Faz 2 özellik çıkarımının temelidir.

Flow nesnesi UI'dan ve yakalamadan bağımsızdır; saf veri + hesaplanmış
property'ler içerir, böylece donanım/ağ olmadan test edilebilir.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Direction(Enum):
    """Paketin akış içindeki yönü."""
    FORWARD = "fwd"
    BACKWARD = "bwd"


class CloseReason(Enum):
    """Akışın neden kapatıldığı."""
    FIN = "fin"                      # TCP FIN görüldü
    RST = "rst"                      # TCP RST görüldü
    ACTIVE_TIMEOUT = "active_timeout"  # akış çok uzun sürdü
    IDLE_TIMEOUT = "idle_timeout"    # belirli süre paket gelmedi
    FLUSH = "flush"                  # kapanışta zorla boşaltıldı


# Tek bir flag harfi -> sayaç anahtarı (CIC-IDS2017 flag sayaçlarıyla uyumlu)
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
    """Akış içinde tutulan tek paketin minimal kaydı.

    payload_len : L4 yük uzunluğu (CIC "packet length" — byte istatistiklerinin temeli).
    header_len  : IP + TCP/UDP başlık baytları.
    window      : TCP pencere boyutu (Init_Win_bytes_* için), TCP değilse 0.
    """
    timestamp: float
    payload_len: int
    flags: str = ""
    header_len: int = 0
    window: int = 0


@dataclass
class Flow:
    """Çift yönlü bir ağ akışı.

    src_* alanları akışı **başlatan** (initiator) tarafa aittir; bu yüzden
    forward = initiator -> diğer uç, backward = diğer uç -> initiator.
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

    # Tüm akış boyunca toplam TCP flag sayaçları (FIN/SYN/RST/PSH/ACK/URG...)
    flag_counts: dict = field(default_factory=lambda: {v: 0 for v in FLAG_LETTERS.values()})

    close_reason: CloseReason | None = None

    # ------------------------------------------------------------------ #
    # Paket ekleme
    # ------------------------------------------------------------------ #
    def add_packet(self, record: PacketRecord, direction: Direction) -> None:
        """Akışa bir paket ekler ve sayaçları/zaman damgalarını günceller."""
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
    # Hesaplanmış özellikler
    # ------------------------------------------------------------------ #
    @property
    def duration(self) -> float:
        """Akış süresi (saniye)."""
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
        """Tüm yönlerdeki ardışık paketler arası süreler (IAT).

        Faz 2'de Flow IAT Mean/Std/Max/Min özelliklerinin temeli.
        """
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
        """'Flow closed: ...' tarzı tek satırlık özet (terminal logu için)."""
        reason = self.close_reason.value if self.close_reason else "open"
        return (
            f"{self.protocol} {self.src_ip}:{self.src_port} <-> "
            f"{self.dst_ip}:{self.dst_port} | "
            f"{self.total_packets} pkts "
            f"(fwd {self.fwd_packet_count}/bwd {self.bwd_packet_count}), "
            f"{self.total_bytes} B, {self.duration:.2f}s [{reason}]"
        )
