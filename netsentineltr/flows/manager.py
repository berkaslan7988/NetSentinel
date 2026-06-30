"""NetSentinel — FlowManager (Faz 1).

Ham paket özetlerini (PacketSummary) çift yönlü akışlara (Flow) birleştirir
ve şu kurallarla kapatır:

  * **Active timeout** — akış `active_timeout` sn'den uzun sürerse zorla kapat.
  * **Idle timeout** — akışa `idle_timeout` sn boyunca paket gelmezse kapat.
  * **TCP FIN/RST** — bu flag'ler görülünce akışı hemen kapat.

Kapanan her akış `on_flow_closed(flow)` callback'ine verilir.

Tasarım notları (roadmap Bölüm 2 & tuzaklar):
  * Thread-safe: tek bir kilit altında akış sözlüğü yönetilir.
  * Bellek sızıntısına karşı: `start_cleanup()` ile bir arka plan thread'i
    periyodik olarak idle/active akışları kapatır. Aksi halde kapanmayan
    akışlar sözlükte birikir.
  * Zaman kaynağı: akış zamanları **paketin kendi timestamp'inden** gelir
    (offline pcap testlerinde tutarlılık için). Idle taraması için "now"
    enjekte edilebilir; canlıda `time.time()` kullanılır.
  * Callback'ler kilit DIŞINDA çağrılır (yeniden giriş/deadlock olmasın).
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from capture.sniffer import PacketSummary
from flows.flow import CloseReason, Direction, Flow, PacketRecord

# Akışı yöne bağımsız tanımlayan kanonik anahtar:
# (protocol, frozenset{(ip1,port1),(ip2,port2)}) — A->B ve B->A aynı anahtarı verir.
FlowKey = Tuple[str, frozenset]

# TCP'de akışı kapatan flag'ler
_FIN = "F"
_RST = "R"


def canonical_key(pkt: PacketSummary) -> FlowKey:
    """Bir paketten yöne bağımsız akış anahtarı üretir."""
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

        # İstatistik
        self.flows_closed = 0

    # ------------------------------------------------------------------ #
    # Paket işleme
    # ------------------------------------------------------------------ #
    def process_packet(self, pkt: PacketSummary) -> None:
        """Tek bir paketi ilgili akışa ekler; gerekirse akışı kapatır."""
        key = canonical_key(pkt)
        closed: List[Flow] = []

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                # İlk paket -> initiator bu paketin kaynağıdır (forward yönü).
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

            # Kapatma kararları (öncelik: FIN/RST > active timeout)
            reason: Optional[CloseReason] = None
            if _RST in pkt.tcp_flags:
                reason = CloseReason.RST
            elif _FIN in pkt.tcp_flags:
                reason = CloseReason.FIN
            elif flow.duration >= self.active_timeout:
                reason = CloseReason.ACTIVE_TIMEOUT

            if reason is not None:
                self._close_locked(key, reason, closed)

        # Callback'leri kilit dışında çağır
        for f in closed:
            self.on_flow_closed(f)

    # ------------------------------------------------------------------ #
    # Timeout taraması
    # ------------------------------------------------------------------ #
    def check_timeouts(self, now: Optional[float] = None) -> int:
        """Idle ve active timeout'a takılan akışları kapatır.

        `now` verilmezse `time.time()` kullanılır (canlı mod). Testlerde
        belirli bir zaman enjekte etmek için parametre geçilir.
        Kapatılan akış sayısını döndürür.
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
        """Kalan tüm açık akışları kapatır (kapanışta çağır). Sayıyı döndürür."""
        closed: List[Flow] = []
        with self._lock:
            for key in list(self._flows.keys()):
                self._close_locked(key, CloseReason.FLUSH, closed)
        for f in closed:
            self.on_flow_closed(f)
        return len(closed)

    # ------------------------------------------------------------------ #
    # Arka plan temizlik thread'i
    # ------------------------------------------------------------------ #
    def start_cleanup(self, interval: float = 5.0) -> None:
        """Periyodik timeout taraması yapan arka plan thread'ini başlatır."""
        if self._cleanup_thread is not None:
            return
        self._stop_event.clear()

        def _loop() -> None:
            while not self._stop_event.wait(interval):
                try:
                    self.check_timeouts()
                except Exception:  # thread'in sessizce ölmesini engelle
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
    # Yardımcılar
    # ------------------------------------------------------------------ #
    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def _close_locked(
        self, key: FlowKey, reason: CloseReason, sink: List[Flow]
    ) -> None:
        """Kilit ALTINDA çağrılmalı. Akışı sözlükten çıkarır, sink'e ekler."""
        flow = self._flows.pop(key, None)
        if flow is None:
            return
        flow.close_reason = reason
        self.flows_closed += 1
        sink.append(flow)
