"""NetSentinel — Kontrollü saldırı simülatörü (Faz 8).

⚠️⚠️  YASAL & ETİK UYARI  ⚠️⚠️
Bu araç YALNIZCA kendi makinende / kendi izole lab ağında / sahibi olduğun
test sistemlerinde çalıştırılmalıdır. İzinsiz ağlara/sistemlere saldırı
düzenlemek çoğu ülkede SUÇTUR. Bu yazılımın kötüye kullanımından doğacak
tüm sorumluluk kullanıcıya aittir.

Güvenlik korumaları:
  * Hedef yalnız loopback (127.0.0.0/8, ::1) veya özel ağ (RFC1918) olabilir.
    Public IP hedefleri REDDEDİLİR.
  * Çalıştırmak için açık `--yes` onayı zorunludur.

Amaç: NetSentinel'in canlı tespitini kanıtlamak. Bir terminalde dedektörü/
dashboard'u, başka bir terminalde bu simülatörü çalıştır; saldırıların
tespit edilip edilmediğini gözlemle.

Kullanım (Windows'ta YÖNETİCİ, Npcap kurulu):
    python tests/attack_simulator.py port-scan --target 127.0.0.1 --yes
    python tests/attack_simulator.py syn-flood --target 127.0.0.1 --port 80 --count 500 --yes
    python tests/attack_simulator.py udp-flood --target 127.0.0.1 --port 53 --count 500 --yes
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
import time

try:
    from scapy.all import IP, TCP, UDP, RandShort, send
    SCAPY_AVAILABLE = True
except Exception:
    IP = TCP = UDP = RandShort = send = None
    SCAPY_AVAILABLE = False


# --------------------------------------------------------------------- #
# Güvenlik
# --------------------------------------------------------------------- #
def is_allowed_target(ip: str) -> bool:
    """Yalnız loopback ve özel (RFC1918) adreslere izin ver."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def guard(target: str, confirmed: bool) -> None:
    """İzin verilmeyen hedef ya da onaysız çalıştırmada programı durdurur."""
    if not is_allowed_target(target):
        print(f"[RED] Hedef '{target}' izin verilen aralıkta değil "
              "(yalnız loopback / özel ağ). İşlem iptal.")
        sys.exit(2)
    if not confirmed:
        print("[RED] Bu, yalnız KENDİ sistemlerinde çalıştırılmalı bir saldırı "
              "simülasyonudur. Onaylamak için --yes ekle.")
        sys.exit(2)
    print("=" * 60)
    print(" ⚠️  KONTROLLÜ SALDIRI SİMÜLASYONU")
    print(f"     Hedef: {target}  (yalnız test/lab)")
    print("=" * 60)


# --------------------------------------------------------------------- #
# Saldırı türleri
# --------------------------------------------------------------------- #
def port_scan(target: str, start: int, end: int, delay: float = 0.0) -> int:
    """SYN port taraması: her porta tek SYN gönderir."""
    n = 0
    for port in range(start, end + 1):
        pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=RandShort())
        send(pkt, verbose=0)
        n += 1
        if delay:
            time.sleep(delay)
    print(f"[ok] Port scan: {n} SYN -> {target}:{start}-{end}")
    return n


def syn_flood(target: str, port: int, count: int, delay: float = 0.0) -> int:
    """SYN flood (DoS benzeri): aynı porta hızlı SYN akışı."""
    for _ in range(count):
        pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=RandShort())
        send(pkt, verbose=0)
        if delay:
            time.sleep(delay)
    print(f"[ok] SYN flood: {count} SYN -> {target}:{port}")
    return count


def udp_flood(target: str, port: int, count: int, delay: float = 0.0) -> int:
    """UDP flood: hedef porta UDP paket akışı."""
    payload = b"X" * 64
    for _ in range(count):
        pkt = IP(dst=target) / UDP(dport=port, sport=RandShort()) / payload
        send(pkt, verbose=0)
        if delay:
            time.sleep(delay)
    print(f"[ok] UDP flood: {count} paket -> {target}:{port}")
    return count


# --------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description="NetSentinel kontrollü saldırı simülatörü")
    sub = p.add_subparsers(dest="attack", required=True)

    ps = sub.add_parser("port-scan")
    ps.add_argument("--target", required=True)
    ps.add_argument("--ports", default="1-1024", help="örn 1-1024")
    ps.add_argument("--delay", type=float, default=0.0)
    ps.add_argument("--yes", action="store_true")

    sf = sub.add_parser("syn-flood")
    sf.add_argument("--target", required=True)
    sf.add_argument("--port", type=int, default=80)
    sf.add_argument("--count", type=int, default=500)
    sf.add_argument("--delay", type=float, default=0.0)
    sf.add_argument("--yes", action="store_true")

    uf = sub.add_parser("udp-flood")
    uf.add_argument("--target", required=True)
    uf.add_argument("--port", type=int, default=53)
    uf.add_argument("--count", type=int, default=500)
    uf.add_argument("--delay", type=float, default=0.0)
    uf.add_argument("--yes", action="store_true")

    args = p.parse_args()

    if not SCAPY_AVAILABLE:
        print("[HATA] Scapy yok. `pip install scapy` + Npcap (Windows) gerekli.")
        return 1

    guard(args.target, args.yes)

    if args.attack == "port-scan":
        start, end = (int(x) for x in args.ports.split("-"))
        port_scan(args.target, start, end, args.delay)
    elif args.attack == "syn-flood":
        syn_flood(args.target, args.port, args.count, args.delay)
    elif args.attack == "udp-flood":
        udp_flood(args.target, args.port, args.count, args.delay)
    return 0


if __name__ == "__main__":
    sys.exit(main())
