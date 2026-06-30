"""NetSentinel - Controlled attack simulator (Phase 8).

WARNING - LEGAL & ETHICAL
This tool must ONLY be run against your own machine / your own isolated lab /
systems you own. Launching attacks against networks or systems without
authorization is a CRIME in most jurisdictions. All responsibility for misuse
lies with the user.

Safety guards:
  * The target may only be loopback (127.0.0.0/8, ::1) or a private network
    (RFC1918). Public IP targets are REFUSED.
  * Explicit `--yes` confirmation is required to run.

Purpose: to demonstrate NetSentinel's live detection. Run the detector/dashboard
in one terminal and this simulator in another; observe whether the attacks get
detected.

Usage (run as ADMINISTRATOR on Windows, Npcap installed):
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
# Safety
# --------------------------------------------------------------------- #
def is_allowed_target(ip: str) -> bool:
    """Allow only loopback and private (RFC1918) addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def guard(target: str, confirmed: bool) -> None:
    """Stops the program for a disallowed target or an unconfirmed run."""
    if not is_allowed_target(target):
        print(f"[REFUSED] target '{target}' is not in the allowed range "
              "(loopback / private network only). Aborting.")
        sys.exit(2)
    if not confirmed:
        print("[REFUSED] This is an attack simulation that must only be run "
              "against YOUR OWN systems. Add --yes to confirm.")
        sys.exit(2)
    print("=" * 60)
    print("  CONTROLLED ATTACK SIMULATION")
    print(f"     Target: {target}  (test/lab only)")
    print("=" * 60)


# --------------------------------------------------------------------- #
# Attack types
# --------------------------------------------------------------------- #
def port_scan(target: str, start: int, end: int, delay: float = 0.0) -> int:
    """SYN port scan: sends a single SYN to each port."""
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
    """SYN flood (DoS-like): a rapid SYN stream to one port."""
    for _ in range(count):
        pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=RandShort())
        send(pkt, verbose=0)
        if delay:
            time.sleep(delay)
    print(f"[ok] SYN flood: {count} SYN -> {target}:{port}")
    return count


def udp_flood(target: str, port: int, count: int, delay: float = 0.0) -> int:
    """UDP flood: a UDP packet stream to the target port."""
    payload = b"X" * 64
    for _ in range(count):
        pkt = IP(dst=target) / UDP(dport=port, sport=RandShort()) / payload
        send(pkt, verbose=0)
        if delay:
            time.sleep(delay)
    print(f"[ok] UDP flood: {count} packets -> {target}:{port}")
    return count


# --------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description="NetSentinel controlled attack simulator")
    sub = p.add_subparsers(dest="attack", required=True)

    ps = sub.add_parser("port-scan")
    ps.add_argument("--target", required=True)
    ps.add_argument("--ports", default="1-1024", help="e.g. 1-1024")
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
        print("[ERROR] Scapy missing. `pip install scapy` + Npcap (Windows) required.")
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
