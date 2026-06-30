"""capture.sniffer için unit testler.

summarize_packet'i sentetik Scapy paketleriyle test eder — canlı yakalama
gerektirmez. Scapy kurulu değilse testler atlanır.
"""
import pytest

from capture.sniffer import SCAPY_AVAILABLE, summarize_packet

pytestmark = pytest.mark.skipif(
    not SCAPY_AVAILABLE, reason="Scapy kurulu değil"
)

if SCAPY_AVAILABLE:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP


def test_tcp_packet_parsed():
    pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=51000, dport=443)
    s = summarize_packet(pkt)
    assert s is not None
    assert s.src_ip == "192.168.1.10"
    assert s.dst_ip == "93.184.216.34"
    assert s.src_port == 51000
    assert s.dst_port == 443
    assert s.protocol == "TCP"
    assert s.length > 0


def test_udp_packet_parsed():
    pkt = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5353, dport=53)
    s = summarize_packet(pkt)
    assert s is not None
    assert s.protocol == "UDP"
    assert s.src_port == 5353
    assert s.dst_port == 53


def test_icmp_has_no_ports():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    s = summarize_packet(pkt)
    assert s is not None
    assert s.protocol == "ICMP"
    assert s.src_port is None
    assert s.dst_port is None


def test_ipv6_tcp_parsed():
    pkt = IPv6(src="::1", dst="::2") / TCP(sport=1234, dport=80)
    s = summarize_packet(pkt)
    assert s is not None
    assert s.protocol == "TCP"
    assert s.src_ip == "::1"
    assert s.dst_port == 80


def test_non_ip_packet_returns_none():
    # ARP'ın IP katmanı yoktur -> atlanmalı
    pkt = Ether() / ARP(pdst="192.168.1.1")
    assert summarize_packet(pkt) is None


def test_str_representation_readable():
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=100, dport=200)
    s = summarize_packet(pkt)
    text = str(s)
    assert "1.1.1.1" in text and "2.2.2.2" in text and "TCP" in text
