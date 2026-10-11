from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.capture.packet_parser import PacketParser


def test_parse_tcp_syn_packet(synthetic_tcp_syn):
    event = PacketParser.parse(synthetic_tcp_syn)
    assert event is not None
    assert event.ip_version == 4
    assert event.src_ip == "192.168.1.50"
    assert event.dst_ip == "192.168.1.1"
    assert event.src_port == 54321
    assert event.dst_port == 80
    assert event.protocol_num == 6
    assert event.protocol_name == "TCP"
    assert "SYN" in event.tcp_flags
    assert event.ttl == 64
    assert event.is_local is True
    assert event.is_broadcast is False
    assert event.is_multicast is False


def test_parse_tcp_ack_packet(synthetic_tcp_ack):
    event = PacketParser.parse(synthetic_tcp_ack)
    assert event is not None
    assert event.ip_version == 4
    assert event.src_ip == "192.168.1.1"
    assert event.dst_ip == "192.168.1.50"
    assert event.src_port == 80
    assert event.dst_port == 54321
    assert "ACK" in event.tcp_flags
    assert event.ttl == 128


def test_parse_udp_packet(synthetic_udp):
    event = PacketParser.parse(synthetic_udp)
    assert event is not None
    assert event.ip_version == 4
    assert event.src_ip == "10.0.0.5"
    assert event.dst_ip == "8.8.8.8"
    assert event.src_port == 53535
    assert event.dst_port == 53
    assert event.protocol_num == 17
    assert event.protocol_name == "UDP"
    assert event.tcp_flags is None
    assert event.is_local is True  # 10.0.0.5 is RFC1918


def test_parse_icmp_without_ports(synthetic_icmp):
    event = PacketParser.parse(synthetic_icmp)
    assert event is not None
    assert event.ip_version == 4
    assert event.src_ip == "172.16.0.2"
    assert event.dst_ip == "172.16.0.1"
    assert event.src_port is None
    assert event.dst_port is None
    assert event.protocol_name == "ICMP"
    assert event.tcp_flags is None
    assert event.ttl == 64


def test_parse_ipv6_packet(synthetic_ipv6_tcp):
    event = PacketParser.parse(synthetic_ipv6_tcp)
    assert event is not None
    assert event.ip_version == 6
    assert event.src_ip == "2001:db8::1"
    assert event.dst_ip == "2001:db8::2"
    assert event.src_port == 443
    assert event.dst_port == 60000
    assert event.protocol_name == "TCP"
    assert "SYN" in event.tcp_flags
    assert "ACK" in event.tcp_flags
    assert event.ttl == 64


def test_privacy_no_payload_retained():
    # Construct a packet containing sensitive payload strings
    pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=1234, dport=80)
        / Raw(load=b"GET / HTTP/1.1\r\nAuthorization: Bearer secret_token\r\nCookie: session=xyz")
    )
    event = PacketParser.parse(pkt)
    assert event is not None
    # Verify that event schema does not have payload, auth tokens or cookies
    event_dict = event.model_dump()
    assert "payload" not in event_dict
    assert "secret_token" not in str(event_dict)
    assert "Cookie" not in str(event_dict)


def test_dns_query_count_without_query_strings():
    pkt = (
        Ether()
        / IP(src="192.168.1.5", dst="8.8.8.8")
        / UDP(sport=50000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="sensitive-internal.company.corp"))
    )
    event = PacketParser.parse(pkt)
    assert event is not None
    assert event.dns_query_count == 1
    assert event.dns_unique_query_count == 1
    # Ensure raw qname string is not persisted in the schema
    assert "sensitive-internal.company.corp" not in str(event.model_dump())


def test_arp_packet():
    arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        psrc="192.168.1.1",
        pdst="192.168.1.100",
    )
    event = PacketParser.parse(arp_pkt)
    assert event is not None
    assert event.l2_protocol == "ARP"
    assert event.protocol_name == "ARP"
    assert event.src_ip == "192.168.1.1"
    assert event.dst_ip == "192.168.1.100"
    assert event.is_broadcast is True


def test_non_ip_packet_handling():
    raw_eth = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x8888) / Raw(load=b"unknown protocol")
    event = PacketParser.parse(raw_eth)
    assert event is None
