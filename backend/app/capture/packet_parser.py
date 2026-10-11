from datetime import datetime, timezone
import ipaddress
from typing import List, Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS
from scapy.packet import Packet

from app.schemas.packet import PacketEventSchema


class PacketParser:
    """
    Lightweight, thread-safe, privacy-preserving network packet parser.
    Extracts strictly header-level metadata and ignores application payloads,
    passwords, cookies, authorization tokens, and encrypted contents.
    """

    @staticmethod
    def _is_local_ip(ip_str: Optional[str]) -> bool:
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return addr.is_private or addr.is_loopback
        except ValueError:
            return False

    @staticmethod
    def _is_broadcast_ip(ip_str: Optional[str]) -> bool:
        if not ip_str:
            return False
        if ip_str == "255.255.255.255":
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
            return False
        except ValueError:
            return False

    @staticmethod
    def _is_multicast_ip(ip_str: Optional[str]) -> bool:
        if not ip_str:
            return False
        try:
            addr = ipaddress.ip_address(ip_str)
            return addr.is_multicast
        except ValueError:
            return False

    @staticmethod
    def _parse_tcp_flags(tcp_layer: TCP) -> List[str]:
        """
        Extracts active TCP flag names (e.g. ['SYN', 'ACK']).
        """
        flags: List[str] = []
        try:
            f = int(tcp_layer.flags)
        except Exception:
            return flags

        flag_map = [
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        ]
        for mask, name in flag_map:
            if f & mask:
                flags.append(name)
        return flags

    @classmethod
    def parse(cls, pkt: Packet) -> Optional[PacketEventSchema]:
        """
        Parses a Scapy packet into a PacketEventSchema.
        Returns None if packet cannot be parsed or lacks relevant layers.
        """
        try:
            # Wire length of the packet
            pkt_length = len(pkt) if hasattr(pkt, "__len__") else 0

            # Extraction of timestamp (convert epoch float to timezone-aware UTC datetime)
            raw_time = getattr(pkt, "time", None)
            if raw_time is not None:
                try:
                    ts = datetime.fromtimestamp(float(raw_time), tz=timezone.utc)
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            ip_version: Optional[int] = None
            src_ip: Optional[str] = None
            dst_ip: Optional[str] = None
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            protocol_num: Optional[int] = None
            protocol_name: Optional[str] = None
            tcp_flags: Optional[List[str]] = None
            ttl: Optional[int] = None
            l2_protocol: Optional[str] = None

            # Handle Layer 2 / ARP
            if ARP in pkt:
                arp = pkt[ARP]
                l2_protocol = "ARP"
                protocol_name = "ARP"
                src_ip = getattr(arp, "psrc", None)
                dst_ip = getattr(arp, "pdst", None)
                is_local = cls._is_local_ip(src_ip) or cls._is_local_ip(dst_ip)
                eth_dst = (getattr(pkt.getlayer(Ether), "dst", "") or "").lower() if pkt.haslayer(Ether) else ""
                is_bcast = (dst_ip == "255.255.255.255") or (eth_dst == "ff:ff:ff:ff:ff:ff")
                is_mcast = False

                return PacketEventSchema(
                    timestamp=ts,
                    ip_version=4 if src_ip and "." in src_ip else None,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=None,
                    dst_port=None,
                    protocol_num=None,
                    protocol_name=protocol_name,
                    tcp_flags=None,
                    ttl=None,
                    length=pkt_length,
                    is_local=is_local,
                    is_broadcast=is_bcast,
                    is_multicast=is_mcast,
                    dns_query_count=0,
                    dns_unique_query_count=0,
                    l2_protocol=l2_protocol,
                )

            # Handle IPv4
            if IP in pkt:
                ip_layer = pkt[IP]
                ip_version = 4
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol_num = int(ip_layer.proto)
                ttl = int(ip_layer.ttl)
            # Handle IPv6
            elif IPv6 in pkt:
                ip6_layer = pkt[IPv6]
                ip_version = 6
                src_ip = ip6_layer.src
                dst_ip = ip6_layer.dst
                protocol_num = int(ip6_layer.nh)
                ttl = int(ip6_layer.hlim)
            else:
                # Non-IP packet (e.g. pure layer 2 broadcast or unknown)
                return None

            # Transport protocol parsing
            if TCP in pkt:
                tcp_layer = pkt[TCP]
                protocol_name = "TCP"
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = cls._parse_tcp_flags(tcp_layer)
            elif UDP in pkt:
                udp_layer = pkt[UDP]
                protocol_name = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif ICMP in pkt:
                protocol_name = "ICMP"
            elif ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt:
                protocol_name = "ICMPv6"
            else:
                protocol_name = f"IP-Proto-{protocol_num}" if protocol_num is not None else "Unknown"

            # DNS Query counting (metadata count only, NO query domain name storage)
            dns_query_count = 0
            dns_unique_query_count = 0
            if DNS in pkt:
                dns_layer = pkt[DNS]
                qdcount = getattr(dns_layer, "qdcount", 0) or 0
                qd = getattr(dns_layer, "qd", None)
                if qd is not None:
                    queries: List[str] = []
                    # In Scapy, qd can be a PacketListField or a single Packet
                    try:
                        if isinstance(qd, (list, tuple)):
                            for q in qd:
                                qname = getattr(q, "qname", b"")
                                queries.append(str(qname))
                        elif hasattr(qd, "qname"):
                            queries.append(str(getattr(qd, "qname", b"")))
                        elif hasattr(qd, "__iter__"):
                            for q in qd:
                                queries.append(str(getattr(q, "qname", b"")))
                    except Exception:
                        pass
                    dns_query_count = len(queries) if queries else int(qdcount)
                    dns_unique_query_count = len(set(queries)) if queries else int(qdcount)
                else:
                    dns_query_count = int(qdcount)
                    dns_unique_query_count = int(qdcount)

            is_local = cls._is_local_ip(src_ip) or cls._is_local_ip(dst_ip)
            is_bcast = cls._is_broadcast_ip(dst_ip)
            if not is_bcast and Ether in pkt:
                eth = pkt[Ether]
                dst_mac = (getattr(eth, "dst", "") or "").lower()
                if dst_mac == "ff:ff:ff:ff:ff:ff":
                    is_bcast = True

            is_mcast = cls._is_multicast_ip(dst_ip)

            return PacketEventSchema(
                timestamp=ts,
                ip_version=ip_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol_num=protocol_num,
                protocol_name=protocol_name,
                tcp_flags=tcp_flags,
                ttl=ttl,
                length=pkt_length,
                is_local=is_local,
                is_broadcast=is_bcast,
                is_multicast=is_mcast,
                dns_query_count=dns_query_count,
                dns_unique_query_count=dns_unique_query_count,
                l2_protocol="Ethernet" if Ether in pkt else None,
            )

        except Exception:
            return None
