from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class PacketEventSchema(BaseModel):
    """
    Structured metadata extracted from network packets.
    Strictly excludes sensitive payloads, passwords, auth tokens, and raw DNS payloads.
    """
    timestamp: datetime = Field(..., description="Timestamp when the packet was captured")
    ip_version: Optional[int] = Field(None, description="IP version (4 or 6)")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    src_port: Optional[int] = Field(None, description="Source transport port")
    dst_port: Optional[int] = Field(None, description="Destination transport port")
    protocol_num: Optional[int] = Field(None, description="IP protocol number (e.g. 6 for TCP, 17 for UDP)")
    protocol_name: Optional[str] = Field(None, description="Transport / L3 protocol name (e.g. TCP, UDP, ICMP)")
    tcp_flags: Optional[List[str]] = Field(None, description="TCP flags if applicable (SYN, ACK, FIN, RST, etc.)")
    ttl: Optional[int] = Field(None, description="Time to live (IPv4) or Hop Limit (IPv6)")
    length: int = Field(..., description="Total wire packet length in bytes")
    is_local: bool = Field(False, description="True if packet is to/from RFC1918 / loopback space")
    is_broadcast: bool = Field(False, description="True if packet is broadcast")
    is_multicast: bool = Field(False, description="True if packet is multicast")
    dns_query_count: int = Field(0, description="Count of visible DNS questions in packet without storing query text")
    dns_unique_query_count: int = Field(0, description="Count of unique DNS questions in packet")
    l2_protocol: Optional[str] = Field(None, description="L2 protocol (e.g. Ethernet, ARP)")

    model_config = {
        "from_attributes": True,
    }
