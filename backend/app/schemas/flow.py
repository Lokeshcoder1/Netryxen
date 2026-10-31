from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field


class FlowRecordResponse(BaseModel):
    """
    Detailed serialized representation of a 10-second aggregated bidirectional flow record.
    """
    id: uuid.UUID
    session_id: uuid.UUID
    window_start: datetime
    window_end: datetime
    flow_key: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    protocol_num: Optional[int] = None
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    packet_count: int
    byte_count: int
    fwd_packets: int
    rev_packets: int
    fwd_bytes: int
    rev_bytes: int
    packets_per_second: float
    bytes_per_second: float
    min_packet_size: int
    max_packet_size: int
    avg_packet_size: float
    tcp_syn_count: int
    tcp_ack_count: int
    tcp_fin_count: int
    tcp_rst_count: int
    tcp_psh_count: int
    dns_query_count: int
    dns_unique_query_count: int
    upload_bytes: int
    download_bytes: int
    upload_ratio: Optional[float] = None
    is_local: bool
    is_broadcast: bool
    is_multicast: bool
    features: Dict[str, Any] = Field(default_factory=dict)
    feature_schema_version: str = "1.0"
    created_at: datetime

    model_config = {
        "from_attributes": True,
    }


class FlowListResponse(BaseModel):
    """
    Paginated list response containing flow records and query metadata.
    """
    total: int
    items: List[FlowRecordResponse]
    skip: int
    limit: int


class FlowFilterParams(BaseModel):
    """
    Query filtering parameters for flow retrieval.
    """
    session_id: Optional[uuid.UUID] = None
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    min_packet_count: Optional[int] = None
    skip: int = 0
    limit: int = 50
