import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

from app.models.capture_session import CaptureStatus, SessionMode
from app.schemas.packet import PacketEventSchema


class InterfaceInfo(BaseModel):
    id: str = Field(..., description="Unique interface identifier used for capture selection")
    name: str = Field(..., description="Human-readable interface name")
    description: Optional[str] = Field(None, description="Interface hardware description")
    mac_address: Optional[str] = Field(None, description="MAC address of interface")
    ip_addresses: List[str] = Field(default_factory=list, description="Assigned IPv4 and IPv6 addresses")
    status: str = Field("Unknown", description="Interface operational status (Up, Down, Unknown)")
    is_loopback: bool = Field(False, description="True if loopback interface")


class CaptureStartRequest(BaseModel):
    interface_id: str = Field(..., description="Validated interface ID to capture from")
    session_mode: SessionMode = Field(
        default=SessionMode.MONITORING,
        description="Session mode: BASELINE or MONITORING",
    )
    bpf_filter: Optional[str] = Field(
        None,
        description="Optional BPF filter expression (e.g. 'ip or ip6')",
    )


class CaptureStatusResponse(BaseModel):
    is_running: bool = Field(..., description="Whether capture engine is currently active")
    active_session_id: Optional[uuid.UUID] = Field(None, description="Active session ID if running")
    interface_id: Optional[str] = Field(None, description="Interface ID being monitored")
    session_mode: Optional[SessionMode] = Field(None, description="Active session mode")
    started_at: Optional[datetime] = Field(None, description="Time capture started")
    packets_seen: int = Field(0, description="Total raw packets seen by Scapy callback")
    packets_enqueued: int = Field(0, description="Total packets successfully parsed and enqueued")
    packets_dropped: int = Field(0, description="Total packets dropped due to full queue")
    queue_size: int = Field(0, description="Current number of packets pending in queue")
    queue_capacity: int = Field(..., description="Configured maximum queue capacity")
    preview_count: int = Field(0, description="Current number of diagnostic preview packets buffered")
    error_summary: Optional[str] = Field(None, description="Last recorded error if any")


class CaptureSessionResponse(BaseModel):
    id: uuid.UUID
    interface_id: str
    session_mode: str
    status: str
    started_at: datetime
    stopped_at: Optional[datetime] = None
    packets_seen: int
    packets_enqueued: int
    packets_dropped: int
    error_summary: Optional[str] = None
    created_at: datetime

    model_config = {
        "from_attributes": True,
    }


class CaptureStopResponse(BaseModel):
    message: str
    session: Optional[CaptureSessionResponse] = None


class CapturePreviewResponse(BaseModel):
    count: int = Field(..., description="Number of packets in preview")
    packets: List[PacketEventSchema] = Field(..., description="Diagnostic preview packets (most recent first)")
