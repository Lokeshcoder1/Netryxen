from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.capture import CaptureStatusResponse
from app.schemas.flow import FlowRecordResponse


class TopTalkerItem(BaseModel):
    ip: str
    packets: int
    bytes: int


class DashboardSummaryResponse(BaseModel):
    """
    Consolidated system dashboard metrics: capture engine state, flow totals,
    protocol distribution, top talker endpoints, and recent flow activity.
    """
    capture_status: CaptureStatusResponse
    total_sessions: int = 0
    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_distribution: Dict[str, int] = Field(default_factory=dict)
    top_talkers: List[TopTalkerItem] = Field(default_factory=list)
    recent_flows: List[FlowRecordResponse] = Field(default_factory=list)
