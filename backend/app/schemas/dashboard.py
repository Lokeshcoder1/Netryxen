from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.capture import CaptureStatusResponse
from app.schemas.flow import FlowRecordResponse


class TopTalkerItem(BaseModel):
    ip: str
    packets: int
    bytes: int
    bytes_sent: int = 0
    bytes_recv: int = 0


class AlertSummary(BaseModel):
    total_open: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DetectionWorkerSummary(BaseModel):
    is_running: bool = False
    pending_jobs: int = 0
    processing_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0
    total_processed: int = 0


class DashboardSummaryResponse(BaseModel):
    """
    Consolidated system dashboard metrics: capture engine state, flow totals,
    protocol distribution, top talker endpoints, recent flow activity,
    alert summary metrics, and background detection worker health.
    """
    capture_status: CaptureStatusResponse
    total_sessions: int = 0
    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    protocol_distribution: Dict[str, int] = Field(default_factory=dict)
    top_talkers: List[TopTalkerItem] = Field(default_factory=list)
    recent_flows: List[FlowRecordResponse] = Field(default_factory=list)
    alert_summary: AlertSummary = Field(default_factory=AlertSummary)
    detection_worker: DetectionWorkerSummary = Field(default_factory=DetectionWorkerSummary)
