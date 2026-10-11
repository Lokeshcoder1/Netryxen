from datetime import datetime
from pydantic import BaseModel, Field


class LivenessResponse(BaseModel):
    status: str = Field("ok", description="Liveness status indicator")
    timestamp: datetime = Field(..., description="Current UTC timestamp")


class ReadinessResponse(BaseModel):
    status: str = Field(..., description="Readiness status ('ready' or 'degraded' or 'not_ready')")
    database: bool = Field(..., description="Whether PostgreSQL is connected and responsive")
    capture_worker: bool = Field(..., description="Whether capture engine is operational")
    npcap_available: bool = Field(..., description="Whether Npcap driver is installed on Windows")
    timestamp: datetime = Field(..., description="Current UTC timestamp")
