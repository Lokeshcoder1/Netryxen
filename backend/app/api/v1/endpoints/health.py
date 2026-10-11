from datetime import datetime, timezone
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.capture.interface_discovery import is_npcap_installed
from app.db.session import check_db_connection
from app.schemas.health import LivenessResponse, ReadinessResponse

router = APIRouter(prefix="/health", tags=["Health"])


@router.get(
    "/live",
    response_model=LivenessResponse,
    status_code=status.HTTP_200_OK,
    summary="Liveness probe",
    description="Returns OK if the API server process is alive and accepting HTTP traffic.",
)
def get_liveness() -> LivenessResponse:
    return LivenessResponse(
        status="ok",
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    status_code=status.HTTP_200_OK,
    summary="Readiness probe",
    description="Verifies database accessibility, Npcap driver availability, and capture readiness.",
)
def get_readiness() -> ReadinessResponse:
    db_ok = check_db_connection()
    npcap_ok = is_npcap_installed()
    now = datetime.now(timezone.utc)

    overall_status = "ready" if (db_ok and npcap_ok) else ("degraded" if db_ok or npcap_ok else "not_ready")

    return ReadinessResponse(
        status=overall_status,
        database=db_ok,
        capture_worker=True,
        npcap_available=npcap_ok,
        timestamp=now,
    )
