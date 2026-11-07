from typing import Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.detection import AlertListResponse, AlertResponse
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get(
    "",
    response_model=AlertListResponse,
    summary="List security alerts",
    description="Retrieves a paginated list of security alerts with filtering by status, severity, source, or session.",
)
def list_alerts(
    status: Optional[str] = Query(None, description="Filter by status (OPEN, RESOLVED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    detection_source: Optional[str] = Query(None, description="Filter by source (ML, RULE, COMBINED)"),
    session_id: Optional[uuid.UUID] = Query(None, description="Filter by capture session UUID"),
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    return DetectionService.list_alerts(
        db=db,
        status=status,
        severity=severity,
        detection_source=detection_source,
        session_id=session_id,
        skip=skip,
        limit=limit,
    )


@router.patch(
    "/{alert_id}/resolve",
    response_model=AlertResponse,
    summary="Resolve a security alert",
    description="Marks an open security alert as RESOLVED and records the resolution timestamp.",
)
def resolve_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> AlertResponse:
    alert = DetectionService.resolve_alert(db=db, alert_id=alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' was not found.",
        )
    return alert
