from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.dashboard import DashboardSummaryResponse
from app.services.flow_service import FlowService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    summary="Get system monitoring summary",
    description=(
        "Returns consolidated operational metrics: capture engine state, total sessions, "
        "total flow records, protocol distributions, top talker endpoints, and recent flow activity."
    ),
)
def get_dashboard_summary(
    db: Session = Depends(get_db),
) -> DashboardSummaryResponse:
    return FlowService.get_dashboard_summary(db=db)
