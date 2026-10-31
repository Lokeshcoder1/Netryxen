from typing import Optional
import uuid

from sqlalchemy.orm import Session

from app.capture.capture_manager import capture_manager
from app.repositories.flow_repository import FlowRepository
from app.schemas.dashboard import DashboardSummaryResponse, TopTalkerItem
from app.schemas.flow import (
    FlowFilterParams,
    FlowListResponse,
    FlowRecordResponse,
)


class FlowService:
    """
    Business logic layer for querying and inspecting network flows and dashboard metrics.
    """

    @staticmethod
    def list_flows(db: Session, filters: FlowFilterParams) -> FlowListResponse:
        records, total = FlowRepository.list_flows(db=db, filters=filters)
        items = [FlowRecordResponse.model_validate(r) for r in records]
        return FlowListResponse(
            total=total,
            items=items,
            skip=filters.skip,
            limit=filters.limit,
        )

    @staticmethod
    def get_flow_by_id(db: Session, flow_id: uuid.UUID) -> Optional[FlowRecordResponse]:
        record = FlowRepository.get_by_id(db=db, flow_id=flow_id)
        if not record:
            return None
        return FlowRecordResponse.model_validate(record)

    @staticmethod
    def get_dashboard_summary(db: Session) -> DashboardSummaryResponse:
        stats = FlowRepository.get_dashboard_stats(db=db)
        capture_status = capture_manager.get_status()

        return DashboardSummaryResponse(
            capture_status=capture_status,
            total_sessions=stats["total_sessions"],
            total_flows=stats["total_flows"],
            total_packets=stats["total_packets"],
            total_bytes=stats["total_bytes"],
            protocol_distribution=stats["protocol_distribution"],
            top_talkers=[TopTalkerItem(**t) for t in stats["top_talkers"]],
            recent_flows=[
                FlowRecordResponse.model_validate(f) for f in stats["recent_flows"]
            ],
        )
