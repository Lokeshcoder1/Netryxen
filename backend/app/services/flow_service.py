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

        from app.services.detection_worker import detection_worker
        worker_stats = detection_worker.get_stats()
        db_job_stats = stats.get("detection_jobs", {})

        worker_summary = {
            "is_running": worker_stats.get("is_running", False),
            "pending_jobs": db_job_stats.get("pending_jobs", 0),
            "processing_jobs": db_job_stats.get("processing_jobs", 0),
            "completed_jobs": db_job_stats.get("completed_jobs", 0),
            "failed_jobs": db_job_stats.get("failed_jobs", 0),
            "total_processed": db_job_stats.get("total_processed", 0),
        }

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
            alert_summary=stats.get("alert_summary", {}),
            detection_worker=worker_summary,
        )
