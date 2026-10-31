from datetime import datetime
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.flow import (
    FlowFilterParams,
    FlowListResponse,
    FlowRecordResponse,
)
from app.services.flow_service import FlowService

router = APIRouter(prefix="/flows", tags=["Network Flows"])


@router.get(
    "",
    response_model=FlowListResponse,
    summary="List aggregated flow records",
    description=(
        "Retrieves a paginated list of bidirectional flow records aggregated "
        "over 10-second observation windows with optional filtering."
    ),
)
def list_flows(
    session_id: Optional[uuid.UUID] = Query(None, description="Filter by capture session UUID"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (e.g. TCP, UDP, ICMP)"),
    src_ip: Optional[str] = Query(None, description="Filter by initiator / source IP"),
    dst_ip: Optional[str] = Query(None, description="Filter by responder / destination IP"),
    ip: Optional[str] = Query(None, description="Filter flows matching either source or destination IP"),
    start_time: Optional[datetime] = Query(None, description="Filter flows with window_start >= start_time"),
    end_time: Optional[datetime] = Query(None, description="Filter flows with window_end <= end_time"),
    min_packet_count: Optional[int] = Query(None, ge=1, description="Filter flows with packet_count >= min_packet_count"),
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=500, description="Page limit (max 500)"),
    db: Session = Depends(get_db),
) -> FlowListResponse:
    filters = FlowFilterParams(
        session_id=session_id,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip=ip,
        start_time=start_time,
        end_time=end_time,
        min_packet_count=min_packet_count,
        skip=skip,
        limit=limit,
    )
    return FlowService.list_flows(db=db, filters=filters)


@router.get(
    "/{flow_id}",
    response_model=FlowRecordResponse,
    summary="Get flow record details",
    description="Retrieves complete statistical details and feature dictionary for a specific flow record.",
)
def get_flow(
    flow_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> FlowRecordResponse:
    flow = FlowService.get_flow_by_id(db=db, flow_id=flow_id)
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow record with ID '{flow_id}' was not found.",
        )
    return flow
