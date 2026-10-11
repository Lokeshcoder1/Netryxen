from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.capture import (
    CapturePreviewResponse,
    CaptureSessionResponse,
    CaptureStartRequest,
    CaptureStatusResponse,
    CaptureStopResponse,
    InterfaceInfo,
)
from app.services.capture_service import CaptureService

router = APIRouter(prefix="/capture", tags=["Packet Capture"])


@router.get(
    "/interfaces",
    response_model=List[InterfaceInfo],
    summary="List network interfaces",
    description="Discovers and returns all network interfaces available on the host.",
)
def list_interfaces() -> List[InterfaceInfo]:
    return CaptureService.list_interfaces()


@router.post(
    "/start",
    response_model=CaptureStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Start live capture session",
    description="Starts non-blocking packet capture on the selected interface.",
)
def start_capture(
    request: CaptureStartRequest,
    db: Session = Depends(get_db),
) -> CaptureStatusResponse:
    try:
        return CaptureService.start_capture(db=db, req=request)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except RuntimeError as run_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(run_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error starting capture: {str(exc)}",
        )


@router.post(
    "/stop",
    response_model=CaptureStopResponse,
    status_code=status.HTTP_200_OK,
    summary="Stop live capture session",
    description="Stops the active packet capture session and persists final statistics.",
)
def stop_capture(
    db: Session = Depends(get_db),
) -> CaptureStopResponse:
    try:
        return CaptureService.stop_capture(db=db)
    except RuntimeError as run_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(run_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error stopping capture: {str(exc)}",
        )


@router.get(
    "/status",
    response_model=CaptureStatusResponse,
    summary="Get capture engine status",
    description="Returns live metrics, queue size, drop count, and worker state.",
)
def get_status() -> CaptureStatusResponse:
    return CaptureService.get_status()


@router.get(
    "/sessions",
    response_model=List[CaptureSessionResponse],
    summary="List past capture sessions",
    description="Retrieves historical capture session records stored in PostgreSQL.",
)
def list_sessions(
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=100, description="Limit for pagination"),
    db: Session = Depends(get_db),
) -> List[CaptureSessionResponse]:
    return CaptureService.list_sessions(db=db, skip=skip, limit=limit)


@router.get(
    "/preview",
    response_model=CapturePreviewResponse,
    summary="Get recent diagnostic packets",
    description="Returns sanitized metadata for the most recently captured packets.",
)
def get_preview() -> CapturePreviewResponse:
    return CaptureService.get_preview()
