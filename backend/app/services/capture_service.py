from datetime import datetime, timezone
from typing import List, Optional
import uuid

from sqlalchemy.orm import Session

from app.capture.capture_manager import capture_manager
from app.capture.interface_discovery import InterfaceDiscoveryService
from app.core.logging import logger
from app.models.capture_session import CaptureSession, CaptureStatus
from app.repositories.capture_repository import CaptureRepository
from app.schemas.capture import (
    CapturePreviewResponse,
    CaptureSessionResponse,
    CaptureStartRequest,
    CaptureStatusResponse,
    CaptureStopResponse,
    InterfaceInfo,
)


class CaptureService:
    """
    Business logic coordinator between live capture engine and database persistence.
    """

    @staticmethod
    def list_interfaces() -> List[InterfaceInfo]:
        return InterfaceDiscoveryService.list_interfaces()

    @staticmethod
    def start_capture(db: Session, req: CaptureStartRequest) -> CaptureStatusResponse:
        # 1. Interface validation
        iface = InterfaceDiscoveryService.get_interface_by_id(req.interface_id)
        if not iface:
            raise ValueError(f"Interface '{req.interface_id}' was not found on this system.")

        # 2. Check if already running
        if capture_manager.is_running:
            raise RuntimeError("A packet capture session is already active. Please stop it first.")

        # 3. Create database session entry
        session_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        db_session = CaptureSession(
            id=session_id,
            interface_id=iface.id,
            session_mode=req.session_mode.value,
            status=CaptureStatus.RUNNING.value,
            started_at=now,
            packets_seen=0,
            packets_enqueued=0,
            packets_dropped=0,
            error_summary=None,
        )
        CaptureRepository.create(db, db_session)

        # 4. Start engine
        try:
            capture_manager.start_capture(
                interface_id=iface.id,
                session_id=session_id,
                session_mode=req.session_mode,
                bpf_filter=req.bpf_filter,
                local_ips=iface.ip_addresses,
            )
        except Exception as exc:
            db_session.status = CaptureStatus.FAILED.value
            db_session.stopped_at = datetime.now(timezone.utc)
            db_session.error_summary = str(exc)
            CaptureRepository.update(db, db_session)
            raise

        return capture_manager.get_status()

    @staticmethod
    def stop_capture(db: Session) -> CaptureStopResponse:
        current_status = capture_manager.get_status()
        if not current_status.is_running:
            raise RuntimeError("No active capture session is currently running.")

        active_session_id = current_status.active_session_id
        stats = capture_manager.stop_capture()

        # Update DB session record
        updated_db_session: Optional[CaptureSession] = None
        if active_session_id:
            updated_db_session = CaptureRepository.complete_session(
                db=db,
                session_id=active_session_id,
                status=CaptureStatus.STOPPED,
                stats=stats,
            )

        session_resp = (
            CaptureSessionResponse.model_validate(updated_db_session)
            if updated_db_session
            else None
        )

        return CaptureStopResponse(
            message="Capture session stopped successfully.",
            session=session_resp,
        )

    @staticmethod
    def get_status() -> CaptureStatusResponse:
        return capture_manager.get_status()

    @staticmethod
    def list_sessions(db: Session, skip: int = 0, limit: int = 50) -> List[CaptureSessionResponse]:
        sessions = CaptureRepository.list_all(db=db, skip=skip, limit=limit)
        return [CaptureSessionResponse.model_validate(s) for s in sessions]

    @staticmethod
    def get_preview() -> CapturePreviewResponse:
        packets = capture_manager.get_preview()
        return CapturePreviewResponse(
            count=len(packets),
            packets=packets,
        )
