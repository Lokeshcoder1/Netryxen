from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.capture_session import CaptureSession, CaptureStatus


class CaptureRepository:
    """
    Data access layer for capture sessions table.
    """

    @staticmethod
    def create(db: Session, session_obj: CaptureSession) -> CaptureSession:
        db.add(session_obj)
        db.commit()
        db.refresh(session_obj)
        return session_obj

    @staticmethod
    def get_by_id(db: Session, session_id: uuid.UUID) -> Optional[CaptureSession]:
        stmt = select(CaptureSession).where(CaptureSession.id == session_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def get_active_session(db: Session) -> Optional[CaptureSession]:
        stmt = (
            select(CaptureSession)
            .where(CaptureSession.status == CaptureStatus.RUNNING.value)
            .order_by(desc(CaptureSession.started_at))
            .limit(1)
        )
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def list_all(db: Session, skip: int = 0, limit: int = 50) -> List[CaptureSession]:
        stmt = (
            select(CaptureSession)
            .order_by(desc(CaptureSession.created_at))
            .offset(skip)
            .limit(limit)
        )
        return list(db.execute(stmt).scalars().all())

    @staticmethod
    def update(db: Session, session_obj: CaptureSession) -> CaptureSession:
        db.commit()
        db.refresh(session_obj)
        return session_obj

    @staticmethod
    def complete_session(
        db: Session,
        session_id: uuid.UUID,
        status: CaptureStatus,
        stats: Dict[str, Any],
        error_summary: Optional[str] = None,
    ) -> Optional[CaptureSession]:
        session_obj = CaptureRepository.get_by_id(db, session_id)
        if not session_obj:
            return None

        session_obj.status = status.value
        session_obj.stopped_at = datetime.now(timezone.utc)
        session_obj.packets_seen = stats.get("packets_seen", session_obj.packets_seen)
        session_obj.packets_enqueued = stats.get("packets_enqueued", session_obj.packets_enqueued)
        session_obj.packets_dropped = stats.get("packets_dropped", session_obj.packets_dropped)
        if error_summary:
            session_obj.error_summary = error_summary

        db.commit()
        db.refresh(session_obj)
        return session_obj
