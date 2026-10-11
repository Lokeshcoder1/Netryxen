import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Enum, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SessionMode(str, enum.Enum):
    BASELINE = "BASELINE"
    MONITORING = "MONITORING"


class CaptureStatus(str, enum.Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


class CaptureSession(Base):
    __tablename__ = "capture_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    interface_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    session_mode: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=SessionMode.MONITORING.value,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=CaptureStatus.RUNNING.value,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    stopped_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    packets_seen: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    packets_enqueued: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    packets_dropped: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    error_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    __table_args__ = (
        CheckConstraint(
            "session_mode IN ('BASELINE', 'MONITORING')",
            name="chk_capture_session_mode",
        ),
        CheckConstraint(
            "status IN ('RUNNING', 'STOPPED', 'FAILED')",
            name="chk_capture_session_status",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<CaptureSession(id={self.id}, interface_id='{self.interface_id}', "
            f"mode='{self.session_mode}', status='{self.status}', "
            f"seen={self.packets_seen}, enqueued={self.packets_enqueued}, "
            f"dropped={self.packets_dropped})>"
        )
