import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.capture_session import CaptureSession


class FlowRecord(Base):
    """
    Represents an aggregated bidirectional network flow record over an observation window.
    Foreign-keyed to the active capture session that recorded the packets.
    """
    __tablename__ = "flow_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("capture_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    flow_key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    src_ip: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    dst_ip: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    src_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    dst_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    protocol: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    protocol_num: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    duration_seconds: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    packet_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    byte_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    fwd_packets: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    rev_packets: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    fwd_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    rev_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    packets_per_second: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    bytes_per_second: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    min_packet_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    max_packet_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    avg_packet_size: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    tcp_syn_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    tcp_ack_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    tcp_fin_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    tcp_rst_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    tcp_psh_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    dns_query_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    dns_unique_query_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    upload_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    download_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    upload_ratio: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    is_local: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    is_broadcast: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    is_multicast: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    features: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )
    feature_schema_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="1.0",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    session: Mapped["CaptureSession"] = relationship(
        "CaptureSession",
        back_populates="flows",
    )

    __table_args__ = (
        Index("ix_flow_records_session_window", "session_id", "window_start"),
    )

    def __repr__(self) -> str:
        return (
            f"<FlowRecord(id={self.id}, key='{self.flow_key}', proto='{self.protocol}', "
            f"pkts={self.packet_count}, bytes={self.byte_count})>"
        )
