"""
Module 3 database models: ModelRegistry, Prediction, Alert.
"""
import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ModelStatus(str, enum.Enum):
    TRAINING = "TRAINING"
    READY = "READY"
    FAILED = "FAILED"
    RETIRED = "RETIRED"


class PredictionStatus(str, enum.Enum):
    NORMAL = "NORMAL"
    ANOMALY = "ANOMALY"
    MODEL_NOT_READY = "MODEL_NOT_READY"
    INFERENCE_ERROR = "INFERENCE_ERROR"


class DetectionSource(str, enum.Enum):
    ML = "ML"
    RULE = "RULE"
    COMBINED = "COMBINED"


class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


# ---------------------------------------------------------------------------
# ModelRegistry
# ---------------------------------------------------------------------------

class ModelRegistry(Base):
    """
    Tracks trained ML model artifacts, their feature schema, training
    provenance and readiness status.
    """
    __tablename__ = "model_registry"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ModelStatus.TRAINING.value, index=True,
    )
    feature_names: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=list,
    )
    feature_schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0",
    )
    training_session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("capture_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    training_sample_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0,
    )
    training_params: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )
    artifact_path: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True,
    )
    artifact_checksum: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True,
    )
    evaluation_info: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        server_default=func.now(), onupdate=func.now(),
    )

    def __repr__(self) -> str:
        return (
            f"<ModelRegistry(id={self.id}, name='{self.name}', "
            f"version='{self.version}', status='{self.status}')>"
        )


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

class Prediction(Base):
    """
    Records the output of running a trained model against an individual flow.
    """
    __tablename__ = "predictions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    flow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("flow_records.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    model_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("model_registry.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    model_version: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True,
    )
    raw_score: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True,
    )
    raw_prediction: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_predictions_flow_model", "flow_id", "model_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<Prediction(id={self.id}, flow={self.flow_id}, "
            f"status='{self.status}', score={self.raw_score})>"
        )


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(Base):
    """
    Security alert with deduplication via fingerprint, severity,
    and lifecycle management.
    """
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    flow_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("flow_records.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("capture_sessions.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    detection_source: Mapped[str] = mapped_column(
        String(32), nullable=False,
    )
    model_version: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True,
    )
    rule_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, index=True,
    )
    rule_evidence: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=False,
        default=dict,
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, index=True,
    )
    title: Mapped[str] = mapped_column(
        String(512), nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text, nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True,
    )
    occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AlertStatus.OPEN.value, index=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_alerts_fingerprint_status", "fingerprint", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<Alert(id={self.id}, severity='{self.severity}', "
            f"source='{self.detection_source}', status='{self.status}')>"
        )
