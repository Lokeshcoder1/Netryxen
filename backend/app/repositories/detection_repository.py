"""
Data access repository for model registry, predictions, and security alerts.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import Session

from app.models.detection import (
    Alert,
    AlertSeverity,
    AlertStatus,
    DetectionSource,
    ModelRegistry,
    ModelStatus,
    Prediction,
    PredictionStatus,
)
from app.models.flow_record import FlowRecord


class DetectionRepository:
    """
    Data access layer for detection subsystem.
    """

    # -------------------------------------------------------------------------
    # Model Registry
    # -------------------------------------------------------------------------

    @staticmethod
    def create_model(db: Session, model_obj: ModelRegistry) -> ModelRegistry:
        db.add(model_obj)
        db.commit()
        db.refresh(model_obj)
        return model_obj

    @staticmethod
    def get_model_by_id(db: Session, model_id: uuid.UUID) -> Optional[ModelRegistry]:
        stmt = select(ModelRegistry).where(ModelRegistry.id == model_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def get_latest_ready_model(db: Session) -> Optional[ModelRegistry]:
        stmt = (
            select(ModelRegistry)
            .where(ModelRegistry.status == ModelStatus.READY.value)
            .order_by(desc(ModelRegistry.created_at))
            .limit(1)
        )
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def count_models(db: Session) -> int:
        stmt = select(func.count(ModelRegistry.id))
        return db.execute(stmt).scalar_one() or 0

    # -------------------------------------------------------------------------
    # Predictions
    # -------------------------------------------------------------------------

    @staticmethod
    def create_prediction(db: Session, pred_obj: Prediction) -> Prediction:
        db.add(pred_obj)
        db.commit()
        db.refresh(pred_obj)
        return pred_obj

    @staticmethod
    def list_predictions(
        db: Session,
        flow_id: Optional[uuid.UUID] = None,
        model_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Prediction], int]:
        query = select(Prediction)
        if flow_id:
            query = query.where(Prediction.flow_id == flow_id)
        if model_id:
            query = query.where(Prediction.model_id == model_id)
        if status:
            query = query.where(Prediction.status == status.upper())

        count_query = select(func.count()).select_from(query.subquery())
        total = db.execute(count_query).scalar_one()

        paginated = query.order_by(desc(Prediction.created_at)).offset(skip).limit(limit)
        items = list(db.execute(paginated).scalars().all())
        return items, total

    # -------------------------------------------------------------------------
    # Alerts
    # -------------------------------------------------------------------------

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: uuid.UUID) -> Optional[Alert]:
        stmt = select(Alert).where(Alert.id == alert_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def list_alerts(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        detection_source: Optional[str] = None,
        session_id: Optional[uuid.UUID] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Alert], int]:
        query = select(Alert)
        if status:
            query = query.where(Alert.status == status.upper())
        if severity:
            query = query.where(Alert.severity == severity.upper())
        if detection_source:
            query = query.where(Alert.detection_source == detection_source.upper())
        if session_id:
            query = query.where(Alert.session_id == session_id)

        count_query = select(func.count()).select_from(query.subquery())
        total = db.execute(count_query).scalar_one()

        paginated = query.order_by(desc(Alert.last_seen)).offset(skip).limit(limit)
        items = list(db.execute(paginated).scalars().all())
        return items, total

    # -------------------------------------------------------------------------
    # Historical Flow Queries for Multi-Flow Rules
    # -------------------------------------------------------------------------

    @staticmethod
    def get_recent_flows_for_src_ip(
        db: Session,
        src_ip: str,
        cutoff_time: datetime,
        limit: int = 100,
    ) -> List[FlowRecord]:
        stmt = (
            select(FlowRecord)
            .where(
                and_(
                    FlowRecord.src_ip == src_ip,
                    FlowRecord.window_start >= cutoff_time,
                )
            )
            .order_by(desc(FlowRecord.window_start))
            .limit(limit)
        )
        return list(db.execute(stmt).scalars().all())
