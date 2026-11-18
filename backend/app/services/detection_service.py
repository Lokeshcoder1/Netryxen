"""
Detection service coordinating ML training, prediction execution, rule evaluation, and alert lifecycle.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import uuid

from sqlalchemy.orm import Session

from app.core.logging import logger
from app.ml.model_manager import model_manager
from app.models.capture_session import CaptureSession, SessionMode
from app.models.detection import (
    Alert,
    ModelRegistry,
    ModelStatus,
    Prediction,
    PredictionStatus,
)
from app.models.flow_record import FlowRecord
from app.repositories.capture_repository import CaptureRepository
from app.repositories.detection_repository import DetectionRepository
from app.repositories.flow_repository import FlowRepository
from app.rules.rule_engine import rule_engine
from app.schemas.detection import (
    AlertListResponse,
    AlertResponse,
    ModelRegistryResponse,
    ModelStatusResponse,
    PredictionListResponse,
    PredictionResponse,
    TrainBaselineRequest,
)
from app.services.alert_service import AlertService


class DetectionService:
    """
    Orchestrates ML baseline training, flow inference, rule matching, and alert persistence.
    """

    @staticmethod
    def _restore_previous_active_model(db: Session, previous_model_id: Optional[uuid.UUID]) -> None:
        """Restores the previously active model when a new training registration fails."""
        if previous_model_id:
            previous = DetectionRepository.get_model_by_id(db=db, model_id=previous_model_id)
            if previous and previous.artifact_path:
                try:
                    model_manager.load_artifact(
                        artifact_path=previous.artifact_path,
                        expected_checksum=previous.artifact_checksum,
                        model_id=previous.id,
                        model_version=previous.version,
                    )
                    return
                except Exception as exc:
                    logger.warning(f"Could not restore previous model '{previous_model_id}': {exc}")
        model_manager.reset()

    @staticmethod
    def train_baseline(db: Session, req: TrainBaselineRequest) -> ModelRegistryResponse:
        # 1. Validate capture session
        session = CaptureRepository.get_by_id(db=db, session_id=req.session_id)
        if not session:
            raise ValueError(f"Capture session with ID '{req.session_id}' not found.")

        if session.session_mode != SessionMode.BASELINE.value:
            raise ValueError(
                f"Session '{req.session_id}' was recorded in '{session.session_mode}' mode. "
                "Baseline model training strictly requires a session in 'BASELINE' mode to avoid "
                "training on unverified monitoring traffic."
            )

        from app.models.capture_session import CaptureStatus
        if session.status != CaptureStatus.STOPPED.value:
            raise ValueError(
                f"Cannot train baseline model on session '{req.session_id}' with status '{session.status}'. "
                "Baseline training strictly requires a completed ('STOPPED') session."
            )

        # 2. Retrieve flows for this baseline session
        flows = list(
            db.query(FlowRecord)
            .filter(FlowRecord.session_id == req.session_id)
            .order_by(FlowRecord.window_start)
            .all()
        )

        previous_active_model_id = model_manager.active_model_info.get("model_id")

        try:
            # 3. Train model pipeline
            train_result = model_manager.train_baseline(
                session_id=req.session_id,
                flows=flows,
                model_name=req.model_name or "IsolationForest_Baseline",
                min_samples=req.min_samples,
                contamination=req.contamination,
                n_estimators=req.n_estimators,
            )

            # 4. Save model registry record in DB
            model_obj = ModelRegistry(
                id=train_result["id"],
                name=train_result["name"],
                version=train_result["version"],
                algorithm=train_result["algorithm"],
                status=train_result["status"],
                feature_names=train_result["feature_names"],
                feature_schema_version=train_result["feature_schema_version"],
                training_session_id=train_result["training_session_id"],
                training_sample_count=train_result["training_sample_count"],
                training_params=train_result["training_params"],
                artifact_path=train_result["artifact_path"],
                artifact_checksum=train_result["artifact_checksum"],
                evaluation_info=train_result["evaluation_info"],
            )
            saved = DetectionRepository.create_model(db=db, model_obj=model_obj)

            # 5. Activate only after the registry transaction succeeds.
            model_manager.activate_model(
                model_id=saved.id,
                version=saved.version,
                pipeline=train_result["_pipeline"],
            )
            return ModelRegistryResponse.model_validate(saved)
        except Exception:
            logger.warning(
                "Baseline model registration failed; restoring the previous active model state.",
                exc_info=True,
            )
            DetectionService._restore_previous_active_model(db=db, previous_model_id=previous_active_model_id)
            raise

    @staticmethod
    def get_model_status(db: Session) -> ModelStatusResponse:
        active_info = model_manager.active_model_info
        is_ready = active_info["is_ready"]
        active_db_model: Optional[ModelRegistry] = None

        if active_info["model_id"]:
            active_db_model = DetectionRepository.get_model_by_id(db=db, model_id=active_info["model_id"])
        if not active_db_model:
            # Fallback to latest ready model in DB
            latest = DetectionRepository.get_latest_ready_model(db=db)
            if latest and not is_ready:
                # Attempt lazy-load of latest verified artifact
                try:
                    if latest.artifact_path:
                        model_manager.load_artifact(
                            artifact_path=latest.artifact_path,
                            expected_checksum=latest.artifact_checksum,
                            model_id=latest.id,
                            model_version=latest.version,
                        )
                        is_ready = True
                        active_db_model = latest
                except Exception as exc:
                    logger.warning(f"Could not automatically load latest model artifact: {exc}")

        total_models = DetectionRepository.count_models(db=db)
        active_resp = (
            ModelRegistryResponse.model_validate(active_db_model)
            if active_db_model
            else None
        )
        return ModelStatusResponse(
            active_model=active_resp,
            is_ready=is_ready,
            total_registered_models=total_models,
        )

    @staticmethod
    def predict_flow(db: Session, flow_id: uuid.UUID) -> PredictionResponse:
        # 1. Fetch flow
        flow = FlowRepository.get_by_id(db=db, flow_id=flow_id)
        if not flow:
            raise ValueError(f"Flow record with ID '{flow_id}' was not found.")

        # Ensure active model is loaded if available in DB
        if not model_manager.is_model_ready:
            latest = DetectionRepository.get_latest_ready_model(db=db)
            if latest and latest.artifact_path:
                try:
                    model_manager.load_artifact(
                        artifact_path=latest.artifact_path,
                        expected_checksum=latest.artifact_checksum,
                        model_id=latest.id,
                        model_version=latest.version,
                    )
                except Exception as exc:
                    logger.warning(f"Failed to auto-load latest model: {exc}")

        # 2. Run ML prediction
        ml_status, ml_score, raw_pred = model_manager.predict_flow(flow)
        model_info = model_manager.active_model_info
        active_model_id = model_info.get("model_id")
        active_version = model_info.get("version")

        # 3. Retrieve historical context for multi-flow rules (strictly bounded, no cross-session leakage, no self-inclusion)
        flow_history: List[FlowRecord] = []
        if flow.src_ip:
            flow_time = flow.last_seen
            if flow_time.tzinfo is None:
                flow_time = flow_time.replace(tzinfo=timezone.utc)
            cutoff = flow_time - timedelta(seconds=120)
            flow_history = DetectionRepository.get_recent_flows_for_src_ip(
                db=db,
                src_ip=flow.src_ip,
                session_id=flow.session_id,
                cutoff_time=cutoff,
                upper_time=flow.window_start,
                exclude_flow_id=flow.id,
                limit=50,
            )

        # 4. Evaluate Rule Engine
        rule_findings = rule_engine.evaluate_flow(flow, flow_history=flow_history)

        # 5. Alert decision policy & deduplication
        alerts = AlertService.evaluate_and_alert(
            db=db,
            flow=flow,
            ml_status=ml_status,
            ml_score=ml_score,
            model_version=active_version,
            rule_findings=rule_findings,
        )

        # 6. Persist prediction record
        pred_obj = Prediction(
            id=uuid.uuid4(),
            flow_id=flow.id,
            model_id=active_model_id,
            model_version=active_version,
            status=ml_status.value,
            raw_score=ml_score,
            raw_prediction=raw_pred,
        )
        saved_pred = DetectionRepository.create_prediction(db=db, pred_obj=pred_obj)

        resp = PredictionResponse.model_validate(saved_pred)
        resp.alerts_generated = len(alerts)
        return resp

    @staticmethod
    def list_predictions(
        db: Session,
        flow_id: Optional[uuid.UUID] = None,
        model_id: Optional[uuid.UUID] = None,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> PredictionListResponse:
        items, total = DetectionRepository.list_predictions(
            db=db, flow_id=flow_id, model_id=model_id, status=status, skip=skip, limit=limit
        )
        return PredictionListResponse(
            total=total,
            items=[PredictionResponse.model_validate(p) for p in items],
            skip=skip,
            limit=limit,
        )

    @staticmethod
    def list_alerts(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        detection_source: Optional[str] = None,
        session_id: Optional[uuid.UUID] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> AlertListResponse:
        items, total = DetectionRepository.list_alerts(
            db=db,
            status=status,
            severity=severity,
            detection_source=detection_source,
            session_id=session_id,
            skip=skip,
            limit=limit,
        )
        return AlertListResponse(
            total=total,
            items=[AlertResponse.model_validate(a) for a in items],
            skip=skip,
            limit=limit,
        )

    @staticmethod
    def update_alert_status(
        db: Session,
        alert_id: uuid.UUID,
        target_status: str,
        notes: Optional[str] = None,
    ) -> Optional[AlertResponse]:
        alert = AlertService.update_alert_status(
            db=db, alert_id=alert_id, target_status=target_status, notes=notes
        )
        if not alert:
            return None
        return AlertResponse.model_validate(alert)

    @staticmethod
    def resolve_alert(db: Session, alert_id: uuid.UUID) -> Optional[AlertResponse]:
        alert = AlertService.resolve_alert(db=db, alert_id=alert_id)
        if not alert:
            return None
        return AlertResponse.model_validate(alert)
