"""
ML Model Manager for Isolation Forest anomaly detection.
Handles baseline training, artifact persistence with SHA-256 checksums,
model loading, and robust inference semantics.
"""
import hashlib
from datetime import datetime, timezone
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Tuple
import uuid

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from app.core.config import settings
from app.core.logging import logger
from app.ml.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract_features_from_flow,
    flows_to_feature_matrix,
)
from app.models.detection import ModelStatus, PredictionStatus


class ModelManager:
    """
    Manages the lifecycle of machine learning models for anomaly detection.
    Provides baseline training, serialization, artifact integrity verification,
    and thread-safe inference.
    """

    def __init__(self, artifacts_dir: Optional[str] = None) -> None:
        if artifacts_dir:
            self.artifacts_dir = Path(artifacts_dir)
        else:
            self.artifacts_dir = settings.get_model_artifacts_path()
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self._active_model_id: Optional[uuid.UUID] = None
        self._active_model_version: Optional[str] = None
        self._active_pipeline: Optional[Pipeline] = None
        self._lock = threading.Lock()

    @property
    def is_model_ready(self) -> bool:
        with self._lock:
            return self._active_pipeline is not None

    @property
    def active_model_info(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "model_id": self._active_model_id,
                "version": self._active_model_version,
                "is_ready": self._active_pipeline is not None,
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_count": len(FEATURE_NAMES),
            }

    @staticmethod
    def compute_file_checksum(filepath: Path) -> str:
        """Computes SHA-256 checksum of a serialized model artifact."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def train_baseline(
        self,
        session_id: uuid.UUID,
        flows: List[Any],
        model_name: str = "IsolationForest_Baseline",
        model_version: Optional[str] = None,
        min_samples: Optional[int] = None,
        contamination: Optional[float] = None,
        n_estimators: Optional[int] = None,
        random_state: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Trains an Isolation Forest anomaly detector on authorized baseline flows.
        Validates sample quantity, imputes missing features, builds an integrated pipeline,
        and serializes the artifact with an integrity checksum.
        """
        required_samples = (
            min_samples
            if min_samples is not None
            else getattr(settings, "ML_MIN_BASELINE_SAMPLES", 50)
        )
        sample_count = len(flows)

        if sample_count == 0:
            raise ValueError(
                f"Cannot train on an empty dataset. Baseline session '{session_id}' has 0 flow records."
            )
        if sample_count < required_samples:
            raise ValueError(
                f"Insufficient baseline samples: session '{session_id}' contains {sample_count} flows, "
                f"but a minimum of {required_samples} is required."
            )

        # Extract numerical feature matrix
        X = flows_to_feature_matrix(flows)
        if X.shape[0] == 0 or X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"Invalid feature matrix dimensions {X.shape}. Expected (N, {len(FEATURE_NAMES)})."
            )

        v_str = model_version or f"v{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        contam = (
            contamination
            if contamination is not None
            else getattr(settings, "ML_CONTAMINATION", 0.05)
        )
        n_est = (
            n_estimators
            if n_estimators is not None
            else getattr(settings, "ML_N_ESTIMATORS", 100)
        )
        r_state = (
            random_state
            if random_state is not None
            else getattr(settings, "ML_RANDOM_STATE", 42)
        )

        # Build pipeline:
        # Note on scaling: While Isolation Forest splits along individual orthogonal features
        # and is scale-invariant, RobustScaler and SimpleImputer ensure clean normalization
        # and guard against NaN/inf inputs during production inference.
        pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=n_est,
                    contamination=contam,
                    random_state=r_state,
                    n_jobs=-1,
                ),
            ),
        ])

        logger.info(
            f"Fitting Isolation Forest on {sample_count} baseline flow vectors (features={len(FEATURE_NAMES)})..."
        )
        pipeline.fit(X)

        # Compute empirical baseline statistics
        # Note: Unlabeled data cannot yield supervised accuracy/precision/recall.
        # We record genuine empirical distributions of the decision function on the baseline.
        train_scores = pipeline.decision_function(X)
        eval_info = {
            "sample_count": sample_count,
            "score_min": float(np.min(train_scores)),
            "score_max": float(np.max(train_scores)),
            "score_mean": float(np.mean(train_scores)),
            "score_median": float(np.median(train_scores)),
            "score_std": float(np.std(train_scores)),
            "note": (
                "Isolation Forest trained on unlabeled baseline traffic. "
                "Scores represent tree isolation depths, not calibrated attack probabilities."
            ),
        }

        # Atomically serialize artifact via temp file
        artifact_filename = f"{model_name}_{v_str}_{uuid.uuid4().hex[:8]}.joblib"
        artifact_path = self.artifacts_dir / artifact_filename
        tmp_artifact_path = self.artifacts_dir / f"{artifact_filename}.tmp"
        try:
            joblib.dump(pipeline, tmp_artifact_path)
            tmp_artifact_path.replace(artifact_path)
        except Exception as exc:
            if tmp_artifact_path.is_file():
                try:
                    tmp_artifact_path.unlink()
                except Exception:
                    pass
            raise RuntimeError(f"Failed to serialize model artifact: {exc}") from exc

        checksum = self.compute_file_checksum(artifact_path)
        logger.info(
            f"Saved model artifact to {artifact_path} (SHA-256: {checksum[:16]}...)"
        )

        model_id = uuid.uuid4()
        training_params = {
            "n_estimators": n_est,
            "contamination": contam,
            "random_state": r_state,
            "min_samples": required_samples,
        }

        # Do not activate in-memory model until DB persistence succeeds
        return {
            "id": model_id,
            "name": model_name,
            "version": v_str,
            "algorithm": "IsolationForest",
            "status": ModelStatus.READY.value,
            "feature_names": FEATURE_NAMES,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "training_session_id": session_id,
            "training_sample_count": sample_count,
            "training_params": training_params,
            "artifact_path": str(artifact_path),
            "artifact_checksum": checksum,
            "evaluation_info": eval_info,
            "_pipeline": pipeline,
        }

    def activate_model(self, model_id: uuid.UUID, version: str, pipeline: Pipeline) -> None:
        """Sets the active loaded model in memory."""
        with self._lock:
            self._active_model_id = model_id
            self._active_model_version = version
            self._active_pipeline = pipeline
        logger.info(f"Activated model {model_id} (version '{version}') for live inference.")

    def load_artifact(
        self,
        artifact_path: str,
        expected_checksum: Optional[str] = None,
        model_id: Optional[uuid.UUID] = None,
        model_version: Optional[str] = None,
    ) -> None:
        """
        Loads a serialized pipeline artifact from the local filesystem.
        Verifies checksum integrity before loading.
        """
        path = Path(artifact_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model artifact not found at path: {path}")

        if expected_checksum:
            actual_checksum = self.compute_file_checksum(path)
            if actual_checksum.lower() != expected_checksum.lower():
                raise ValueError(
                    f"Artifact checksum verification failed! Expected {expected_checksum}, got {actual_checksum}."
                )

        loaded_obj = joblib.load(path)
        if not hasattr(loaded_obj, "predict") or not hasattr(loaded_obj, "decision_function"):
            raise TypeError(
                f"Invalid model artifact: object at {path} does not implement predict and decision_function."
            )

        with self._lock:
            self._active_pipeline = loaded_obj
            self._active_model_id = model_id
            self._active_model_version = model_version or path.stem

        logger.info(f"Loaded active ML model artifact: {path.name}")

    def predict_flow(self, flow: Any) -> Tuple[PredictionStatus, Optional[float], Optional[int]]:
        """
        Executes prediction on a single flow record.
        Returns:
            (status, raw_score, raw_prediction)
        Semantics:
            - predict() == -1 -> ANOMALY
            - predict() == 1  -> NORMAL
            - decision_function() is the raw isolation score (not calibrated attack probability).
        If model is not loaded:
            Returns (PredictionStatus.MODEL_NOT_READY, None, None)
        """
        with self._lock:
            pipeline = self._active_pipeline

        if pipeline is None:
            return PredictionStatus.MODEL_NOT_READY, None, None

        try:
            vec = extract_features_from_flow(flow)
            X = np.array([vec], dtype=np.float64)

            pred_arr = pipeline.predict(X)
            score_arr = pipeline.decision_function(X)

            raw_pred = int(pred_arr[0])
            raw_score = float(score_arr[0])

            status = (
                PredictionStatus.ANOMALY
                if raw_pred == -1
                else PredictionStatus.NORMAL
            )
            return status, round(raw_score, 6), raw_pred
        except Exception as exc:
            logger.error(f"Inference error on flow {getattr(flow, 'id', None)}: {exc}")
            return PredictionStatus.INFERENCE_ERROR, None, None

    def reset(self) -> None:
        """Unloads the active model."""
        with self._lock:
            self._active_model_id = None
            self._active_model_version = None
            self._active_pipeline = None


# Global ModelManager singleton
model_manager = ModelManager()
