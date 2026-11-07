"""
Pydantic v2 schemas for ML Model Registry, Predictions, and Security Alerts.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Model Registry Schemas
# ---------------------------------------------------------------------------

class TrainBaselineRequest(BaseModel):
    session_id: uuid.UUID = Field(..., description="ID of completed BASELINE capture session")
    model_name: Optional[str] = Field("IsolationForest_Baseline", description="Name label for model")
    min_samples: Optional[int] = Field(None, description="Optional minimum sample threshold override")
    contamination: Optional[float] = Field(None, description="Expected proportion of outliers in baseline", ge=0.001, le=0.5)
    n_estimators: Optional[int] = Field(None, description="Number of isolation trees", ge=10, le=1000)


class ModelRegistryResponse(BaseModel):
    id: uuid.UUID
    name: str
    version: str
    algorithm: str
    status: str
    feature_names: List[str]
    feature_schema_version: str
    training_session_id: Optional[uuid.UUID] = None
    training_sample_count: int
    training_params: Dict[str, Any] = Field(default_factory=dict)
    artifact_path: Optional[str] = None
    artifact_checksum: Optional[str] = None
    evaluation_info: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    created_at: datetime

    model_config = {
        "from_attributes": True,
    }


class ModelStatusResponse(BaseModel):
    active_model: Optional[ModelRegistryResponse] = None
    is_ready: bool = Field(..., description="Whether an ML model is loaded and ready for live inference")
    total_registered_models: int = Field(0, description="Total count of models in registry")


# ---------------------------------------------------------------------------
# Prediction Schemas
# ---------------------------------------------------------------------------

class PredictionResponse(BaseModel):
    id: uuid.UUID
    flow_id: uuid.UUID
    model_id: Optional[uuid.UUID] = None
    model_version: Optional[str] = None
    status: str
    raw_score: Optional[float] = None
    raw_prediction: Optional[int] = None
    created_at: datetime
    alerts_generated: int = Field(0, description="Count of alerts generated/updated by this prediction")

    model_config = {
        "from_attributes": True,
    }


class PredictionListResponse(BaseModel):
    total: int
    items: List[PredictionResponse]
    skip: int
    limit: int


# ---------------------------------------------------------------------------
# Alert Schemas
# ---------------------------------------------------------------------------

class AlertResponse(BaseModel):
    id: uuid.UUID
    flow_id: Optional[uuid.UUID] = None
    session_id: Optional[uuid.UUID] = None
    detection_source: str
    model_version: Optional[str] = None
    rule_id: Optional[str] = None
    rule_evidence: Dict[str, Any] = Field(default_factory=dict)
    severity: str
    title: str
    description: str
    fingerprint: str
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    status: str
    resolved_at: Optional[datetime] = None
    created_at: datetime

    model_config = {
        "from_attributes": True,
    }


class AlertListResponse(BaseModel):
    total: int
    items: List[AlertResponse]
    skip: int
    limit: int
