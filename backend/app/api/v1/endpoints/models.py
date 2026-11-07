from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.detection import ModelRegistryResponse, ModelStatusResponse, TrainBaselineRequest
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/models", tags=["Machine Learning Models"])


@router.post(
    "/train-baseline",
    response_model=ModelRegistryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Train Isolation Forest on baseline session",
    description=(
        "Trains a scikit-learn Isolation Forest anomaly detector on authorized traffic collected "
        "in a completed BASELINE capture session. Serializes the pipeline artifact, computes an "
        "integrity checksum, registers metadata in PostgreSQL, and activates it for live detection."
    ),
)
def train_baseline(
    request: TrainBaselineRequest,
    db: Session = Depends(get_db),
) -> ModelRegistryResponse:
    try:
        return DetectionService.train_baseline(db=db, req=request)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Baseline model training failed: {str(exc)}",
        )


@router.get(
    "/status",
    response_model=ModelStatusResponse,
    summary="Get active ML model status",
    description="Returns current active model version, readiness status, artifact checksum, and feature schema.",
)
def get_model_status(
    db: Session = Depends(get_db),
) -> ModelStatusResponse:
    return DetectionService.get_model_status(db=db)
