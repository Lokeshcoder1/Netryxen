from typing import Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.detection import PredictionListResponse, PredictionResponse
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/predictions", tags=["Predictions & Inference"])


@router.get(
    "",
    response_model=PredictionListResponse,
    summary="List historical predictions",
    description="Retrieves a paginated list of flow predictions with optional filtering by flow, model, or status.",
)
def list_predictions(
    flow_id: Optional[uuid.UUID] = Query(None, description="Filter by flow UUID"),
    model_id: Optional[uuid.UUID] = Query(None, description="Filter by model UUID"),
    status: Optional[str] = Query(None, description="Filter by status (NORMAL, ANOMALY, MODEL_NOT_READY, INFERENCE_ERROR)"),
    skip: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    db: Session = Depends(get_db),
) -> PredictionListResponse:
    return DetectionService.list_predictions(
        db=db, flow_id=flow_id, model_id=model_id, status=status, skip=skip, limit=limit
    )


@router.post(
    "/{flow_id}",
    response_model=PredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute detection on flow record",
    description=(
        "Executes Isolation Forest anomaly scoring and behavioral rule evaluation on a flow record. "
        "Applies the alert decision policy, generates deduplicated alerts if warranted, "
        "and persists the prediction record."
    ),
)
def predict_flow(
    flow_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> PredictionResponse:
    try:
        return DetectionService.predict_flow(db=db, flow_id=flow_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference execution failed: {str(exc)}",
        )
