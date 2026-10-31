from fastapi import APIRouter

from app.api.v1.endpoints.capture import router as capture_router
from app.api.v1.endpoints.dashboard import router as dashboard_router
from app.api.v1.endpoints.flows import router as flows_router
from app.api.v1.endpoints.health import router as health_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router)
api_v1_router.include_router(capture_router)
api_v1_router.include_router(flows_router)
api_v1_router.include_router(dashboard_router)
