from app.api.v1.endpoints.capture import router as capture_router
from app.api.v1.endpoints.health import router as health_router

__all__ = ["capture_router", "health_router"]
