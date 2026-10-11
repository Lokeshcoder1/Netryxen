from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_v1_router
from app.capture.capture_manager import capture_manager
from app.core.config import settings
from app.core.logging import logger
from app.schemas.error import ErrorDetail, ErrorResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    Ensures safe initialization and graceful cleanup of resources upon shutdown.
    NOTE: Per specifications, Base.metadata.create_all() is strictly omitted.
    Schema migrations are managed explicitly via Alembic.
    """
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    yield
    # Shutdown logic
    logger.info("Application shutting down...")
    if capture_manager.is_running:
        logger.info("Stopping active capture engine on shutdown...")
        try:
            capture_manager.stop_capture()
        except Exception as exc:
            logger.warning(f"Error during shutdown capture termination: {exc}")
    logger.info("Shutdown cleanup complete.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Backend foundation and live network packet capture engine for NIDS.",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware for local prototype development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled exception at {request.url.path}: {exc}", exc_info=True)
    error_resp = ErrorResponse(
        error=ErrorDetail(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected internal server error occurred.",
        )
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_resp.model_dump(),
    )


# Register API v1 routes
app.include_router(api_v1_router, prefix=settings.API_V1_STR)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.DEBUG,
    )
