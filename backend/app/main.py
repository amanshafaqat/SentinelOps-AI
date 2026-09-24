"""SentinelOps AI - FastAPI Application Entry Point.

Modular Monolith Architecture for AI SOC Analyst & Incident Response Copilot.
Configured with strict CORS, structured logging, safe exception handling,
and security headers.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.core.config import settings
from backend.app.core.logging import setup_logging, logger
from backend.app.core.errors import (
    SentinelOpsException,
    sentinelops_exception_handler,
    validation_exception_handler,
    http_exception_handler,
    unhandled_exception_handler,
)
from backend.app.api.v1.router import api_v1_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager for startup and shutdown procedures."""
    # Setup structured and filtered logging
    setup_logging()
    logger.info(
        f"Starting {settings.app_name} v{settings.app_version} [env={settings.app_env}]"
    )
    logger.info(f"API v1 mounted at: {settings.api_v1_prefix}")

    yield

    logger.info(f"Shutting down {settings.app_name} gracefully.")


def create_application() -> FastAPI:
    """Application factory for SentinelOps AI."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="SentinelOps AI - AI SOC Analyst & Incident Response Copilot",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # Security Headers Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

    # Safe CORS Middleware Configuration
    origins = settings.cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    # Register Global Exception Handlers
    app.add_exception_handler(SentinelOpsException, sentinelops_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # Mount API Routers
    app.include_router(api_v1_router, prefix=settings.api_v1_prefix)

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "status": "operational",
            "phase": "Phase 1 - Foundation & Architecture",
            "docs": "/docs" if not settings.is_production else "Disabled in production",
            "health": f"{settings.api_v1_prefix}/health",
        }

    return app


app = create_application()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )
