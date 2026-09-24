"""Health Check Endpoints.

Provides simple and detailed health status for load balancers, container orchestrators,
and administrative dashboards.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, status
from pydantic import BaseModel
from backend.app.core.config import settings
from backend.app.db.session import check_database_connection

router = APIRouter(prefix="/health", tags=["Health & Diagnostics"])


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    timestamp: str


class DatabaseStatus(BaseModel):
    status: str
    dialect: str
    latency_ms: float
    error: str | None = None


class DetailedHealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    timestamp: str
    database: DatabaseStatus


@router.get(
    "",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Basic Service Health Check",
    description="Returns service availability, version, and current UTC timestamp.",
)
async def get_health() -> HealthResponse:
    """Basic health check endpoint."""
    return HealthResponse(
        status="healthy",
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/detailed",
    response_model=DetailedHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Detailed System Health and Database Connectivity",
    description="Returns detailed health metrics including database connection check.",
)
async def get_detailed_health() -> DetailedHealthResponse:
    """Detailed health check endpoint including database connectivity."""
    db_check = check_database_connection()
    overall_status = "healthy" if db_check.get("status") == "connected" else "degraded"

    return DetailedHealthResponse(
        status=overall_status,
        service=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        timestamp=datetime.now(timezone.utc).isoformat(),
        database=DatabaseStatus(
            status=db_check.get("status", "unknown"),
            dialect=db_check.get("dialect", "unknown"),
            latency_ms=db_check.get("latency_ms", 0.0),
            error=db_check.get("error"),
        ),
    )
