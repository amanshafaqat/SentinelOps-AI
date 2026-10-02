"""System Information and Architectural Specification Endpoints."""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.auth import AuthUser, get_current_user
from backend.app.db.session import get_db
from backend.app.services.demo_seeder import seed_demo_pipeline

router = APIRouter(prefix="/system", tags=["System Information"])


class SystemInfoResponse(BaseModel):
    name: str
    version: str
    environment: str
    current_phase: str
    phase_title: str
    architecture: Dict[str, Any]
    security_features: List[str]


@router.get(
    "/info",
    response_model=SystemInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="System Status",
    description="Returns platform operational status.",
)
async def get_system_info() -> SystemInfoResponse:
    """Returns platform operational metadata without exposing internal configuration."""
    return SystemInfoResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        current_phase="Operational",
        phase_title="AI-Assisted SOC & Incident Response Copilot",
        architecture={
            "service": "SentinelOps AI",
            "status": "Operational",
        },
        security_features=[
            "Deterministic Detection & Alert Deduplication",
            "Explainable Incident Correlation",
            "Evidence-Grounded AI Investigation Copilot",
            "Audited Incident Lifecycle & Case Notes",
            "Server-Side Authorization Matrix",
        ],
    )


@router.post(
    "/demo/seed",
    status_code=status.HTTP_200_OK,
    summary="Seed Demo Scenarios",
    description="Seeds realistic telemetry for demonstration scenarios in development mode.",
)
def run_demo_seed(
    current_user: AuthUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Execute end-to-end demo seeding pipeline. Disabled in production."""
    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo database seeding is disabled in production environments.",
        )
    result = seed_demo_pipeline(db=db, force_reset=True)
    return result

