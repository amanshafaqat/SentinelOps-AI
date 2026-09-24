"""System Information and Architectural Specification Endpoints."""

from typing import List, Dict, Any
from fastapi import APIRouter, status
from pydantic import BaseModel
from backend.app.core.config import settings

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
    summary="System Architecture and Phase Status",
    description="Returns metadata about SentinelOps AI architecture, current phase, and capabilities.",
)
async def get_system_info() -> SystemInfoResponse:
    """Returns platform metadata and phase verification info."""
    return SystemInfoResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        current_phase="Phase 1",
        phase_title="Foundation & Architecture",
        architecture={
            "style": "Modular Monolith",
            "backend": "FastAPI + Pydantic v2",
            "database": "PostgreSQL + SQLAlchemy 2.0 + Alembic",
            "frontend": "React / TypeScript + Tailwind CSS",
            "detection_engine": "Deterministic Python (Isolated from LLM)",
            "ai_copilot": "Gemini API (Server-Side Only, Phase 5)",
        },
        security_features=[
            "Zero client-side AI keys",
            "Sanitized structured logging (redacts secrets)",
            "Strict CORS origin validation",
            "Structured error response envelopes",
            "Untrusted log data handling architecture",
        ],
    )
