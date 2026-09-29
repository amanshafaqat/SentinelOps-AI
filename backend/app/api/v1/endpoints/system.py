"""System Information and Architectural Specification Endpoints."""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.config import settings
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
    summary="System Architecture and Phase Status",
    description="Returns metadata about SentinelOps AI architecture, current phase, and capabilities.",
)
async def get_system_info() -> SystemInfoResponse:
    """Returns platform metadata and phase verification info."""
    return SystemInfoResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.app_env,
        current_phase="Phase 7",
        phase_title="Security Audit, Testing & Production Polish",
        architecture={
            "style": "Modular Monolith",
            "backend": "FastAPI + Pydantic v2",
            "database": "PostgreSQL / SQLite + SQLAlchemy 2.0 + Alembic",
            "frontend": "React / TypeScript + Tailwind CSS",
            "detection_engine": "Deterministic Python (Isolated from LLM)",
            "correlation_engine": "Deterministic & Explainable Graph/Window Engine",
            "ai_copilot": f"Gemini ({settings.gemini_model}) Server-Side Evidence-Grounded Copilot",
            "case_management": "Audited Case Notes & Structured Evidence-Grounded Reports",
            "security_hardening": "Role-Based Server Authorization Matrix, Strict Input Sanitization & Audit Trails",
        },
        security_features=[
            "Zero client-side AI keys (server-side proxy only)",
            "Server-side role-based authorization matrix on all sensitive mutating endpoints",
            "Strict prompt injection defense with delimited untrusted data boundary",
            "Deterministic evidence-grounding cross-reference validation (flags hallucinated references)",
            "Evidence-grounded report generation with Incident -> Alert -> Event traceability",
            "Strict path traversal and hostile filename sanitization on file uploads",
            "Content-Disposition header injection defense on report downloads",
            "Case note modification and deletion author authorization enforcement",
            "Sanitized structured logging (redacts secrets, tokens, and API keys)",
            "Strict CORS origin validation and defense-in-depth security headers",
            "Structured error response envelopes (zero stack trace or internal path leakage)",
            "Audited SOC Incident Lifecycle & Case Activity Stream",
            "Controlled status transition enforcement and immutable audit trail",
        ],
    )


@router.post(
    "/demo/seed",
    status_code=status.HTTP_200_OK,
    summary="Seed Phase 4 Demo Scenarios",
    description="Seeds realistic telemetry for Scenarios 1-4, runs detection, and executes correlation engine.",
)
def run_demo_seed(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Execute end-to-end demo seeding pipeline."""
    result = seed_demo_pipeline(db=db, force_reset=True)
    return result

