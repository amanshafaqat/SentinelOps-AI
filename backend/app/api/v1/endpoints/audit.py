"""API Endpoints for SOC Audit Logs and Compliance History."""

from typing import List, Optional
import re
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from pydantic import BaseModel, Field

from backend.app.db.session import get_db
from backend.app.models.incident import IncidentAuditLog
from backend.app.schemas.incident import IncidentAuditLogResponse

router = APIRouter(prefix="/audit", tags=["Audit Logging"])


class AuditLogListResponse(BaseModel):
    total: int = Field(description="Total audit log entries matching filter")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Number of records per page")
    logs: List[IncidentAuditLogResponse] = Field(description="List of audit records")


# Redaction pattern for sensitive tokens, passwords, keys
SECRET_PATTERN = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9\-._~+/]+=*|password[\"'\s:=]+[^\s,\";]+|api[_-]?key[\"'\s:=]+[^\s,\";]+|secret[\"'\s:=]+[^\s,\";]+|AIza[0-9A-Za-z\-_]{35})"
)


def redact_sensitive_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    return SECRET_PATTERN.sub("[REDACTED_SECRET]", text)


@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get System & Incident Audit Logs",
    description="Retrieves immutable chronological audit records with sensitive token redaction.",
)
def get_audit_logs(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=200, description="Page size"),
    action: Optional[str] = Query(default=None, description="Filter by action type"),
    actor: Optional[str] = Query(default=None, description="Filter by actor handle"),
    incident_id: Optional[str] = Query(default=None, description="Filter by incident UUID"),
    db: Session = Depends(get_db),
) -> AuditLogListResponse:
    query = select(IncidentAuditLog)
    count_query = select(func.count(IncidentAuditLog.id))

    if action:
        query = query.where(IncidentAuditLog.action == action.strip().upper())
        count_query = count_query.where(IncidentAuditLog.action == action.strip().upper())
    if actor:
        query = query.where(IncidentAuditLog.actor == actor.strip())
        count_query = count_query.where(IncidentAuditLog.actor == actor.strip())
    if incident_id:
        query = query.where(IncidentAuditLog.incident_id == incident_id.strip())
        count_query = count_query.where(IncidentAuditLog.incident_id == incident_id.strip())

    total = db.scalar(count_query) or 0
    records = db.scalars(
        query.order_by(IncidentAuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    items = [
        IncidentAuditLogResponse(
            id=r.id,
            incident_id=r.incident_id,
            action=r.action,
            previous_value=redact_sensitive_text(r.previous_value),
            new_value=redact_sensitive_text(r.new_value),
            notes=redact_sensitive_text(r.notes),
            actor=r.actor,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in records
    ]

    return AuditLogListResponse(
        total=total,
        page=page,
        page_size=page_size,
        logs=items,
    )
