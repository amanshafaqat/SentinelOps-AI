"""Alerts API Endpoints.

Provides SOC alert queue listing, filtering, statistical metrics, detail inspection
with immutable evidence chains, and status triage updates.
"""

import math
from datetime import datetime
from typing import Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_, select

from backend.app.db.session import get_db
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent
from backend.app.schemas.alert import (
    AlertDetailResponse,
    AlertEvidenceResponse,
    AlertResponse,
    AlertStatsResponse,
    AlertStatusUpdate,
    PaginatedAlertsResponse,
)
from backend.app.schemas.event import SecurityEventResponse

router = APIRouter()


@router.get(
    "",
    response_model=PaginatedAlertsResponse,
    summary="List and Filter Security Alerts",
    description="Retrieve paginated security alerts with optional filters for severity, status, rule, user, IP, or keyword.",
)
def list_alerts(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=25, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (low, medium, high, critical)"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status (new, in_review, dismissed, escalated)"),
    rule_id: Optional[str] = Query(default=None, description="Filter by rule ID (e.g. RULE-001)"),
    affected_user: Optional[str] = Query(default=None, description="Filter by affected username"),
    affected_ip: Optional[str] = Query(default=None, description="Filter by affected IP"),
    search: Optional[str] = Query(default=None, description="Search term matching title, description, or host"),
    start_time: Optional[datetime] = Query(default=None, description="Filter detected_at >= start_time"),
    end_time: Optional[datetime] = Query(default=None, description="Filter detected_at <= end_time"),
    db: Session = Depends(get_db),
) -> PaginatedAlertsResponse:
    """List alerts with pagination and multidimensional filtering."""
    base_query = select(Alert)

    if severity:
        base_query = base_query.where(Alert.severity == severity.lower())
    if status_filter:
        base_query = base_query.where(Alert.status == status_filter.lower())
    if rule_id:
        base_query = base_query.where(Alert.rule_id == rule_id.upper())
    if affected_user:
        base_query = base_query.where(Alert.affected_user.ilike(f"%{affected_user}%"))
    if affected_ip:
        base_query = base_query.where(Alert.affected_ip == affected_ip)
    if start_time:
        base_query = base_query.where(Alert.detected_at >= start_time)
    if end_time:
        base_query = base_query.where(Alert.detected_at <= end_time)

    if search:
        pattern = f"%{search.strip()}%"
        base_query = base_query.where(
            or_(
                Alert.title.ilike(pattern),
                Alert.description.ilike(pattern),
                Alert.affected_hostname.ilike(pattern),
                Alert.rule_name.ilike(pattern),
            )
        )

    # Count total matching alerts
    count_stmt = select(func.count()).select_from(base_query.subquery())
    total = db.scalar(count_stmt) or 0

    # Paginate and order chronologically descending (newest detection first)
    offset = (page - 1) * page_size
    alerts_query = (
        base_query.options(joinedload(Alert.evidence))
        .order_by(Alert.detected_at.desc(), Alert.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )

    alerts = list(db.scalars(alerts_query).unique().all())
    total_pages = math.ceil(total / page_size) if total > 0 else 1

    alert_responses = [
        AlertResponse(
            id=a.id,
            rule_id=a.rule_id,
            rule_name=a.rule_name,
            title=a.title,
            description=a.description,
            severity=a.severity,
            status=a.status,
            dedup_key=a.dedup_key,
            affected_user=a.affected_user,
            affected_ip=a.affected_ip,
            affected_hostname=a.affected_hostname,
            detected_at=a.detected_at.isoformat() if a.detected_at else "",
            created_at=a.created_at.isoformat() if a.created_at else "",
            incident_id=a.incident_id,
            evidence_count=len(a.evidence) if a.evidence else 0,
        )
        for a in alerts
    ]

    return PaginatedAlertsResponse(
        alerts=alert_responses,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/stats",
    response_model=AlertStatsResponse,
    summary="Get Alert Statistics",
    description="Aggregated count of alerts categorized by severity, status, and triggering rule.",
)
def get_alert_stats(db: Session = Depends(get_db)) -> AlertStatsResponse:
    """Return aggregated alert metrics."""
    total = db.scalar(select(func.count(Alert.id))) or 0

    # Severity distribution
    sev_rows = db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    ).all()
    by_severity: Dict[str, int] = {s: c for s, c in sev_rows}

    # Status distribution
    status_rows = db.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    ).all()
    by_status: Dict[str, int] = {st: c for st, c in status_rows}

    # Rule distribution
    rule_rows = db.execute(
        select(Alert.rule_id, func.count(Alert.id)).group_by(Alert.rule_id)
    ).all()
    by_rule: Dict[str, int] = {r: c for r, c in rule_rows}

    return AlertStatsResponse(
        total_alerts=total,
        by_severity=by_severity,
        by_status=by_status,
        by_rule=by_rule,
    )


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Get Alert Details with Evidence",
    description="Retrieve an alert along with its full supporting evidence timeline and underlying SecurityEvents.",
)
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> AlertDetailResponse:
    """Retrieve full alert details including linked evidence events."""
    stmt = (
        select(Alert)
        .options(
            joinedload(Alert.evidence).joinedload(AlertEvidence.event)
        )
        .where(Alert.id == alert_id)
    )
    alert = db.scalar(stmt)

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' not found",
        )

    evidence_responses: list[AlertEvidenceResponse] = []
    for ev in alert.evidence:
        event_dict = None
        if ev.event:
            event_dict = SecurityEventResponse(**ev.event.to_dict())

        evidence_responses.append(
            AlertEvidenceResponse(
                id=ev.id,
                alert_id=ev.alert_id,
                event_id=ev.event_id,
                evidence_role=ev.evidence_role,
                description=ev.description,
                created_at=ev.created_at.isoformat() if ev.created_at else "",
                event=event_dict,
            )
        )

    return AlertDetailResponse(
        id=alert.id,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status=alert.status,
        dedup_key=alert.dedup_key,
        affected_user=alert.affected_user,
        affected_ip=alert.affected_ip,
        affected_hostname=alert.affected_hostname,
        detected_at=alert.detected_at.isoformat() if alert.detected_at else "",
        created_at=alert.created_at.isoformat() if alert.created_at else "",
        incident_id=alert.incident_id,
        evidence_count=len(alert.evidence),
        metadata=alert.alert_metadata or {},
        evidence=evidence_responses,
    )


@router.patch(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update Alert Status",
    description="Transition alert triage status (new, in_review, dismissed, escalated).",
)
def update_alert_status(
    alert_id: str,
    update: AlertStatusUpdate,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Update status of an alert."""
    alert = db.scalar(select(Alert).where(Alert.id == alert_id))
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' not found",
        )

    alert.status = update.status
    db.commit()
    db.refresh(alert)

    return AlertResponse(
        id=alert.id,
        rule_id=alert.rule_id,
        rule_name=alert.rule_name,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status=alert.status,
        dedup_key=alert.dedup_key,
        affected_user=alert.affected_user,
        affected_ip=alert.affected_ip,
        affected_hostname=alert.affected_hostname,
        detected_at=alert.detected_at.isoformat() if alert.detected_at else "",
        created_at=alert.created_at.isoformat() if alert.created_at else "",
        incident_id=alert.incident_id,
        evidence_count=len(alert.evidence) if alert.evidence else 0,
    )
