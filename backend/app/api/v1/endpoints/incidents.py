"""Incident API Endpoints.

Provides SOC incident management, correlation execution, detailed forensic investigation
with complete Incident -> Alert -> Security Event traceability, unified chronological timelines,
and audited analyst triage updates.
"""

from datetime import datetime, timezone
import math
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_, select, desc

from backend.app.core.errors import NotFoundError, ValidationError
from backend.app.core.logging import logger
from backend.app.db.session import get_db
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident, IncidentAuditLog
from backend.app.correlation.engine import default_correlation_engine
from backend.app.schemas.alert import AlertResponse
from backend.app.schemas.incident import (
    CorrelateRequest,
    CorrelateResponse,
    IncidentAuditLogResponse,
    IncidentDetailResponse,
    IncidentListItem,
    IncidentStatsResponse,
    IncidentStatusUpdate,
    IncidentTimelineItem,
    IncidentTimelineResponse,
    PaginatedIncidentsResponse,
)

router = APIRouter()

VALID_STATUSES = {"new", "investigating", "resolved", "closed"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


@router.post(
    "/correlate",
    response_model=CorrelateResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Incident Correlation Engine",
    description=(
        "Evaluates discrete security alerts against deterministic entity and temporal signals, "
        "synthesizing correlated incidents with explainable narratives."
    ),
)
def correlate_incidents(
    params: CorrelateRequest = CorrelateRequest(),
    db: Session = Depends(get_db),
) -> CorrelateResponse:
    """Trigger the correlation engine and return execution statistics."""
    logger.info(
        f"Triggering incident correlation (window={params.time_window_minutes}m, "
        f"min_severity={params.min_severity}, force_recorrelate={params.force_recorrelate})"
    )

    summary = default_correlation_engine.run_correlation(
        db=db,
        time_window_minutes=params.time_window_minutes,
        min_severity=params.min_severity,
        force_recorrelate=params.force_recorrelate,
    )

    return CorrelateResponse(
        alerts_evaluated=summary.alerts_evaluated,
        alerts_correlated=summary.alerts_correlated,
        incidents_created=summary.incidents_created,
        incidents_updated=summary.incidents_updated,
        execution_duration_ms=summary.execution_duration_ms,
        created_incident_ids=summary.created_incident_ids,
        correlation_window_minutes=summary.correlation_window_minutes,
        executed_at=summary.executed_at,
    )


@router.get(
    "/stats",
    response_model=IncidentStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Incident Statistics Summary",
    description="Aggregated incident counts by severity and status for SOC situational awareness.",
)
def get_incident_stats(db: Session = Depends(get_db)) -> IncidentStatsResponse:
    """Retrieve statistical distribution of security incidents."""
    total_incidents = db.scalar(select(func.count(Incident.id))) or 0

    open_incidents = (
        db.scalar(
            select(func.count(Incident.id)).where(
                Incident.status.in_(["new", "investigating"])
            )
        )
        or 0
    )

    # By Severity
    sev_rows = db.execute(
        select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
    ).all()
    by_severity = {row[0]: row[1] for row in sev_rows}
    for s in VALID_SEVERITIES:
        by_severity.setdefault(s, 0)

    # By Status
    status_rows = db.execute(
        select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
    ).all()
    by_status = {row[0]: row[1] for row in status_rows}
    for st in VALID_STATUSES:
        by_status.setdefault(st, 0)

    # Average alerts per incident
    total_alerts_in_incidents = (
        db.scalar(select(func.count(Alert.id)).where(Alert.incident_id.is_not(None))) or 0
    )
    avg_alerts = (
        round(total_alerts_in_incidents / total_incidents, 2)
        if total_incidents > 0
        else 0.0
    )

    return IncidentStatsResponse(
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        by_severity=by_severity,
        by_status=by_status,
        average_alerts_per_incident=avg_alerts,
    )


@router.get(
    "",
    response_model=PaginatedIncidentsResponse,
    summary="List and Filter Incidents",
    description="Retrieve paginated incidents with multi-attribute filtering on status, severity, user, IP, or keyword.",
)
def list_incidents(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (low, medium, high, critical)"),
    status: Optional[str] = Query(default=None, description="Filter by status (new, investigating, resolved, closed)"),
    affected_user: Optional[str] = Query(default=None, description="Filter incidents containing user"),
    affected_ip: Optional[str] = Query(default=None, description="Filter incidents containing IP"),
    search: Optional[str] = Query(default=None, description="Search term matching title or description"),
    start_time: Optional[datetime] = Query(default=None, description="Filter incidents first_seen >= start_time"),
    end_time: Optional[datetime] = Query(default=None, description="Filter incidents last_seen <= end_time"),
    db: Session = Depends(get_db),
) -> PaginatedIncidentsResponse:
    """List incidents with filtering and pagination."""
    base_query = select(Incident)

    if severity:
        base_query = base_query.where(Incident.severity == severity.lower())
    if status:
        base_query = base_query.where(Incident.status == status.strip().lower())
    if start_time:
        base_query = base_query.where(Incident.first_seen >= start_time)
    if end_time:
        base_query = base_query.where(Incident.last_seen <= end_time)

    if search:
        pattern = f"%{search.strip()}%"
        base_query = base_query.where(
            or_(
                Incident.title.ilike(pattern),
                Incident.description.ilike(pattern),
            )
        )

    # Execute count
    count_stmt = select(func.count()).select_from(base_query.subquery())
    total = db.scalar(count_stmt) or 0

    # Paginate and order by last_seen descending
    offset = (page - 1) * page_size
    incidents_query = (
        base_query.options(joinedload(Incident.alerts))
        .order_by(Incident.last_seen.desc(), Incident.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )

    incidents = list(db.scalars(incidents_query).unique().all())

    # In-memory filter for JSON list fields if specified
    if affected_user:
        u_lower = affected_user.strip().lower()
        incidents = [
            inc for inc in incidents
            if any(u_lower in str(u).lower() for u in (inc.affected_users or []))
        ]
    if affected_ip:
        ip_clean = affected_ip.strip()
        incidents = [
            inc for inc in incidents
            if any(ip_clean in str(ip) for ip in (inc.affected_ips or []))
        ]

    total_pages = math.ceil(total / page_size) if total > 0 else 1

    items: List[IncidentListItem] = []
    for inc in incidents:
        items.append(
            IncidentListItem(
                id=inc.id,
                title=inc.title,
                description=inc.description,
                severity=inc.severity,
                status=inc.status,
                first_seen=inc.first_seen.isoformat() if inc.first_seen else "",
                last_seen=inc.last_seen.isoformat() if inc.last_seen else "",
                affected_users=inc.affected_users or [],
                affected_ips=inc.affected_ips or [],
                affected_hostnames=inc.affected_hostnames or [],
                alert_count=len(inc.alerts) if inc.alerts else 0,
                correlation_reasons=inc.correlation_reasons or [],
                created_at=inc.created_at.isoformat() if inc.created_at else "",
                updated_at=inc.updated_at.isoformat() if inc.updated_at else "",
            )
        )

    return PaginatedIncidentsResponse(
        incidents=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Get Detailed Incident",
    description="Retrieve full incident record, correlated alerts, supporting evidence links, and audit history.",
)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    """Fetch individual incident with related alerts and audit trail."""
    stmt = (
        select(Incident)
        .options(
            joinedload(Incident.alerts).joinedload(Alert.evidence),
            joinedload(Incident.audit_logs),
        )
        .where(Incident.id == incident_id)
    )
    incident = db.scalar(stmt)
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

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
        for a in incident.alerts
    ]

    audit_responses = [
        IncidentAuditLogResponse(
            id=log.id,
            incident_id=log.incident_id,
            action=log.action,
            previous_value=log.previous_value,
            new_value=log.new_value,
            notes=log.notes,
            actor=log.actor,
            created_at=log.created_at.isoformat() if log.created_at else "",
        )
        for log in sorted(incident.audit_logs, key=lambda l: l.created_at, reverse=True)
    ]

    return IncidentDetailResponse(
        id=incident.id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        first_seen=incident.first_seen.isoformat() if incident.first_seen else "",
        last_seen=incident.last_seen.isoformat() if incident.last_seen else "",
        affected_users=incident.affected_users or [],
        affected_ips=incident.affected_ips or [],
        affected_hostnames=incident.affected_hostnames or [],
        alert_count=len(incident.alerts),
        correlation_reasons=incident.correlation_reasons or [],
        correlation_metadata=incident.correlation_metadata or {},
        alerts=alert_responses,
        audit_logs=audit_responses,
        created_at=incident.created_at.isoformat() if incident.created_at else "",
        updated_at=incident.updated_at.isoformat() if incident.updated_at else "",
    )


@router.get(
    "/{incident_id}/timeline",
    response_model=IncidentTimelineResponse,
    summary="Incident Investigation Timeline",
    description="Unified, strictly chronological timeline combining Security Events, Alerts, and Incident Actions.",
)
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
) -> IncidentTimelineResponse:
    """Assembles a unified chronological timeline from telemetry events, alerts, and incident actions."""
    incident = db.scalar(
        select(Incident)
        .options(
            joinedload(Incident.alerts).joinedload(Alert.evidence).joinedload(AlertEvidence.event),
            joinedload(Incident.audit_logs),
        )
        .where(Incident.id == incident_id)
    )
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    timeline_items: List[IncidentTimelineItem] = []
    seen_event_ids = set()

    # 1. Telemetry Security Events (from constituent alert evidence)
    for alert in incident.alerts:
        for ev in alert.evidence:
            event_obj = ev.event
            if event_obj and event_obj.id not in seen_event_ids:
                seen_event_ids.add(event_obj.id)
                timeline_items.append(
                    IncidentTimelineItem(
                        id=event_obj.id,
                        item_type="event",
                        timestamp=event_obj.timestamp.isoformat() if event_obj.timestamp else "",
                        title=f"Telemetry Event: {event_obj.event_type.upper()} ({event_obj.action or 'action'})",
                        description=event_obj.message,
                        severity=event_obj.severity,
                        status=event_obj.status,
                        entity=event_obj.username or event_obj.source_ip or event_obj.hostname,
                        source=event_obj.source,
                        metadata={
                            "source_ip": event_obj.source_ip,
                            "destination_ip": event_obj.destination_ip,
                            "evidence_role": ev.evidence_role,
                            "event_type": event_obj.event_type,
                            "action": event_obj.action,
                        },
                    )
                )

    # 2. Correlated Security Alerts
    for alert in incident.alerts:
        timeline_items.append(
            IncidentTimelineItem(
                id=alert.id,
                item_type="alert",
                timestamp=alert.detected_at.isoformat() if alert.detected_at else "",
                title=f"Detection Alert: {alert.rule_name} [{alert.rule_id}]",
                description=alert.description,
                severity=alert.severity,
                status=alert.status,
                entity=alert.affected_user or alert.affected_ip,
                source=alert.rule_id,
                metadata={
                    "rule_id": alert.rule_id,
                    "dedup_key": alert.dedup_key,
                    "evidence_count": len(alert.evidence),
                    "alert_title": alert.title,
                },
            )
        )

    # 3. Incident Lifecycle Actions (Audit entries)
    for log in incident.audit_logs:
        timeline_items.append(
            IncidentTimelineItem(
                id=log.id,
                item_type="incident_action",
                timestamp=log.created_at.isoformat() if log.created_at else "",
                title=f"Incident Action: {log.action.replace('_', ' ').title()}",
                description=log.notes or f"Value changed from '{log.previous_value}' to '{log.new_value}'",
                severity=incident.severity,
                status=incident.status,
                entity=log.actor,
                source=f"actor:{log.actor}",
                metadata={
                    "action": log.action,
                    "previous_value": log.previous_value,
                    "new_value": log.new_value,
                    "actor": log.actor,
                },
            )
        )

    # Sort strictly chronologically by timestamp ascending
    timeline_items.sort(key=lambda item: item.timestamp)

    return IncidentTimelineResponse(
        incident_id=incident.id,
        total_items=len(timeline_items),
        items=timeline_items,
    )


@router.patch(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Update Incident Status and Severity",
    description="Allows SOC analysts to modify incident lifecycle status, severity, title, and add audited notes.",
)
def update_incident(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
) -> IncidentDetailResponse:
    """Audited mutation of incident triage status or severity."""
    incident = db.scalar(
        select(Incident)
        .options(
            joinedload(Incident.alerts).joinedload(Alert.evidence),
            joinedload(Incident.audit_logs),
        )
        .where(Incident.id == incident_id)
    )
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    actor = (payload.actor or "analyst").strip()

    # 1. Status Mutation
    if payload.status:
        normalized_status = payload.status.strip().lower()
        if normalized_status not in VALID_STATUSES:
            raise ValidationError(
                message=f"Invalid status '{payload.status}'. Allowed: {sorted(list(VALID_STATUSES))}",
                details={"allowed": list(VALID_STATUSES), "provided": payload.status},
            )
        if normalized_status != incident.status:
            prev_status = incident.status
            incident.status = normalized_status
            audit = IncidentAuditLog(
                incident_id=incident.id,
                action="status_change",
                previous_value=prev_status,
                new_value=normalized_status,
                notes=payload.notes or f"Analyst updated incident status to {normalized_status}.",
                actor=actor,
            )
            db.add(audit)

    # 2. Severity Mutation
    if payload.severity:
        normalized_sev = payload.severity.strip().lower()
        if normalized_sev not in VALID_SEVERITIES:
            raise ValidationError(
                message=f"Invalid severity '{payload.severity}'. Allowed: {sorted(list(VALID_SEVERITIES))}",
                details={"allowed": list(VALID_SEVERITIES), "provided": payload.severity},
            )
        if normalized_sev != incident.severity:
            prev_sev = incident.severity
            incident.severity = normalized_sev
            audit = IncidentAuditLog(
                incident_id=incident.id,
                action="severity_change",
                previous_value=prev_sev,
                new_value=normalized_sev,
                notes=payload.notes or f"Analyst updated incident severity to {normalized_sev}.",
                actor=actor,
            )
            db.add(audit)

    # 3. Title / Description
    if payload.title:
        incident.title = payload.title.strip()
    if payload.description:
        incident.description = payload.description.strip()

    # 4. Analyst standalone note
    if payload.notes and not payload.status and not payload.severity:
        audit = IncidentAuditLog(
            incident_id=incident.id,
            action="analyst_note",
            previous_value=None,
            new_value=None,
            notes=payload.notes.strip(),
            actor=actor,
        )
        db.add(audit)

    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(incident)

    return get_incident(incident_id=incident_id, db=db)
