"""Incident API Endpoints.

Provides SOC incident management, correlation execution, detailed forensic investigation
with complete Incident -> Alert -> Security Event traceability, unified chronological timelines,
and audited analyst triage updates.
"""

import uuid
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Set
from fastapi import APIRouter, Depends, HTTPException, Query, status, Path, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_, select, desc

from backend.app.core.errors import NotFoundError, ValidationError
from backend.app.core.logging import logger
from backend.app.db.session import get_db
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident, IncidentAuditLog, CaseNote, InvestigationReport
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
from backend.app.schemas.case import (
    CaseNoteCreate,
    CaseNoteUpdate,
    CaseNoteResponse,
    CaseNoteListResponse,
    InvestigationReportCreate,
    InvestigationReportListItem,
    InvestigationReportListResponse,
    InvestigationReportResponse,
)
from backend.app.services.report_generator import ReportGeneratorService

router = APIRouter()

VALID_STATUSES = {"new", "investigating", "resolved", "closed"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

ALLOWED_STATUS_TRANSITIONS: Dict[str, Set[str]] = {
    "new": {"investigating", "resolved", "closed"},
    "investigating": {"resolved", "closed", "new"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},
}


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
            joinedload(Incident.notes),
            joinedload(Incident.reports),
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

    note_responses = [
        CaseNoteResponse(
            id=n.id,
            incident_id=n.incident_id,
            author=n.author,
            content=n.content,
            created_at=n.created_at.isoformat() if n.created_at else "",
            updated_at=n.updated_at.isoformat() if n.updated_at else "",
        )
        for n in sorted(incident.notes, key=lambda l: l.created_at, reverse=True)
    ] if incident.notes else []

    report_responses = [
        InvestigationReportListItem(
            id=r.id,
            incident_id=r.incident_id,
            title=r.title,
            report_type=r.report_type,
            generated_by=r.generated_by,
            summary=r.summary,
            metadata=r.metadata_info or {},
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in sorted(incident.reports, key=lambda l: l.created_at, reverse=True)
    ] if incident.reports else []

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
        notes=note_responses,
        reports=report_responses,
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
            allowed_transitions = ALLOWED_STATUS_TRANSITIONS.get(incident.status, set())
            if normalized_status not in allowed_transitions:
                raise ValidationError(
                    message=f"Invalid status transition from '{incident.status}' to '{normalized_status}'. Allowed transitions: {sorted(list(allowed_transitions))}",
                    details={
                        "current_status": incident.status,
                        "attempted_status": normalized_status,
                        "allowed": sorted(list(allowed_transitions)),
                    },
                )
            prev_status = incident.status
            incident.status = normalized_status
            audit = IncidentAuditLog(
                incident_id=incident.id,
                action="status_change",
                previous_value=prev_status,
                new_value=normalized_status,
                notes=payload.notes or f"Analyst updated incident status from {prev_status} to {normalized_status}.",
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


# ============================================================================
# PHASE 6: CASE NOTES & ANALYST INVESTIGATION NOTES
# ============================================================================

@router.post(
    "/{incident_id}/notes",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add Analyst Investigation Note",
    description="Attaches a validated forensic note to the incident case and writes an immutable audit record.",
)
def add_case_note(
    incident_id: str,
    payload: CaseNoteCreate,
    db: Session = Depends(get_db),
) -> CaseNoteResponse:
    """Add a validated analyst investigation note to the incident case."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    author = (payload.author or "soc_analyst").strip()
    content = payload.content.strip()

    note = CaseNote(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        author=author,
        content=content,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(note)

    # Immutable audit trail entry
    preview = content[:80] + ("..." if len(content) > 80 else "")
    audit = IncidentAuditLog(
        incident_id=incident.id,
        action="NOTE_ADDED",
        previous_value=None,
        new_value=note.id,
        notes=f"Note added by {author}: {preview}",
        actor=author,
    )
    db.add(audit)

    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(note)

    return CaseNoteResponse(
        id=note.id,
        incident_id=note.incident_id,
        author=note.author,
        content=note.content,
        created_at=note.created_at.isoformat(),
        updated_at=note.updated_at.isoformat(),
    )


@router.get(
    "/{incident_id}/notes",
    response_model=CaseNoteListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Investigation Notes",
    description="Retrieves all analyst investigation notes for an incident, ordered latest first.",
)
def list_case_notes(
    incident_id: str,
    db: Session = Depends(get_db),
) -> CaseNoteListResponse:
    """Retrieve all case notes for an incident."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    notes = db.scalars(
        select(CaseNote)
        .where(CaseNote.incident_id == incident_id)
        .order_by(CaseNote.created_at.desc())
    ).all()

    items = [
        CaseNoteResponse(
            id=n.id,
            incident_id=n.incident_id,
            author=n.author,
            content=n.content,
            created_at=n.created_at.isoformat() if n.created_at else "",
            updated_at=n.updated_at.isoformat() if n.updated_at else "",
        )
        for n in notes
    ]

    return CaseNoteListResponse(
        incident_id=incident_id,
        total=len(items),
        notes=items,
    )


@router.put(
    "/{incident_id}/notes/{note_id}",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Analyst Investigation Note",
    description="Edits an existing investigation note. Audits changes and enforces authorization.",
)
@router.patch(
    "/{incident_id}/notes/{note_id}",
    response_model=CaseNoteResponse,
    status_code=status.HTTP_200_OK,
)
def update_case_note(
    incident_id: str,
    note_id: str,
    payload: CaseNoteUpdate,
    db: Session = Depends(get_db),
) -> CaseNoteResponse:
    """Edit an existing analyst note and record the audit entry."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    note = db.scalar(
        select(CaseNote).where(CaseNote.id == note_id, CaseNote.incident_id == incident_id)
    )
    if not note:
        raise NotFoundError(
            message=f"Case note with ID '{note_id}' not found for incident '{incident_id}'.",
            details={"note_id": note_id, "incident_id": incident_id},
        )

    actor = (payload.author or note.author).strip()
    if note.author and payload.author and payload.author != note.author and payload.author not in ["soc_analyst", "admin", "lead_analyst"]:
        raise ValidationError(
            message=f"User '{payload.author}' is not authorized to edit note authored by '{note.author}'.",
            details={"author": note.author, "requested_by": payload.author},
        )

    prev_preview = note.content[:60]
    note.content = payload.content.strip()
    note.updated_at = datetime.now(timezone.utc)

    # Auditing edit
    audit = IncidentAuditLog(
        incident_id=incident.id,
        action="NOTE_UPDATED",
        previous_value=prev_preview,
        new_value=note.content[:60],
        notes=f"Note updated by {actor}.",
        actor=actor,
    )
    db.add(audit)

    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(note)

    return CaseNoteResponse(
        id=note.id,
        incident_id=note.incident_id,
        author=note.author,
        content=note.content,
        created_at=note.created_at.isoformat() if note.created_at else "",
        updated_at=note.updated_at.isoformat() if note.updated_at else "",
    )


@router.delete(
    "/{incident_id}/notes/{note_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Analyst Investigation Note",
    description="Deletes a note and records an immutable audit trail entry.",
)
def delete_case_note(
    incident_id: str,
    note_id: str,
    author: Optional[str] = Query(default="soc_analyst"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Delete an analyst note with audit logging."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    note = db.scalar(
        select(CaseNote).where(CaseNote.id == note_id, CaseNote.incident_id == incident_id)
    )
    if not note:
        raise NotFoundError(
            message=f"Case note with ID '{note_id}' not found for incident '{incident_id}'.",
            details={"note_id": note_id, "incident_id": incident_id},
        )

    actor = (author or "soc_analyst").strip()
    if note.author and actor != note.author and actor not in ["soc_analyst", "admin", "lead_analyst"]:
        raise ValidationError(
            message=f"User '{actor}' is not authorized to delete note authored by '{note.author}'.",
            details={"author": note.author, "requested_by": actor},
        )

    db.delete(note)
    audit = IncidentAuditLog(
        incident_id=incident.id,
        action="NOTE_DELETED",
        previous_value=note_id,
        new_value=None,
        notes=f"Note deleted by {author}: {note.content[:60]}...",
        actor=author or "soc_analyst",
    )
    db.add(audit)

    incident.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"status": "deleted", "id": note_id, "incident_id": incident_id}


# ============================================================================
# PHASE 6: INVESTIGATION HISTORY & CASE ACTIVITIES
# ============================================================================

@router.get(
    "/{incident_id}/history",
    response_model=List[IncidentAuditLogResponse],
    status_code=status.HTTP_200_OK,
    summary="Investigation History / Case Activity",
    description="Returns chronological audit logs and case activities for the incident.",
)
def get_incident_history(
    incident_id: str,
    db: Session = Depends(get_db),
) -> List[IncidentAuditLogResponse]:
    """Retrieve complete audit history and activity stream for an incident."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    audit_logs = db.scalars(
        select(IncidentAuditLog)
        .where(IncidentAuditLog.incident_id == incident_id)
        .order_by(IncidentAuditLog.created_at.desc())
    ).all()

    return [
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
        for log in audit_logs
    ]


# ============================================================================
# PHASE 6: INVESTIGATION REPORTS GENERATION, PREVIEW & EXPORT
# ============================================================================

@router.post(
    "/{incident_id}/reports",
    response_model=InvestigationReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate Investigation Report",
    description="Generates an evidence-grounded incident investigation report in structured JSON and print-ready HTML.",
)
@router.post(
    "/{incident_id}/report",
    response_model=InvestigationReportResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
def generate_investigation_report(
    incident_id: str,
    payload: InvestigationReportCreate = InvestigationReportCreate(),
    db: Session = Depends(get_db),
) -> InvestigationReportResponse:
    """Generate an evidence-grounded report from actual incident data."""
    incident = db.scalar(
        select(Incident)
        .options(joinedload(Incident.alerts))
        .where(Incident.id == incident_id)
    )
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    # Versioning: count existing reports to determine version number
    existing_count = db.scalar(
        select(func.count(InvestigationReport.id)).where(
            InvestigationReport.incident_id == incident_id
        )
    ) or 0
    version = existing_count + 1

    generator_actor = (payload.generated_by or "soc_analyst").strip()

    generated = ReportGeneratorService.generate_report(
        db=db,
        incident=incident,
        report_type=payload.report_type or "investigation_summary",
        custom_title=payload.title,
        generated_by=generator_actor,
        include_ai_analysis=payload.include_ai_analysis,
    )

    metadata_info = generated["metadata_info"]
    metadata_info["version"] = version

    report = InvestigationReport(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        title=generated["title"],
        report_type=payload.report_type or "investigation_summary",
        generated_by=generator_actor,
        summary=generated["summary"],
        content=generated["content"],
        rendered_html=generated["rendered_html"],
        metadata_info=metadata_info,
        created_at=datetime.now(timezone.utc),
    )
    db.add(report)

    # Auditing report generation
    audit = IncidentAuditLog(
        incident_id=incident.id,
        action="REPORT_GENERATED",
        previous_value=None,
        new_value=report.id,
        notes=f"Generated report '{report.title}' (v{version}) by {generator_actor}.",
        actor=generator_actor,
    )
    db.add(audit)

    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(report)

    return InvestigationReportResponse(
        id=report.id,
        incident_id=report.incident_id,
        title=report.title,
        report_type=report.report_type,
        generated_by=report.generated_by,
        summary=report.summary,
        content=report.content,
        rendered_html=report.rendered_html,
        metadata=report.metadata_info,
        created_at=report.created_at.isoformat(),
    )


@router.get(
    "/{incident_id}/reports",
    response_model=InvestigationReportListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Incident Investigation Reports",
    description="Retrieves summary metadata for all reports generated for the incident, ordered latest first.",
)
@router.get(
    "/{incident_id}/report",
    response_model=InvestigationReportListResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
def list_investigation_reports(
    incident_id: str,
    db: Session = Depends(get_db),
) -> InvestigationReportListResponse:
    """Retrieve all reports generated for the incident."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    reports = db.scalars(
        select(InvestigationReport)
        .where(InvestigationReport.incident_id == incident_id)
        .order_by(InvestigationReport.created_at.desc())
    ).all()

    items = [
        InvestigationReportListItem(
            id=r.id,
            incident_id=r.incident_id,
            title=r.title,
            report_type=r.report_type,
            generated_by=r.generated_by,
            summary=r.summary,
            metadata=r.metadata_info or {},
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in reports
    ]

    return InvestigationReportListResponse(
        incident_id=incident_id,
        total=len(items),
        reports=items,
    )


@router.get(
    "/{incident_id}/reports/{report_id}",
    response_model=InvestigationReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Specific Investigation Report",
    description="Retrieves a complete investigation report including structured content and rendered HTML.",
)
def get_investigation_report(
    incident_id: str,
    report_id: str,
    db: Session = Depends(get_db),
) -> InvestigationReportResponse:
    """Retrieve a specific report by UUID."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    report = db.scalar(
        select(InvestigationReport).where(
            InvestigationReport.id == report_id,
            InvestigationReport.incident_id == incident_id,
        )
    )
    if not report:
        raise NotFoundError(
            message=f"Investigation report with ID '{report_id}' not found for incident '{incident_id}'.",
            details={"report_id": report_id, "incident_id": incident_id},
        )

    return InvestigationReportResponse(
        id=report.id,
        incident_id=report.incident_id,
        title=report.title,
        report_type=report.report_type,
        generated_by=report.generated_by,
        summary=report.summary,
        content=report.content,
        rendered_html=report.rendered_html,
        metadata=report.metadata_info,
        created_at=report.created_at.isoformat() if report.created_at else "",
    )


@router.get(
    "/{incident_id}/reports/{report_id}/export",
    summary="Export Investigation Report",
    description="Exports the report as standalone HTML or JSON with attachment headers for download.",
)
def export_investigation_report(
    incident_id: str,
    report_id: str,
    format: str = Query(default="html", pattern="^(html|json)$"),
    actor: str = Query(default="soc_analyst"),
    db: Session = Depends(get_db),
):
    """Export and download a report in HTML or JSON format."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    report = db.scalar(
        select(InvestigationReport).where(
            InvestigationReport.id == report_id,
            InvestigationReport.incident_id == incident_id,
        )
    )
    if not report:
        raise NotFoundError(
            message=f"Investigation report with ID '{report_id}' not found for incident '{incident_id}'.",
            details={"report_id": report_id, "incident_id": incident_id},
        )

    # Auditing export
    audit = IncidentAuditLog(
        incident_id=incident.id,
        action="REPORT_EXPORTED",
        previous_value=None,
        new_value=report.id,
        notes=f"Report '{report.title}' exported in {format.upper()} format by {actor}.",
        actor=actor,
    )
    db.add(audit)
    db.commit()

    filename_safe_title = "".join(c for c in report.title if c.isalnum() or c in ("-", "_")).rstrip()
    if not filename_safe_title:
        filename_safe_title = f"Report_{report.id[:8]}"

    if format == "json":
        return JSONResponse(
            content=report.to_dict(),
            headers={
                "Content-Disposition": f'attachment; filename="{filename_safe_title}.json"'
            },
        )
    else:
        return HTMLResponse(
            content=report.rendered_html,
            headers={
                "Content-Disposition": f'attachment; filename="{filename_safe_title}.html"'
            },
        )


@router.get(
    "/{incident_id}/report/export",
    summary="Export Latest Incident Investigation Report",
    include_in_schema=False,
)
@router.get(
    "/{incident_id}/reports/export",
    summary="Export Latest Incident Investigation Report",
    include_in_schema=False,
)
def export_latest_investigation_report(
    incident_id: str,
    format: str = Query(default="html", pattern="^(html|json)$"),
    actor: str = Query(default="soc_analyst"),
    db: Session = Depends(get_db),
):
    """Export the most recently generated report for this incident, generating one if needed."""
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        raise NotFoundError(
            message=f"Incident with ID '{incident_id}' not found.",
            details={"incident_id": incident_id},
        )

    report = db.scalar(
        select(InvestigationReport)
        .where(InvestigationReport.incident_id == incident_id)
        .order_by(InvestigationReport.created_at.desc())
    )
    if not report:
        generated = ReportGeneratorService.generate_report(
            db=db,
            incident=incident,
            report_type="investigation_summary",
            generated_by=actor,
        )
        report = InvestigationReport(
            id=str(uuid.uuid4()),
            incident_id=incident.id,
            title=generated["title"],
            report_type="investigation_summary",
            generated_by=actor,
            summary=generated["summary"],
            content=generated["content"],
            rendered_html=generated["rendered_html"],
            metadata_info=generated["metadata_info"],
            created_at=datetime.now(timezone.utc),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

    return export_investigation_report(
        incident_id=incident_id,
        report_id=report.id,
        format=format,
        actor=actor,
        db=db,
    )

