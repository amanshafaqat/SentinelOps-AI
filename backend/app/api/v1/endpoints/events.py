"""Security Event Ingestion, Search, and Analytics Endpoints."""

from datetime import datetime
import json
from typing import Optional, List, Union, Dict, Any
from fastapi import APIRouter, Depends, Query, UploadFile, File, Body, status
from sqlalchemy import select, func, or_, desc
from sqlalchemy.orm import Session

from backend.app.core.errors import NotFoundError, ValidationError
from backend.app.core.logging import logger
from backend.app.db.session import get_db
from backend.app.models.event import SecurityEvent
from backend.app.schemas.event import (
    SecurityEventCreate,
    SecurityEventResponse,
    SecurityEventListItem,
    PaginatedEventsResponse,
    EventImportSummary,
    EventStatsSummary,
)
from backend.app.services.importer import (
    read_and_validate_upload,
    parse_raw_records,
    process_and_persist_events,
)

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.post(
    "/import",
    response_model=EventImportSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Import Security Events from File",
    description="Upload JSON or CSV files containing security telemetry. Validates and normalizes records.",
)
async def import_events_file(
    file: UploadFile = File(..., description="JSON or CSV log file"),
    db: Session = Depends(get_db),
) -> EventImportSummary:
    """Accepts multipart/form-data log file uploads (JSON or CSV)."""
    raw_bytes, extension = await read_and_validate_upload(file)
    records = parse_raw_records(raw_bytes, extension)
    summary = process_and_persist_events(records, db)
    return summary


@router.post(
    "/batch",
    response_model=EventImportSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Batch Ingest JSON Events",
    description="Ingest an array of raw or normalized JSON security log records.",
)
@router.post(
    "/import/json",
    response_model=EventImportSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Import JSON Security Events",
    description="Alias endpoint for batch importing JSON security log records.",
)
async def batch_ingest_events(
    payload: Union[List[dict], Dict[str, Any]] = Body(..., description="Array of event objects or object containing events key"),
    db: Session = Depends(get_db),
) -> EventImportSummary:
    """Accepts JSON array directly or wrapped object with 'events' array in request body."""
    if isinstance(payload, dict):
        events = payload.get("events")
        if events is None:
            raise ValidationError(message="JSON object payload must contain an 'events' list.")
    else:
        events = payload

    if not isinstance(events, list):
        raise ValidationError(message="Payload must be a JSON array of event objects.")
    if len(events) == 0:
        raise ValidationError(message="Event list is empty.")
    if len(events) > 5000:
        raise ValidationError(message="Batch size exceeds maximum limit of 5,000 events.")

    summary = process_and_persist_events(events, db)
    return summary


@router.post(
    "",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Single Security Event",
    description="Ingests a single validated security event.",
)
async def create_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db),
) -> SecurityEventResponse:
    """Create a single security event record."""
    event_model = SecurityEvent(
        timestamp=event_in.timestamp,
        event_type=event_in.event_type,
        source=event_in.source,
        source_ip=event_in.source_ip,
        destination_ip=event_in.destination_ip,
        source_port=event_in.source_port,
        destination_port=event_in.destination_port,
        username=event_in.username,
        user_id=event_in.user_id,
        hostname=event_in.hostname,
        action=event_in.action,
        status=event_in.status,
        severity=event_in.severity,
        message=event_in.message,
        raw_event=event_in.raw_event,
        event_metadata=event_in.metadata,
    )
    db.add(event_model)
    db.commit()
    db.refresh(event_model)
    return SecurityEventResponse(
        id=event_model.id,
        timestamp=event_model.timestamp,
        event_type=event_model.event_type,
        source=event_model.source,
        source_ip=event_model.source_ip,
        destination_ip=event_model.destination_ip,
        source_port=event_model.source_port,
        destination_port=event_model.destination_port,
        username=event_model.username,
        user_id=event_model.user_id,
        hostname=event_model.hostname,
        action=event_model.action,
        status=event_model.status,
        severity=event_model.severity,
        message=event_model.message,
        raw_event=event_model.raw_event,
        metadata=event_model.event_metadata,
        created_at=event_model.created_at,
    )


@router.get(
    "",
    response_model=PaginatedEventsResponse,
    status_code=status.HTTP_200_OK,
    summary="List and Filter Security Events",
    description="Retrieve paginated security events with optional multi-attribute filters.",
)
async def list_events(
    start_time: Optional[datetime] = Query(None, description="Filter events >= start timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events <= end timestamp"),
    event_type: Optional[str] = Query(None, description="Filter by event classification"),
    source: Optional[str] = Query(None, description="Filter by sensor source name"),
    username: Optional[str] = Query(None, description="Filter by subject username"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by outcome status"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    search: Optional[str] = Query(None, description="Free text search across message, user, host, IPs"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page (1-100)"),
    db: Session = Depends(get_db),
) -> PaginatedEventsResponse:
    """Query and filter security events with index acceleration."""
    query = select(SecurityEvent)

    # Apply Filters
    if start_time:
        query = query.where(SecurityEvent.timestamp >= start_time)
    if end_time:
        query = query.where(SecurityEvent.timestamp <= end_time)
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type.strip())
    if source:
        query = query.where(SecurityEvent.source == source.strip())
    if username:
        query = query.where(SecurityEvent.username == username.strip())
    if source_ip:
        query = query.where(SecurityEvent.source_ip == source_ip.strip())
    if destination_ip:
        query = query.where(SecurityEvent.destination_ip == destination_ip.strip())
    if status_filter:
        query = query.where(SecurityEvent.status == status_filter.strip().lower())
    if severity:
        query = query.where(SecurityEvent.severity == severity.strip().lower())

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                SecurityEvent.message.ilike(term),
                SecurityEvent.username.ilike(term),
                SecurityEvent.hostname.ilike(term),
                SecurityEvent.source_ip.ilike(term),
                SecurityEvent.destination_ip.ilike(term),
                SecurityEvent.action.ilike(term),
            )
        )

    # Compute Total Matching Records
    count_subquery = query.with_only_columns(func.count(SecurityEvent.id)).order_by(None)
    total = db.scalar(count_subquery) or 0

    # Paginate and Sort by Timestamp Descending
    offset = (page - 1) * page_size
    query = query.order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.created_at))
    query = query.offset(offset).limit(page_size)

    results = db.scalars(query).all()

    items = [
        SecurityEventListItem(
            id=evt.id,
            timestamp=evt.timestamp,
            event_type=evt.event_type,
            source=evt.source,
            source_ip=evt.source_ip,
            destination_ip=evt.destination_ip,
            username=evt.username,
            hostname=evt.hostname,
            action=evt.action,
            status=evt.status,
            severity=evt.severity,
            message=evt.message,
            created_at=evt.created_at,
        )
        for evt in results
    ]

    total_pages = (total + page_size - 1) // page_size if total > 0 else 0

    return PaginatedEventsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/stats/summary",
    response_model=EventStatsSummary,
    status_code=status.HTTP_200_OK,
    summary="Get Aggregated Event Statistics",
    description="Returns aggregate counts grouped by severity, status, and top sources.",
)
async def get_event_stats(db: Session = Depends(get_db)) -> EventStatsSummary:
    """Aggregates security events distribution for SOC situational awareness."""
    total = db.scalar(select(func.count(SecurityEvent.id))) or 0

    # Group by Severity
    sev_rows = db.execute(
        select(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity)
    ).all()
    by_severity = {row[0]: row[1] for row in sev_rows}

    # Group by Status
    status_rows = db.execute(
        select(SecurityEvent.status, func.count(SecurityEvent.id)).group_by(SecurityEvent.status)
    ).all()
    by_status = {row[0]: row[1] for row in status_rows}

    # Group by Event Type
    type_rows = db.execute(
        select(SecurityEvent.event_type, func.count(SecurityEvent.id)).group_by(SecurityEvent.event_type)
    ).all()
    by_event_type = {row[0]: row[1] for row in type_rows}

    # Top Sources
    source_rows = db.execute(
        select(SecurityEvent.source, func.count(SecurityEvent.id))
        .group_by(SecurityEvent.source)
        .order_by(desc(func.count(SecurityEvent.id)))
        .limit(10)
    ).all()
    top_sources = {row[0]: row[1] for row in source_rows}

    return EventStatsSummary(
        total_events=total,
        by_severity=by_severity,
        by_status=by_status,
        by_event_type=by_event_type,
        top_sources=top_sources,
        recent_activity_count=total,
    )


@router.get(
    "/{event_id}",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Individual Security Event",
    description="Retrieve full details for an individual event including raw payload and metadata.",
)
async def get_event(
    event_id: str,
    db: Session = Depends(get_db),
) -> SecurityEventResponse:
    """Fetch individual event by UUID."""
    event = db.scalar(select(SecurityEvent).where(SecurityEvent.id == event_id))
    if not event:
        raise NotFoundError(
            message=f"Security event with ID '{event_id}' not found.",
            details={"event_id": event_id},
        )

    return SecurityEventResponse(
        id=event.id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        source=event.source,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        username=event.username,
        user_id=event.user_id,
        hostname=event.hostname,
        action=event.action,
        status=event.status,
        severity=event.severity,
        message=event.message,
        raw_event=event.raw_event,
        metadata=event.event_metadata or {},
        created_at=event.created_at,
    )


@router.delete(
    "/{event_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Single Event",
    description="Remove an individual event record (useful for analyst pruning during testing).",
)
async def delete_event(
    event_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Delete an individual event."""
    event = db.scalar(select(SecurityEvent).where(SecurityEvent.id == event_id))
    if not event:
        raise NotFoundError(message=f"Event '{event_id}' not found.")
    db.delete(event)
    db.commit()
    return {"status": "deleted", "id": event_id}
