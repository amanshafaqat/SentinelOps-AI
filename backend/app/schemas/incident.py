"""Pydantic schemas for Incident Correlation, Investigation, and Audit Logging."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.alert import AlertResponse


class IncidentAuditLogResponse(BaseModel):
    """Immutable audit record for an incident update."""
    id: str = Field(description="Unique audit log ID")
    incident_id: str = Field(description="Associated incident ID")
    action: str = Field(description="Action: status_change, severity_change, correlation_created, alert_added, analyst_note")
    previous_value: Optional[str] = Field(default=None, description="Previous value before change")
    new_value: Optional[str] = Field(default=None, description="New value after change")
    notes: Optional[str] = Field(default=None, description="Analyst rationale or notes")
    actor: str = Field(default="system", description="User or system service that made the change")
    created_at: str = Field(description="UTC timestamp of the action")

    class Config:
        from_attributes = True


class IncidentListItem(BaseModel):
    """Summary item for SOC incident queues."""
    id: str = Field(description="Unique incident UUID")
    title: str = Field(description="Correlated activity title")
    description: str = Field(description="Forensic narrative")
    severity: str = Field(description="Severity: low, medium, high, critical")
    status: str = Field(description="Status: new, investigating, resolved, closed")
    first_seen: str = Field(description="Earliest timestamp among alerts")
    last_seen: str = Field(description="Latest timestamp among alerts")
    affected_users: List[str] = Field(default_factory=list, description="Targeted user accounts")
    affected_ips: List[str] = Field(default_factory=list, description="Associated IP addresses")
    affected_hostnames: List[str] = Field(default_factory=list, description="Associated hosts")
    alert_count: int = Field(default=0, description="Total correlated alerts")
    correlation_reasons: List[str] = Field(default_factory=list, description="Explainable grouping signals")
    created_at: str = Field(description="Incident creation timestamp")
    updated_at: str = Field(description="Last update timestamp")

    class Config:
        from_attributes = True


class IncidentDetailResponse(IncidentListItem):
    """Comprehensive incident view with full alert links, evidence, and audit logs."""
    correlation_metadata: Dict[str, Any] = Field(default_factory=dict, description="Correlation window and entity metrics")
    alerts: List[AlertResponse] = Field(default_factory=list, description="Correlated security alerts")
    audit_logs: List[IncidentAuditLogResponse] = Field(default_factory=list, description="Audit history trail")


class PaginatedIncidentsResponse(BaseModel):
    """Paginated incident list response."""
    incidents: List[IncidentListItem]
    total: int = Field(description="Total matching incidents")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total pages")


class IncidentStatusUpdate(BaseModel):
    """Payload for updating incident status and analyst notes."""
    status: Optional[str] = Field(
        default=None,
        description="New status: new, investigating, resolved, closed",
        pattern="^(new|investigating|resolved|closed|NEW|INVESTIGATING|RESOLVED|CLOSED)$",
    )
    severity: Optional[str] = Field(
        default=None,
        description="Override severity: low, medium, high, critical",
        pattern="^(low|medium|high|critical|LOW|MEDIUM|HIGH|CRITICAL)$",
    )
    title: Optional[str] = Field(default=None, max_length=255, description="Updated title")
    description: Optional[str] = Field(default=None, description="Updated description")
    notes: Optional[str] = Field(default=None, description="Analyst rationale or notes for audit trail")
    actor: Optional[str] = Field(default="analyst", description="Analyst username or service identifier")


class CorrelateRequest(BaseModel):
    """Parameters to trigger deterministic correlation engine."""
    time_window_minutes: int = Field(
        default=60,
        ge=5,
        le=1440,
        description="Sliding correlation window in minutes (5 to 1440)",
    )
    min_severity: Optional[str] = Field(
        default=None,
        description="Minimum alert severity to consider (low, medium, high, critical)",
    )
    force_recorrelate: bool = Field(
        default=False,
        description="If True, re-evaluates all alerts and rebuilds incidents from scratch",
    )


class CorrelateResponse(BaseModel):
    """Summary of correlation engine execution."""
    alerts_evaluated: int = Field(description="Total candidate alerts inspected")
    alerts_correlated: int = Field(description="Alerts associated with an incident")
    incidents_created: int = Field(description="New incidents created")
    incidents_updated: int = Field(description="Existing incidents expanded")
    execution_duration_ms: float = Field(description="Correlation engine runtime in milliseconds")
    created_incident_ids: List[str] = Field(default_factory=list, description="IDs of newly created incidents")
    correlation_window_minutes: int = Field(description="Window size used in minutes")
    executed_at: str = Field(description="UTC timestamp of execution")


class IncidentTimelineItem(BaseModel):
    """Unified chronological item in an incident investigation timeline."""
    id: str = Field(description="Entity identifier")
    item_type: str = Field(description="Type: event, alert, incident_action")
    timestamp: str = Field(description="UTC timestamp of the occurrence")
    title: str = Field(description="Headline / summary")
    description: Optional[str] = Field(default=None, description="Detailed narrative")
    severity: Optional[str] = Field(default=None, description="Severity if applicable")
    status: Optional[str] = Field(default=None, description="Status if applicable")
    entity: Optional[str] = Field(default=None, description="Primary user, IP, or host involved")
    source: Optional[str] = Field(default=None, description="Originating rule, sensor, or user")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Raw attributes or properties")


class IncidentTimelineResponse(BaseModel):
    """Chronologically sorted timeline of events, alerts, and incident actions."""
    incident_id: str
    total_items: int
    items: List[IncidentTimelineItem]


class IncidentStatsResponse(BaseModel):
    """High-level metrics for SOC analyst situational awareness."""
    total_incidents: int
    open_incidents: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    average_alerts_per_incident: float
