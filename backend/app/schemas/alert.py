"""Pydantic schemas for Alerts, Evidence, and Detection Engine API."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from backend.app.schemas.event import SecurityEventResponse


class AlertEvidenceResponse(BaseModel):
    """Evidence link connecting an Alert to a supporting SecurityEvent."""
    id: str = Field(description="Evidence record ID")
    alert_id: str = Field(description="Parent Alert ID")
    event_id: str = Field(description="Referenced SecurityEvent ID")
    evidence_role: str = Field(description="Functional role of this evidence in the detection")
    description: Optional[str] = Field(default=None, description="Contextual explanation")
    created_at: str = Field(description="Timestamp when evidence association was recorded")
    event: Optional[SecurityEventResponse] = Field(default=None, description="Full security event payload")

    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    """Summary representation for alert queues and lists."""
    id: str = Field(description="Unique alert UUID")
    rule_id: str = Field(description="Rule identifier (e.g. RULE-001)")
    rule_name: str = Field(description="Rule title")
    title: str = Field(description="Brief alert title")
    description: str = Field(description="Detailed alert narrative")
    severity: str = Field(description="Severity: low, medium, high, critical")
    status: str = Field(description="Status: new, in_review, dismissed, escalated")
    dedup_key: str = Field(description="Deterministic deduplication key")
    affected_user: Optional[str] = Field(default=None, description="Affected user account")
    affected_ip: Optional[str] = Field(default=None, description="Affected source or destination IP")
    affected_hostname: Optional[str] = Field(default=None, description="Affected host or container")
    detected_at: str = Field(description="Timestamp when malicious activity occurred")
    created_at: str = Field(description="Timestamp when alert was generated")
    incident_id: Optional[str] = Field(default=None, description="Linked incident ID")
    evidence_count: int = Field(default=0, description="Total evidence events supporting this alert")

    class Config:
        from_attributes = True


class AlertDetailResponse(AlertResponse):
    """Comprehensive alert view including supporting evidence events and metadata."""
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Rule-specific metrics and parameters")
    evidence: List[AlertEvidenceResponse] = Field(default_factory=list, description="Supporting evidence events")


class PaginatedAlertsResponse(BaseModel):
    """Paginated list of alerts for SOC queue."""
    alerts: List[AlertResponse]
    total: int = Field(description="Total matching alerts")
    page: int = Field(description="Current page number (1-indexed)")
    page_size: int = Field(description="Items per page")
    total_pages: int = Field(description="Total calculated pages")


class AlertStatusUpdate(BaseModel):
    """Payload to update an alert's triage status."""
    status: str = Field(
        description="New status: new, in_review, dismissed, escalated",
        pattern="^(new|in_review|dismissed|escalated)$",
    )


class DetectionRunRequest(BaseModel):
    """Parameters to trigger deterministic detection execution."""
    time_window_minutes: Optional[int] = Field(
        default=None,
        description="Look back window in minutes (e.g. 60). Evaluates all events if not specified.",
        ge=1,
    )
    start_time: Optional[datetime] = Field(
        default=None,
        description="Optional UTC start timestamp filter",
    )
    end_time: Optional[datetime] = Field(
        default=None,
        description="Optional UTC end timestamp filter",
    )
    limit: int = Field(
        default=1000,
        description="Maximum events to evaluate in this detection pass",
        ge=1,
        le=10000,
    )


class DetectionRunResponse(BaseModel):
    """Execution summary returned after running detection rules."""
    events_evaluated: int = Field(description="Count of security events scanned")
    rules_executed: int = Field(description="Count of detection rules executed")
    alerts_generated: int = Field(description="Count of new alerts created and persisted")
    alerts_deduplicated: int = Field(description="Count of duplicate alert candidates suppressed")
    execution_duration_ms: float = Field(description="Execution runtime in milliseconds")
    generated_alert_ids: List[str] = Field(description="IDs of newly generated alerts")
    rule_breakdown: Dict[str, int] = Field(description="Candidate alerts detected per rule")
    executed_at: str = Field(description="UTC timestamp of detection execution")


class AlertStatsResponse(BaseModel):
    """Aggregated statistics for security alerts."""
    total_alerts: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_rule: Dict[str, int]
