"""Pydantic Schemas for SecurityEvent.

Provides request validation, normalization data contracts, and response envelopes.
"""

from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_STATUSES = {"success", "failure", "blocked", "denied", "unknown"}


class SecurityEventBase(BaseModel):
    """Base attributes shared by event schemas."""

    timestamp: datetime = Field(
        ...,
        description="Time the event occurred. Timezone-aware UTC is enforced.",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="High-level category (authentication, network, privilege_change, system, etc.)",
    )
    source: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Telemetry sensor or platform name (linux_auth, okta, firewall, etc.)",
    )
    source_ip: Optional[str] = Field(
        None,
        max_length=45,
        description="Originating IPv4 or IPv6 address",
    )
    destination_ip: Optional[str] = Field(
        None,
        max_length=45,
        description="Target IPv4 or IPv6 address",
    )
    source_port: Optional[int] = Field(
        None,
        ge=1,
        le=65535,
        description="Source TCP/UDP port",
    )
    destination_port: Optional[int] = Field(
        None,
        ge=1,
        le=65535,
        description="Destination TCP/UDP port",
    )
    username: Optional[str] = Field(
        None,
        max_length=128,
        description="Subject username or actor account",
    )
    user_id: Optional[str] = Field(
        None,
        max_length=128,
        description="Account identifier or UID/SID",
    )
    hostname: Optional[str] = Field(
        None,
        max_length=128,
        description="Machine hostname or asset identifier",
    )
    action: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Action performed (login, logout, sudo, password_reset, block, etc.)",
    )
    status: str = Field(
        ...,
        description="Outcome of the action (success, failure, blocked, denied, unknown)",
    )
    severity: str = Field(
        default="info",
        description="Normalized severity level: info, low, medium, high, critical",
    )
    message: Optional[str] = Field(
        None,
        max_length=4096,
        description="Human-readable event summary or log message",
    )
    raw_event: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw telemetry payload for forensic traceability",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Extracted enrichment metadata (geo, tags, process, headers)",
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_timezone_aware(cls, v: Any) -> datetime:
        if isinstance(v, str):
            # Parse ISO formats or common datetime strings
            try:
                # Handle trailing Z
                clean_str = v.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(clean_str)
            except ValueError:
                # Try common log formats
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%b %d %H:%M:%S"):
                    try:
                        parsed = datetime.strptime(v, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError(f"Unable to parse timestamp string: {v}")
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        elif isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v
        raise ValueError(f"Invalid timestamp format: {type(v)}")

    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def validate_ip_address(cls, v: Any) -> Optional[str]:
        if not v:
            return None
        v_str = str(v).strip()
        if not v_str:
            return None
        # Clean potential port or brackets like [127.0.0.1]
        v_clean = v_str.strip("[]")
        try:
            # Validate valid IPv4 or IPv6
            ipaddress.ip_address(v_clean)
            return v_clean
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{v_str}'")

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> str:
        if not v:
            return "info"
        v_str = str(v).strip().lower()
        mapping = {
            "informational": "info",
            "debug": "info",
            "notice": "info",
            "warn": "medium",
            "warning": "medium",
            "err": "high",
            "error": "high",
            "fatal": "critical",
            "emergency": "critical",
            "crit": "critical",
            "alert": "high",
        }
        val = mapping.get(v_str, v_str)
        if val not in VALID_SEVERITIES:
            return "info"
        return val

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, v: Any) -> str:
        if not v:
            return "unknown"
        v_str = str(v).strip().lower()
        mapping = {
            "succ": "success",
            "successful": "success",
            "ok": "success",
            "pass": "success",
            "passed": "success",
            "fail": "failure",
            "failed": "failure",
            "error": "failure",
            "deny": "denied",
            "drop": "blocked",
            "rejected": "blocked",
        }
        val = mapping.get(v_str, v_str)
        if val not in VALID_STATUSES:
            return "unknown"
        return val


class SecurityEventCreate(SecurityEventBase):
    """Schema for direct event creation or insertion."""
    pass


class SecurityEventResponse(SecurityEventBase):
    """Schema returned for a single security event."""

    id: str = Field(..., description="Unique event identifier")
    created_at: datetime = Field(..., description="UTC timestamp of event ingestion")

    model_config = {
        "from_attributes": True,
    }


class SecurityEventListItem(BaseModel):
    """Condensed schema for high-density tabular listings."""

    id: str
    timestamp: datetime
    event_type: str
    source: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    action: str
    status: str
    severity: str
    message: Optional[str] = None
    created_at: datetime

    model_config = {
        "from_attributes": True,
    }


class PaginatedEventsResponse(BaseModel):
    """Paginated envelope for security event lists."""

    items: List[SecurityEventListItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class EventImportErrorDetail(BaseModel):
    """Structured detail for an ingestion validation error."""

    record_index: int
    field: Optional[str] = None
    error: str
    raw_sample: Optional[Dict[str, Any]] = None


class EventImportSummary(BaseModel):
    """Structured summary of an event import job."""

    total_records: int
    imported_records: int
    rejected_records: int
    errors: List[EventImportErrorDetail]
    sample_imported_ids: List[str]


class EventStatsSummary(BaseModel):
    """Analytical summary counts for SOC dashboards and Event Explorer."""

    total_events: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_event_type: Dict[str, int]
    top_sources: Dict[str, int]
    recent_activity_count: int
