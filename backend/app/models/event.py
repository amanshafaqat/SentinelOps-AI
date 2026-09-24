"""SecurityEvent SQLAlchemy Model.

Normalized schema representing security telemetry across diverse log sources
(e.g., Linux auth, Windows event logs, Okta/IdP, firewalls, and cloud audit trails).
Optimized with B-tree indexes for fast analytical filtering and future detection rules.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Text,
    Index,
    JSON,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from backend.app.db.base import Base


class SecurityEvent(Base):
    """Normalized security event log record."""

    __tablename__ = "security_events"

    # Primary identifier: UUID v4
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
        doc="Unique UUID identifier for the security event",
    )

    # Core Event Attributes
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="UTC timestamp when the event occurred on the source system",
    )

    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="High-level classification: authentication, authorization, network, process, etc.",
    )

    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Telemetry sensor or log source: linux_auth, windows_event, okta, firewall, aws_cloudtrail",
    )

    # Network Context (IPv4/IPv6 compatible up to 45 chars)
    source_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        index=True,
        doc="Originating IP address",
    )

    destination_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        index=True,
        doc="Target IP address",
    )

    source_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Source TCP/UDP port (1-65535)",
    )

    destination_port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        doc="Destination TCP/UDP port (1-65535)",
    )

    # Identity & Host Context
    username: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        doc="Subject or actor username",
    )

    user_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        doc="Unique user identifier or UID/SID",
    )

    hostname: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=True,
        doc="Device, computer, or server hostname",
    )

    # Operational Action & Status
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
        doc="Specific operation: login, logout, privilege_escalation, query, block, deny",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        doc="Outcome: success, failure, blocked, denied, unknown",
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
        default="info",
        doc="Normalized severity level: info, low, medium, high, critical",
    )

    message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Human-readable summary or log description",
    )

    # Raw Payload & Extended Context (uses JSONB on PostgreSQL, JSON on SQLite)
    raw_event: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        doc="Exact original input payload for auditability and forensic fidelity",
    )

    event_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=True,
        default=dict,
        doc="Additional extracted tags, geo-location, user-agent, or cloud metadata",
    )

    # Ingestion Audit Timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        doc="UTC timestamp when this record was ingested into SentinelOps",
    )

    # Composite indexes for high-frequency detection engine and timeline queries
    __table_args__ = (
        Index("ix_security_events_user_time", "username", "timestamp"),
        Index("ix_security_events_src_ip_time", "source_ip", "timestamp"),
        Index("ix_security_events_type_time", "event_type", "timestamp"),
        Index("ix_security_events_status_time", "status", "timestamp"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize event to dictionary format."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "source": self.source,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "username": self.username,
            "user_id": self.user_id,
            "hostname": self.hostname,
            "action": self.action,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "raw_event": self.raw_event,
            "metadata": self.event_metadata or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
