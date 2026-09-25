"""Incident and IncidentAudit SQLAlchemy Models.

Provides persistent data models for security incidents formed by correlating
deterministic security alerts sharing entities, temporal windows, and attack progressions.
Traceable down to individual Alerts and immutable SecurityEvents.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    String,
    DateTime,
    Text,
    ForeignKey,
    Index,
    JSON,
    Boolean,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.db.base import Base


class Incident(Base):
    """Correlated security incident representing grouped alerts of related activity."""

    __tablename__ = "incidents"

    # Primary identifier: UUID v4
    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
        doc="Unique UUID identifier for the incident",
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        doc="Human-readable title describing the correlated security activity",
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Forensic description explaining the observed incident narrative",
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="medium",
        index=True,
        doc="Calculated potential severity: low, medium, high, critical",
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="new",
        index=True,
        doc="Incident lifecycle state: new, investigating, resolved, closed",
    )

    # Activity Boundaries
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Earliest timestamp among correlated alerts/events",
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Latest timestamp among correlated alerts/events",
    )

    # Entity Aggregations (stored as lists for fast filtering and inspection)
    affected_users: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
        doc="List of distinct user accounts affected in this incident",
    )

    affected_ips: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
        doc="List of distinct source/destination IP addresses observed",
    )

    affected_hostnames: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
        doc="List of distinct affected hosts or cloud resources",
    )

    # Explainable Correlation Metadata
    correlation_reasons: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
        doc="Deterministic reasons explaining why alerts were correlated into this incident",
    )

    correlation_metadata: Mapped[Dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=dict,
        doc="Supplemental correlation parameters, window data, and entity graph metrics",
    )

    # Lifecycle Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        doc="UTC timestamp when the incident was created",
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
        doc="UTC timestamp when the incident was last modified or appended",
    )

    # Relationships
    alerts: Mapped[List["backend.app.models.alert.Alert"]] = relationship(
        "backend.app.models.alert.Alert",
        back_populates="incident",
        order_by="backend.app.models.alert.Alert.detected_at",
    )

    audit_logs: Mapped[List["IncidentAuditLog"]] = relationship(
        "IncidentAuditLog",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentAuditLog.created_at.desc()",
    )

    ai_analyses: Mapped[List["IncidentAIAnalysis"]] = relationship(
        "IncidentAIAnalysis",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentAIAnalysis.created_at.desc()",
    )

    __table_args__ = (
        Index("ix_incidents_severity_status", "severity", "status"),
    )

    def to_dict(self, include_alerts: bool = False) -> Dict[str, Any]:
        """Serialize incident to dictionary."""
        data: Dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "affected_users": self.affected_users or [],
            "affected_ips": self.affected_ips or [],
            "affected_hostnames": self.affected_hostnames or [],
            "correlation_reasons": self.correlation_reasons or [],
            "correlation_metadata": self.correlation_metadata or {},
            "alert_count": len(self.alerts) if self.alerts else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_alerts and self.alerts:
            data["alerts"] = [a.to_dict(include_evidence=True) for a in self.alerts]
        return data


class IncidentAuditLog(Base):
    """Immutable audit trail for status changes, severity updates, and analyst notes."""

    __tablename__ = "incident_audit_logs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Action type: status_change, severity_change, correlation_created, alert_added, analyst_note",
    )

    previous_value: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    new_value: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Analyst rationale or notes",
    )

    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="system",
        doc="User email/ID or system service responsible for change",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="audit_logs")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "action": self.action,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "notes": self.notes,
            "actor": self.actor,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IncidentAIAnalysis(Base):
    """Audit record and persistent store for AI Copilot incident analyses and analyst Q&A."""

    __tablename__ = "incident_ai_analyses"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    analysis_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="Type: incident_summary, analyst_query",
    )

    query: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        doc="Analyst question or query (if analyst_query type)",
    )

    model: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        doc="Model identifier used, e.g. gemini-3.8-flash",
    )

    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Executive summary or direct answer",
    )

    observed_facts: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
    )

    potential_explanations: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
    )

    evidence_references: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
    )

    missing_information: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
    )

    recommended_next_steps: Mapped[List[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        default=list,
    )

    uncertainty_assessment: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )

    evidence_truncated: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="soc_analyst",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="ai_analyses")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "analysis_type": self.analysis_type,
            "query": self.query,
            "model": self.model,
            "summary": self.summary,
            "observed_facts": self.observed_facts or [],
            "potential_explanations": self.potential_explanations or [],
            "evidence_references": self.evidence_references or [],
            "missing_information": self.missing_information or [],
            "recommended_next_steps": self.recommended_next_steps or [],
            "uncertainty_assessment": self.uncertainty_assessment or "",
            "evidence_truncated": self.evidence_truncated,
            "actor": self.actor,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

