"""Core Detection Engine Abstractions.

Defines the abstract base class for DetectionRule, execution context (DetectionContext),
structured evaluation results (DetectionResult), and standardized severity definitions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from backend.app.detection.config import DetectionConfig, default_detection_config
from backend.app.models.event import SecurityEvent


class DetectionSeverity(str, Enum):
    """Standardized severity levels for generated security alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class EvidenceReference:
    """Reference binding an alert to a specific supporting SecurityEvent."""
    event_id: str
    evidence_role: str  # e.g., 'trigger', 'preceding_failure', 'successful_login', 'privilege_escalation', 'indicator_match'
    description: Optional[str] = None


@dataclass
class DetectionResult:
    """Candidate alert output produced by an evaluated detection rule."""
    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: DetectionSeverity
    dedup_key: str
    detected_at: datetime
    evidence_items: List[EvidenceReference]
    affected_user: Optional[str] = None
    affected_ip: Optional[str] = None
    affected_hostname: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_alert_dict(self) -> Dict[str, Any]:
        """Convert result to Alert model initialization dict."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": "new",
            "dedup_key": self.dedup_key,
            "affected_user": self.affected_user,
            "affected_ip": self.affected_ip,
            "affected_hostname": self.affected_hostname,
            "detected_at": self.detected_at,
            "alert_metadata": self.metadata,
        }


class DetectionContext:
    """Execution context containing normalized security events and rule configurations."""

    def __init__(
        self,
        events: List[SecurityEvent],
        config: Optional[DetectionConfig] = None,
    ):
        # Store chronologically sorted events
        self.events: List[SecurityEvent] = sorted(
            events,
            key=lambda e: e.timestamp if e.timestamp else datetime.min.replace(tzinfo=timezone.utc),
        )
        self.config: DetectionConfig = config or default_detection_config

    @property
    def total_events(self) -> int:
        return len(self.events)

    def get_events_by_type(self, event_type: str) -> List[SecurityEvent]:
        """Return events matching a specific event classification."""
        return [e for e in self.events if e.event_type.lower() == event_type.lower()]

    def get_events_by_source(self, source: str) -> List[SecurityEvent]:
        """Return events matching a specific telemetry emitter."""
        return [e for e in self.events if e.source.lower() == source.lower()]

    def get_events_by_user(self, username: str) -> List[SecurityEvent]:
        """Return events associated with a specific user principal."""
        if not username:
            return []
        return [
            e for e in self.events
            if e.username and e.username.lower() == username.lower()
        ]

    def get_events_by_ip(self, ip_address: str) -> List[SecurityEvent]:
        """Return events associated with a specific source or destination IP."""
        if not ip_address:
            return []
        return [
            e for e in self.events
            if (e.source_ip == ip_address) or (e.destination_ip == ip_address)
        ]


class DetectionRule(ABC):
    """Abstract Base Class for modular deterministic detection rules.

    Each rule encapsulates its detection logic, deterministic severity
    calculation, and evidence generation.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier (e.g., 'RULE-001')."""
        pass

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable name of the rule."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed security description of the observed pattern."""
        pass

    @property
    @abstractmethod
    def default_severity(self) -> DetectionSeverity:
        """Baseline severity level."""
        pass

    @abstractmethod
    def evaluate(self, context: DetectionContext) -> List[DetectionResult]:
        """Execute deterministic evaluation against provided context.

        Returns a list of DetectionResult objects (empty if no condition met).
        """
        pass
