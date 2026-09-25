"""Correlation package."""

from backend.app.correlation.core import (
    IncidentSeverity,
    IncidentStatus,
    CorrelationSignal,
    CorrelatedCluster,
    calculate_incident_severity,
    build_incident_narrative,
)
from backend.app.correlation.engine import (
    CorrelationEngine,
    CorrelationRunSummary,
    default_correlation_engine,
)

__all__ = [
    "IncidentSeverity",
    "IncidentStatus",
    "CorrelationSignal",
    "CorrelatedCluster",
    "calculate_incident_severity",
    "build_incident_narrative",
    "CorrelationEngine",
    "CorrelationRunSummary",
    "default_correlation_engine",
]
