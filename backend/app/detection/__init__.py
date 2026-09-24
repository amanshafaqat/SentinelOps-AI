"""Detection engine package."""

from backend.app.detection.config import DetectionConfig, default_detection_config
from backend.app.detection.core import (
    DetectionContext,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    EvidenceReference,
)
from backend.app.detection.engine import (
    DetectionEngine,
    DetectionRunSummary,
    default_detection_engine,
)
from backend.app.detection.rules import DEFAULT_RULES

__all__ = [
    "DetectionConfig",
    "default_detection_config",
    "DetectionContext",
    "DetectionResult",
    "DetectionRule",
    "DetectionSeverity",
    "EvidenceReference",
    "DetectionEngine",
    "DetectionRunSummary",
    "default_detection_engine",
    "DEFAULT_RULES",
]
