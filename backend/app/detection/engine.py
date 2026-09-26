"""Detection Engine Orchestrator.

Manages detection rule execution, execution context creation, deterministic deduplication,
and atomic persistence of generated Alert and AlertEvidence records into PostgreSQL.
"""

import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Sequence, Set
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app.detection.config import DetectionConfig, default_detection_config
from backend.app.detection.core import (
    DetectionContext,
    DetectionResult,
    DetectionRule,
)
from backend.app.detection.rules import DEFAULT_RULES
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent

logger = logging.getLogger("sentinelops")


class DetectionRunSummary:
    """Structured summary returned after a detection run."""

    def __init__(
        self,
        events_evaluated: int,
        rules_executed: int,
        alerts_generated: int,
        alerts_deduplicated: int,
        execution_duration_ms: float,
        generated_alert_ids: List[str],
        rule_breakdown: Optional[Dict[str, int]] = None,
    ):
        self.events_evaluated = events_evaluated
        self.rules_executed = rules_executed
        self.alerts_generated = alerts_generated
        self.alerts_deduplicated = alerts_deduplicated
        self.execution_duration_ms = round(execution_duration_ms, 2)
        self.generated_alert_ids = generated_alert_ids
        self.rule_breakdown = rule_breakdown or {}
        self.executed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events_evaluated": self.events_evaluated,
            "rules_executed": self.rules_executed,
            "alerts_generated": self.alerts_generated,
            "alerts_deduplicated": self.alerts_deduplicated,
            "execution_duration_ms": self.execution_duration_ms,
            "generated_alert_ids": self.generated_alert_ids,
            "rule_breakdown": self.rule_breakdown,
            "executed_at": self.executed_at,
        }


class DetectionEngine:
    """Orchestrates detection rules against security event telemetry."""

    def __init__(
        self,
        rules: Optional[Sequence[DetectionRule]] = None,
        config: Optional[DetectionConfig] = None,
    ):
        self.rules: List[DetectionRule] = list(rules) if rules is not None else list(DEFAULT_RULES)
        self.config: DetectionConfig = config or default_detection_config

    def register_rule(self, rule: DetectionRule) -> None:
        """Register an additional detection rule."""
        self.rules.append(rule)

    def run_detection(
        self,
        db: Session,
        events: Optional[List[SecurityEvent]] = None,
        time_window_minutes: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> DetectionRunSummary:
        """Execute detection rules against security events with deduplication and persistence.

        Args:
            db: Active SQLAlchemy database session
            events: Optional pre-loaded event list. If None, queries DB based on filters.
            time_window_minutes: Optional window for scoping query to recent events.
            start_time: Optional lower bound timestamp filter.
            end_time: Optional upper bound timestamp filter.
            limit: Maximum events to load from DB for this detection sweep.
        """
        start_mono = time.monotonic()

        # 1. Fetch events from database if not provided
        if events is None:
            query = select(SecurityEvent).order_by(SecurityEvent.timestamp.asc())

            if start_time:
                query = query.where(SecurityEvent.timestamp >= start_time)
            elif time_window_minutes:
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
                query = query.where(SecurityEvent.timestamp >= cutoff)

            if end_time:
                query = query.where(SecurityEvent.timestamp <= end_time)

            query = query.limit(limit)
            events = list(db.scalars(query).all())

        events_evaluated = len(events)
        if events_evaluated == 0:
            duration_ms = (time.monotonic() - start_mono) * 1000
            return DetectionRunSummary(
                events_evaluated=0,
                rules_executed=len(self.rules),
                alerts_generated=0,
                alerts_deduplicated=0,
                execution_duration_ms=duration_ms,
                generated_alert_ids=[],
            )

        # 2. Build execution context
        context = DetectionContext(events=events, config=self.config)

        # 3. Evaluate each rule deterministically
        raw_candidates: List[DetectionResult] = []
        rule_breakdown: Dict[str, int] = {}

        for rule in self.rules:
            try:
                results = rule.evaluate(context)
                raw_candidates.extend(results)
                rule_breakdown[rule.rule_id] = len(results)
            except Exception as exc:
                logger.error(f"Error evaluating rule {rule.rule_id}: {exc}", exc_info=True)

        if not raw_candidates:
            duration_ms = (time.monotonic() - start_mono) * 1000
            return DetectionRunSummary(
                events_evaluated=events_evaluated,
                rules_executed=len(self.rules),
                alerts_generated=0,
                alerts_deduplicated=0,
                execution_duration_ms=duration_ms,
                generated_alert_ids=[],
                rule_breakdown=rule_breakdown,
            )

        # 4. Deterministic Deduplication Check
        # Check both the database and intra-run candidate duplicates
        candidate_dedup_keys = [c.dedup_key for c in raw_candidates]

        # Query existing alerts matching candidate dedup keys
        existing_alerts_stmt = select(Alert.dedup_key).where(Alert.dedup_key.in_(candidate_dedup_keys))
        existing_keys: Set[str] = set(db.scalars(existing_alerts_stmt).all())

        seen_keys_in_run: Set[str] = set()
        alerts_to_persist: List[Alert] = []
        alerts_deduplicated = 0

        for candidate in raw_candidates:
            if candidate.dedup_key in existing_keys or candidate.dedup_key in seen_keys_in_run:
                alerts_deduplicated += 1
                continue

            seen_keys_in_run.add(candidate.dedup_key)

            # Construct new Alert model instance
            alert = Alert(
                rule_id=candidate.rule_id,
                rule_name=candidate.rule_name,
                title=candidate.title,
                description=candidate.description,
                severity=candidate.severity.value,
                status="new",
                dedup_key=candidate.dedup_key,
                affected_user=candidate.affected_user,
                affected_ip=candidate.affected_ip,
                affected_hostname=candidate.affected_hostname,
                detected_at=candidate.detected_at,
                alert_metadata=candidate.metadata,
            )

            # Construct immutable AlertEvidence associations
            for item in candidate.evidence_items:
                evidence = AlertEvidence(
                    alert=alert,
                    event_id=item.event_id,
                    evidence_role=item.evidence_role,
                    description=item.description,
                )
                alert.evidence.append(evidence)

            alerts_to_persist.append(alert)

        # 5. Persist to Database atomically
        generated_alert_ids: List[str] = []
        if alerts_to_persist:
            db.add_all(alerts_to_persist)
            db.commit()
            for a in alerts_to_persist:
                db.refresh(a)
                generated_alert_ids.append(a.id)

            logger.info(
                f"Detection run generated {len(alerts_to_persist)} alerts "
                f"({alerts_deduplicated} deduplicated) from {events_evaluated} events."
            )

        duration_ms = (time.monotonic() - start_mono) * 1000

        return DetectionRunSummary(
            events_evaluated=events_evaluated,
            rules_executed=len(self.rules),
            alerts_generated=len(alerts_to_persist),
            alerts_deduplicated=alerts_deduplicated,
            execution_duration_ms=duration_ms,
            generated_alert_ids=generated_alert_ids,
            rule_breakdown=rule_breakdown,
        )


# Singleton engine instance with default rules
default_detection_engine = DetectionEngine()
