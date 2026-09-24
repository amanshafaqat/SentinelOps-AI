"""Detection API Endpoints.

Provides endpoints to execute the deterministic detection engine across ingested security events.
"""

import logging
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.detection.engine import default_detection_engine
from backend.app.schemas.alert import (
    DetectionRunRequest,
    DetectionRunResponse,
)

logger = logging.getLogger("sentinelops")
router = APIRouter()


@router.post(
    "/run",
    response_model=DetectionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Detection Engine",
    description=(
        "Scans stored security events against deterministic detection rules, "
        "generating alerts with evidence links and enforcing deduplication."
    ),
)
def run_detection(
    params: DetectionRunRequest = DetectionRunRequest(),
    db: Session = Depends(get_db),
) -> DetectionRunResponse:
    """Execute detection engine and return execution summary."""
    logger.info(
        f"Triggering detection run (window={params.time_window_minutes}m, "
        f"start={params.start_time}, end={params.end_time}, limit={params.limit})"
    )

    summary = default_detection_engine.run_detection(
        db=db,
        time_window_minutes=params.time_window_minutes,
        start_time=params.start_time,
        end_time=params.end_time,
        limit=params.limit,
    )

    return DetectionRunResponse(
        events_evaluated=summary.events_evaluated,
        rules_executed=summary.rules_executed,
        alerts_generated=summary.alerts_generated,
        alerts_deduplicated=summary.alerts_deduplicated,
        execution_duration_ms=summary.execution_duration_ms,
        generated_alert_ids=summary.generated_alert_ids,
        rule_breakdown=summary.rule_breakdown,
        executed_at=summary.executed_at,
    )
