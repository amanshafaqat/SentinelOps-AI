"""Controlled Status Workflow Engine for SOC Incident Lifecycle.

Enforces valid status transitions, prevents arbitrary state jumps, and ensures
that all transitions are explainable and auditable.
"""

from typing import Dict, Set
from backend.app.core.errors import ValidationError

VALID_STATUSES: Set[str] = {"new", "investigating", "resolved", "closed"}

# Controlled workflow transitions:
# NEW: initial state upon correlation -> can move to INVESTIGATING (triage begun) or CLOSED (immediate false positive / non-actionable)
# INVESTIGATING: active triage -> can move to RESOLVED (mitigation verified) or CLOSED (dismissed / concluded)
# RESOLVED: remediation verified -> can move to CLOSED (archived) or INVESTIGATING (re-opened upon recurrence or follow-up)
# CLOSED: case archived -> can move to INVESTIGATING (re-opened upon new evidence or escalation)
ALLOWED_STATUS_TRANSITIONS: Dict[str, Set[str]] = {
    "new": {"investigating", "closed"},
    "investigating": {"resolved", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},
}


def validate_status_transition(current_status: str, target_status: str) -> None:
    """Validates that a transition from current_status to target_status is permissible.

    Raises:
        ValidationError: If target_status is invalid or the transition is forbidden.
    """
    curr = current_status.strip().lower()
    tgt = target_status.strip().lower()

    if tgt not in VALID_STATUSES:
        raise ValidationError(
            message=f"Invalid status '{target_status}'. Allowed statuses: {sorted(list(VALID_STATUSES))}",
            details={"allowed": sorted(list(VALID_STATUSES)), "provided": target_status},
        )

    # Identical status is a no-op, allowed
    if curr == tgt:
        return

    allowed_targets = ALLOWED_STATUS_TRANSITIONS.get(curr, set())
    if tgt not in allowed_targets:
        allowed_display = [s.upper() for s in sorted(list(allowed_targets))]
        raise ValidationError(
            message=(
                f"Controlled workflow prohibits transition from '{curr.upper()}' directly to '{tgt.upper()}'. "
                f"Allowed transitions from '{curr.upper()}': {allowed_display}"
            ),
            details={
                "current_status": curr,
                "target_status": tgt,
                "allowed_transitions": sorted(list(allowed_targets)),
            },
        )
