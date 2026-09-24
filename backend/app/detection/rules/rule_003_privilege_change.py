"""RULE 003: Suspicious Privilege Change.

Detects privilege escalation, administrative group modifications, or sensitive
role reassignments based on normalized security events.
Describes observed telemetry objectively without assuming compromise certainty.
"""

import hashlib
from typing import List
from backend.app.detection.core import (
    DetectionContext,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    EvidenceReference,
)


class RuleSuspiciousPrivilegeChange(DetectionRule):
    """Detects account role elevations and sensitive privilege changes."""

    @property
    def rule_id(self) -> str:
        return "RULE-003"

    @property
    def rule_name(self) -> str:
        return "Suspicious Privilege or Role Modification"

    @property
    def description(self) -> str:
        return (
            "Detects administrative group membership modifications, privileged role assignments, "
            "or direct root/sudo elevation commands. Observed behavior is highlighted for SOC review."
        )

    @property
    def default_severity(self) -> DetectionSeverity:
        return DetectionSeverity.HIGH

    def evaluate(self, context: DetectionContext) -> List[DetectionResult]:
        sensitive_roles = [r.lower() for r in context.config.privilege_sensitive_roles]
        sensitive_actions = [a.lower() for a in context.config.privilege_sensitive_actions]

        results: List[DetectionResult] = []

        for event in context.events:
            action_lower = (event.action or "").lower()
            event_type_lower = (event.event_type or "").lower()
            message_lower = (event.message or "").lower()
            meta_str = str(event.event_metadata or {}).lower()

            is_priv_type = event_type_lower in ("privilege_change", "authorization", "user_management")
            is_sensitive_action = any(sa in action_lower for sa in sensitive_actions)
            mentions_priv_role = any(sr in message_lower or sr in meta_str for sr in sensitive_roles)

            if is_priv_type or is_sensitive_action or mentions_priv_role:
                # Match detected!
                user = event.username or "unspecified_user"
                host = event.hostname or "unspecified_host"

                # Check if it targeted high-impact domain/root credentials
                high_impact_keywords = ["domain admins", "enterprise admins", "root", "wheel", "/bin/bash", "/bin/sh"]
                is_high_impact = any(k in message_lower or k in meta_str for k in high_impact_keywords)

                if is_high_impact and event.status.lower() in ("success", "successful"):
                    severity = DetectionSeverity.CRITICAL
                elif event.status.lower() in ("success", "successful"):
                    severity = DetectionSeverity.HIGH
                else:
                    severity = DetectionSeverity.MEDIUM

                title = f"Privilege Modification: {event.action} on {host} (User: {user})"
                description = (
                    f"Observed privilege elevation or role modification event '{event.action}' "
                    f"associated with account '{user}' on host '{host}'. "
                    f"Status: {event.status}. Message: {event.message or 'No message provided'}. "
                    f"Action reflects elevation or assignment into sensitive access boundaries."
                )

                raw_sig = f"RULE-003:{event.id}:{user}:{event.action}:{event.timestamp.isoformat()}"
                dedup_key = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

                evidence_items = [
                    EvidenceReference(
                        event_id=event.id,
                        evidence_role="privilege_escalation",
                        description=(
                            f"Privilege modification event '{event.action}' by/for '{user}' "
                            f"on {host} with status '{event.status}'"
                        ),
                    )
                ]

                results.append(
                    DetectionResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        title=title,
                        description=description,
                        severity=severity,
                        dedup_key=dedup_key,
                        detected_at=event.timestamp,
                        evidence_items=evidence_items,
                        affected_user=event.username,
                        affected_ip=event.source_ip,
                        affected_hostname=event.hostname,
                        metadata={
                            "action": event.action,
                            "status": event.status,
                            "high_impact": is_high_impact,
                            "log_source": event.source,
                            "message": event.message,
                        },
                    )
                )

        return results
