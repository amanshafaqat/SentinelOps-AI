"""RULE 002: Successful Login After Repeated Failures.

Detects a successful authentication event preceded by a configurable sequence of
failed attempts for the same username or source IP within a lookback window.
"""

import hashlib
from datetime import timedelta
from typing import List
from backend.app.detection.core import (
    DetectionContext,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    EvidenceReference,
)


class RuleLoginAfterFailures(DetectionRule):
    """Detects successful authentication occurring after prior failed attempts."""

    @property
    def rule_id(self) -> str:
        return "RULE-002"

    @property
    def rule_name(self) -> str:
        return "Successful Authentication After Repeated Failures"

    @property
    def description(self) -> str:
        return (
            "Detects a successful login that occurs immediately after multiple failed "
            "authentication attempts within a lookback window, which may indicate password guessing or compromise."
        )

    @property
    def default_severity(self) -> DetectionSeverity:
        return DetectionSeverity.HIGH

    def evaluate(self, context: DetectionContext) -> List[DetectionResult]:
        threshold = context.config.login_after_failures_threshold
        lookback_delta = timedelta(minutes=context.config.login_after_failures_window_minutes)

        auth_events = [
            e for e in context.events
            if e.event_type.lower() == "authentication"
        ]

        if not auth_events:
            return []

        # Find all successful logins
        success_events = [
            e for e in auth_events
            if e.status.lower() in ("success", "successful", "accepted")
        ]

        # Find all failed logins
        failed_events = [
            e for e in auth_events
            if e.status.lower() in ("failure", "failed", "denied", "blocked")
        ]

        results: List[DetectionResult] = []

        for success in success_events:
            success_time = success.timestamp
            success_user = (success.username or "").strip().lower()
            success_ip = (success.source_ip or "").strip()

            if not success_user and not success_ip:
                continue

            # Look for failed attempts in the window [success_time - lookback_delta, success_time)
            preceding_failures = [
                f for f in failed_events
                if (success_time - lookback_delta) <= f.timestamp < success_time
                and (
                    (success_user and f.username and f.username.strip().lower() == success_user)
                    or (success_ip and f.source_ip and f.source_ip.strip() == success_ip)
                )
            ]

            if len(preceding_failures) >= threshold:
                sorted_failures = sorted(preceding_failures, key=lambda f: f.timestamp)
                failure_count = len(sorted_failures)

                # Deterministic deduplication key tied to the successful event ID + trigger count
                fail_ids = ",".join(sorted([f.id for f in sorted_failures]))
                raw_sig = f"RULE-002:{success.id}:{success_user}:{success_ip}:{fail_ids}"
                dedup_key = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

                entity_label = f"account '{success.username or success_user}'"
                if success.source_ip:
                    entity_label += f" from source IP {success.source_ip}"

                title = f"Successful Login Following {failure_count} Failures: {entity_label}"
                description = (
                    f"A successful login for {entity_label} occurred at {success_time.isoformat()} "
                    f"after {failure_count} preceding failed login attempts within "
                    f"{context.config.login_after_failures_window_minutes} minutes. "
                    f"Earliest failure was at {sorted_failures[0].timestamp.isoformat()}."
                )

                evidence_items: List[EvidenceReference] = [
                    EvidenceReference(
                        event_id=f.id,
                        evidence_role="preceding_failure",
                        description=(
                            f"Preceding failed attempt for '{f.username or 'unknown'}' from "
                            f"{f.source_ip or 'unknown'} at {f.timestamp.isoformat()}"
                        ),
                    )
                    for f in sorted_failures
                ]

                # Append the pivotal successful login as trigger evidence
                evidence_items.append(
                    EvidenceReference(
                        event_id=success.id,
                        evidence_role="successful_login",
                        description=(
                            f"Target successful login for '{success.username or 'unknown'}' from "
                            f"{success.source_ip or 'unknown'} on host '{success.hostname or 'unknown'}'"
                        ),
                    )
                )

                results.append(
                    DetectionResult(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        title=title,
                        description=description,
                        severity=self.default_severity,
                        dedup_key=dedup_key,
                        detected_at=success_time,
                        evidence_items=evidence_items,
                        affected_user=success.username,
                        affected_ip=success.source_ip,
                        affected_hostname=success.hostname,
                        metadata={
                            "preceding_failure_count": failure_count,
                            "threshold": threshold,
                            "lookback_window_minutes": context.config.login_after_failures_window_minutes,
                            "successful_login_event_id": success.id,
                            "first_failure_timestamp": sorted_failures[0].timestamp.isoformat(),
                            "success_timestamp": success_time.isoformat(),
                        },
                    )
                )

        return results
