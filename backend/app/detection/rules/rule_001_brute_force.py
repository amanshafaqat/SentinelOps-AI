"""RULE 001: Brute Force Login Attempt.

Detects repeated failed authentication attempts associated with the same account
and/or source IP within a configurable sliding time window.
"""

import hashlib
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Tuple
from backend.app.detection.core import (
    DetectionContext,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    EvidenceReference,
)
from backend.app.models.event import SecurityEvent


class RuleBruteForceLogin(DetectionRule):
    """Detects repeated failed logins targeting an account or originating from a source IP."""

    @property
    def rule_id(self) -> str:
        return "RULE-001"

    @property
    def rule_name(self) -> str:
        return "Brute Force Authentication Attempt"

    @property
    def description(self) -> str:
        return (
            "Detects repeated failed authentication attempts associated with the "
            "same account or source IP exceeding the threshold within an observation window."
        )

    @property
    def default_severity(self) -> DetectionSeverity:
        return DetectionSeverity.MEDIUM

    def evaluate(self, context: DetectionContext) -> List[DetectionResult]:
        threshold = context.config.brute_force_failed_threshold
        window_delta = timedelta(minutes=context.config.brute_force_window_minutes)

        # Filter strictly for failed authentication events
        failed_auth_events = [
            e for e in context.events
            if e.event_type.lower() == "authentication"
            and e.status.lower() in ("failure", "failed", "denied", "blocked")
        ]

        if not failed_auth_events:
            return []

        # Group by entity key: prefer (username, source_ip); fallback to username or source_ip
        entity_groups: Dict[Tuple[str, str], List[SecurityEvent]] = defaultdict(list)
        for event in failed_auth_events:
            user = event.username.strip().lower() if event.username else ""
            ip = event.source_ip.strip() if event.source_ip else ""
            if not user and not ip:
                continue
            entity_groups[(user, ip)].append(event)

        results: List[DetectionResult] = []

        for (user, ip), events in entity_groups.items():
            # Chronologically sort events for sliding window
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            n = len(sorted_events)
            if n < threshold:
                continue

            # Sliding window algorithm to detect clusters
            i = 0
            while i < n:
                window_events = [sorted_events[i]]
                start_time = sorted_events[i].timestamp

                j = i + 1
                while j < n and (sorted_events[j].timestamp - start_time) <= window_delta:
                    window_events.append(sorted_events[j])
                    j += 1

                if len(window_events) >= threshold:
                    # Gather all supporting events for this cluster
                    cluster_event_ids = sorted([e.id for e in window_events])
                    primary_event = window_events[-1]

                    # Deterministic hash for deduplication
                    raw_sig = f"RULE-001:{user}:{ip}:" + ",".join(cluster_event_ids)
                    dedup_key = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

                    # Dynamic severity scaling: HIGH if >= 2x threshold
                    failure_count = len(window_events)
                    severity = (
                        DetectionSeverity.HIGH
                        if failure_count >= (threshold * 2)
                        else DetectionSeverity.MEDIUM
                    )

                    entity_label = f"account '{user}'" if user else f"source IP {ip}"
                    if user and ip:
                        entity_label = f"account '{user}' from source IP {ip}"

                    title = f"Brute Force Detected: {failure_count} Failed Logins for {entity_label}"
                    description = (
                        f"Detected {failure_count} consecutive failed authentication attempts "
                        f"for {entity_label} within {context.config.brute_force_window_minutes} minutes. "
                        f"First failure at {window_events[0].timestamp.isoformat()}, "
                        f"latest at {primary_event.timestamp.isoformat()}."
                    )

                    evidence_items = [
                        EvidenceReference(
                            event_id=ev.id,
                            evidence_role="failed_attempt",
                            description=(
                                f"Failed login for '{ev.username or 'unknown'}' from "
                                f"{ev.source_ip or 'unknown'} via {ev.source} at {ev.timestamp.isoformat()}"
                            ),
                        )
                        for ev in window_events
                    ]

                    results.append(
                        DetectionResult(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            title=title,
                            description=description,
                            severity=severity,
                            dedup_key=dedup_key,
                            detected_at=primary_event.timestamp,
                            evidence_items=evidence_items,
                            affected_user=primary_event.username,
                            affected_ip=primary_event.source_ip,
                            affected_hostname=primary_event.hostname,
                            metadata={
                                "failed_count": failure_count,
                                "threshold": threshold,
                                "window_minutes": context.config.brute_force_window_minutes,
                                "first_failure_time": window_events[0].timestamp.isoformat(),
                                "last_failure_time": primary_event.timestamp.isoformat(),
                            },
                        )
                    )
                    # Advance i past this cluster
                    i = j
                else:
                    i += 1

        return results
