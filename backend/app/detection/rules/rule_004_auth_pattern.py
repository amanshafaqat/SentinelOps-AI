"""RULE 004: Suspicious Authentication Pattern.

Detects anomalous multi-source authentication patterns where the same user account
is accessed from multiple distinct source IPs within a configurable observation window.
Grounded strictly in observable telemetry without fabricating geographic intelligence.
"""

import hashlib
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Set
from backend.app.detection.core import (
    DetectionContext,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    EvidenceReference,
)
from backend.app.models.event import SecurityEvent


class RuleSuspiciousAuthPattern(DetectionRule):
    """Detects multi-IP authentication attempts targeting the same user within a short window."""

    @property
    def rule_id(self) -> str:
        return "RULE-004"

    @property
    def rule_name(self) -> str:
        return "Unusual Multi-Source Authentication Pattern"

    @property
    def description(self) -> str:
        return (
            "Detects when a single user account is accessed from multiple distinct source IPs "
            "within a short observation window, which may indicate concurrent session hijacking or distributed credential abuse."
        )

    @property
    def default_severity(self) -> DetectionSeverity:
        return DetectionSeverity.MEDIUM

    def evaluate(self, context: DetectionContext) -> List[DetectionResult]:
        distinct_ip_threshold = context.config.auth_pattern_distinct_ips_threshold
        window_delta = timedelta(minutes=context.config.auth_pattern_window_minutes)

        auth_events = [
            e for e in context.events
            if e.event_type.lower() == "authentication"
            and e.username
            and e.source_ip
        ]

        if not auth_events:
            return []

        # Group by normalized username
        user_events: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for ev in auth_events:
            user_events[ev.username.strip().lower()].append(ev)

        results: List[DetectionResult] = []

        for user, events in user_events.items():
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            n = len(sorted_events)
            if n < distinct_ip_threshold:
                continue

            # Sliding window over time
            i = 0
            while i < n:
                window_events = [sorted_events[i]]
                start_time = sorted_events[i].timestamp

                j = i + 1
                while j < n and (sorted_events[j].timestamp - start_time) <= window_delta:
                    window_events.append(sorted_events[j])
                    j += 1

                # Check number of distinct source IPs in window
                distinct_ips: Set[str] = {e.source_ip for e in window_events if e.source_ip}

                if len(distinct_ips) >= distinct_ip_threshold:
                    cluster_event_ids = sorted([e.id for e in window_events])
                    primary_event = window_events[-1]
                    ips_str = ", ".join(sorted(distinct_ips))

                    raw_sig = f"RULE-004:{user}:{','.join(sorted(distinct_ips))}:{','.join(cluster_event_ids)}"
                    dedup_key = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

                    title = f"Multi-Source Authentication Pattern for '{user}' ({len(distinct_ips)} IPs)"
                    description = (
                        f"User account '{user}' authenticated or attempted authentication from "
                        f"{len(distinct_ips)} distinct source IPs ({ips_str}) within "
                        f"{context.config.auth_pattern_window_minutes} minutes. "
                        f"Total events in observation window: {len(window_events)}."
                    )

                    evidence_items = [
                        EvidenceReference(
                            event_id=ev.id,
                            evidence_role="trigger",
                            description=(
                                f"Auth attempt for '{user}' from IP {ev.source_ip} "
                                f"with status '{ev.status}' at {ev.timestamp.isoformat()}"
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
                            severity=self.default_severity,
                            dedup_key=dedup_key,
                            detected_at=primary_event.timestamp,
                            evidence_items=evidence_items,
                            affected_user=primary_event.username,
                            affected_ip=primary_event.source_ip,
                            affected_hostname=primary_event.hostname,
                            metadata={
                                "distinct_ip_count": len(distinct_ips),
                                "distinct_ips": sorted(list(distinct_ips)),
                                "total_events_in_window": len(window_events),
                                "window_minutes": context.config.auth_pattern_window_minutes,
                            },
                        )
                    )
                    i = j
                else:
                    i += 1

        return results
