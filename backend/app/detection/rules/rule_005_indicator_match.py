"""RULE 005: Explicit Indicator Match (Configured Demo Threat Intelligence).

Detects events matching explicitly configured demo threat indicators (IPs, usernames, hostnames).
Transparently labeled as configured/simulated indicators in accordance with SOC evidence standards.
"""

import hashlib
from typing import List, Tuple
from backend.app.detection.core import (
    DetectionContext,
    DetectionResult,
    DetectionRule,
    DetectionSeverity,
    EvidenceReference,
)


class RuleExplicitIndicatorMatch(DetectionRule):
    """Detects events containing configured demo indicators (IPs, users, hosts)."""

    @property
    def rule_id(self) -> str:
        return "RULE-005"

    @property
    def rule_name(self) -> str:
        return "Configured Threat Indicator Match"

    @property
    def description(self) -> str:
        return (
            "Detects events matching explicitly configured demo threat indicators "
            "(known simulated attacker IPs, persistent accounts, or malicious domains). "
            "Transparently tags matches without claiming certainty beyond configured rules."
        )

    @property
    def default_severity(self) -> DetectionSeverity:
        return DetectionSeverity.HIGH

    def evaluate(self, context: DetectionContext) -> List[DetectionResult]:
        demo_ips = context.config.demo_indicators_ips
        demo_users = {u.lower() for u in context.config.demo_indicators_usernames}
        demo_hosts = {h.lower() for h in context.config.demo_indicators_hostnames}

        results: List[DetectionResult] = []

        for event in context.events:
            matches: List[Tuple[str, str]] = []  # (indicator_type, indicator_value)

            # Check source and destination IP
            if event.source_ip and event.source_ip in demo_ips:
                matches.append(("source_ip", event.source_ip))
            if event.destination_ip and event.destination_ip in demo_ips:
                matches.append(("destination_ip", event.destination_ip))

            # Check username
            if event.username and event.username.lower() in demo_users:
                matches.append(("username", event.username))

            # Check hostname
            if event.hostname and event.hostname.lower() in demo_hosts:
                matches.append(("hostname", event.hostname))

            if matches:
                # Format matched indicators
                matched_summary = "; ".join([f"{t}={v}" for t, v in matches])

                # Severity: HIGH for successful actions involving indicator; MEDIUM for blocked/denied
                if event.status.lower() in ("blocked", "denied", "dropped"):
                    severity = DetectionSeverity.MEDIUM
                else:
                    severity = DetectionSeverity.HIGH

                title = f"[Simulated IOC] Indicator Match on {event.source}: {matches[0][1]}"
                description = (
                    f"Security event matched configured demo indicator(s): {matched_summary}. "
                    f"Action: '{event.action}' on host '{event.hostname or 'unknown'}'. "
                    f"Status: {event.status}. "
                    f"Note: This alert is triggered by explicit configuration match in the demonstration environment."
                )

                raw_sig = f"RULE-005:{event.id}:{matched_summary}:{event.timestamp.isoformat()}"
                dedup_key = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

                evidence_items = [
                    EvidenceReference(
                        event_id=event.id,
                        evidence_role="indicator_match",
                        description=(
                            f"Matched configured indicator ({matched_summary}) in {event.source} "
                            f"log with action '{event.action}' and status '{event.status}'"
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
                        affected_ip=event.source_ip or event.destination_ip,
                        affected_hostname=event.hostname,
                        metadata={
                            "matched_indicators": [{"type": t, "value": v} for t, v in matches],
                            "log_source": event.source,
                            "action": event.action,
                            "status": event.status,
                            "simulated_ioc": True,
                        },
                    )
                )

        return results
