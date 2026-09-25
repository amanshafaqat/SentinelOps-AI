"""Core Data Structures, Enums, and Severity Calculations for Incident Correlation.

Defines deterministic correlation signals, entity extraction, explainability builders,
and transparent severity calculation rules.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


SEVERITY_RANKS: Dict[str, int] = {
    IncidentSeverity.LOW.value: 1,
    IncidentSeverity.MEDIUM.value: 2,
    IncidentSeverity.HIGH.value: 3,
    IncidentSeverity.CRITICAL.value: 4,
}

RANK_TO_SEVERITY: Dict[int, str] = {
    1: IncidentSeverity.LOW.value,
    2: IncidentSeverity.MEDIUM.value,
    3: IncidentSeverity.HIGH.value,
    4: IncidentSeverity.CRITICAL.value,
}


@dataclass
class CorrelationSignal:
    """An explainable signal linking two or more alerts."""
    signal_type: str  # e.g., same_username, same_ip, attack_progression, temporal_window
    entity_key: str   # e.g., user:jdoe, ip:198.51.100.42
    description: str  # Human-readable explanation
    confidence_weight: float = 1.0


@dataclass
class CorrelatedCluster:
    """A deterministic cluster of related alerts destined to become or join an incident."""
    alert_ids: List[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    severity: str = IncidentSeverity.MEDIUM.value
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    affected_users: List[str] = field(default_factory=list)
    affected_ips: List[str] = field(default_factory=list)
    affected_hostnames: List[str] = field(default_factory=list)
    correlation_reasons: List[str] = field(default_factory=list)
    correlation_metadata: Dict[str, Any] = field(default_factory=dict)


def calculate_incident_severity(
    alert_severities: List[str],
    rule_ids: List[str],
    has_attack_progression: bool = False,
) -> Tuple[str, str]:
    """Calculate deterministic incident severity based on correlated alerts.

    Rules:
    1. If any alert is CRITICAL -> CRITICAL
    2. If attack progression detected (e.g. brute force + successful login/privilege escalation) -> elevated by 1 tier
    3. If any alert is HIGH and >= 2 distinct detection rules triggered -> CRITICAL
    4. If any alert is HIGH -> HIGH
    5. If >= 2 distinct alerts are MEDIUM -> HIGH (compounding risk)
    6. If any alert is MEDIUM -> MEDIUM
    7. Otherwise -> LOW

    Returns:
        Tuple of (severity_string, explanation_string)
    """
    if not alert_severities:
        return IncidentSeverity.LOW.value, "Default baseline severity: no constituent alerts."

    normalized_sevs = [s.lower() for s in alert_severities]
    max_rank = max(SEVERITY_RANKS.get(s, 1) for s in normalized_sevs)
    unique_rules = set(rule_ids)

    explanation_parts: List[str] = []

    # Check for direct critical
    if max_rank >= 4:
        calculated_rank = 4
        explanation_parts.append("One or more constituent alerts evaluated at CRITICAL severity.")
    elif max_rank == 3:
        if has_attack_progression:
            calculated_rank = 4
            explanation_parts.append(
                "Promoted to CRITICAL due to confirmed multi-stage attack progression (authentication anomaly followed by unauthorized privilege access)."
            )
        elif len(unique_rules) >= 2:
            calculated_rank = 4
            explanation_parts.append(
                "Promoted to CRITICAL: multiple distinct detection rules triggered (compounding alert correlation)."
            )
        else:
            calculated_rank = 3
            explanation_parts.append("Derived from constituent HIGH severity alert.")
    elif max_rank == 2:
        medium_count = sum(1 for s in normalized_sevs if s == IncidentSeverity.MEDIUM.value)
        if has_attack_progression:
            calculated_rank = 3
            explanation_parts.append(
                "Promoted to HIGH due to correlated attack sequence across related security detections."
            )
        elif medium_count >= 2:
            calculated_rank = 3
            explanation_parts.append(
                f"Elevated to HIGH: compound risk from {medium_count} correlated MEDIUM severity alerts."
            )
        else:
            calculated_rank = 2
            explanation_parts.append("Derived from constituent MEDIUM severity alert.")
    else:
        calculated_rank = 1
        explanation_parts.append("Constituent alerts evaluated at LOW baseline severity.")

    final_severity = RANK_TO_SEVERITY.get(calculated_rank, IncidentSeverity.MEDIUM.value)
    return final_severity, " ".join(explanation_parts)


def build_incident_narrative(
    affected_users: List[str],
    affected_ips: List[str],
    rule_ids: List[str],
    alert_count: int,
    time_span_minutes: float,
) -> Tuple[str, str]:
    """Generate explainable, deterministic incident title and description."""
    user_str = ", ".join(affected_users) if affected_users else "Unspecified Accounts"
    ip_str = ", ".join(affected_ips) if affected_ips else "Unknown IP"

    # Identify rule themes
    has_brute_force = any("001" in r for r in rule_ids)
    has_login_after_fail = any("002" in r for r in rule_ids)
    has_priv_esc = any("003" in r for r in rule_ids)
    has_auth_pattern = any("004" in r for r in rule_ids)
    has_indicator = any("005" in r for r in rule_ids)

    # Narrative Synthesis
    if has_brute_force and has_login_after_fail:
        title = f"Credential Compromise Sequence: Brute Force Followed by Success ({user_str})"
        desc = (
            f"Automated correlation detected a multi-stage authentication compromise against account(s) '{user_str}'. "
            f"Initial repeated authentication failures were subsequently followed by a successful logon event "
            f"from source {ip_str} within an active {time_span_minutes:.1f}-minute window."
        )
    elif has_priv_esc and (has_brute_force or has_login_after_fail or has_auth_pattern):
        title = f"Unauthorized Privilege Escalation following Authentication Anomalies ({user_str})"
        desc = (
            f"Correlated security telemetry indicates an account privilege escalation event affecting '{user_str}' "
            f"in close temporal proximity ({time_span_minutes:.1f}m) to anomalous authentication activity."
        )
    elif has_priv_esc:
        title = f"Suspicious Administrative Privilege Escalation ({user_str})"
        desc = (
            f"Elevated privilege grant detected for account '{user_str}'. Observed administrative modifications "
            f"deviate from expected operational baseline and warrant verification."
        )
    elif has_brute_force:
        title = f"Distributed Credential Attack / Brute Force ({user_str})"
        desc = (
            f"Multiple repeated authentication failures detected targeting account(s) '{user_str}' "
            f"originating from {ip_str} ({alert_count} alerts correlated over {time_span_minutes:.1f}m)."
        )
    elif has_auth_pattern:
        title = f"Anomalous Concurrent Multi-Source Authentication ({user_str})"
        desc = (
            f"Account '{user_str}' demonstrated successful authentications from multiple geographically or network-distinct "
            f"IP addresses ({ip_str}) within a {time_span_minutes:.1f}-minute window."
        )
    elif has_indicator:
        title = f"High-Confidence Threat Intelligence Indicator Match ({ip_str})"
        desc = (
            f"Security activity correlated around known malicious indicator {ip_str} across "
            f"{alert_count} detection alert(s)."
        )
    else:
        title = f"Correlated Security Activity ({user_str})"
        desc = (
            f"Incident assembled from {alert_count} correlated alerts sharing common entities "
            f"({user_str}, {ip_str}) within a {time_span_minutes:.1f}-minute temporal correlation window."
        )

    return title, desc
