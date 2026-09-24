"""Unit Tests for Deterministic Detection Rules.

Covers positive, negative, boundary, timing, missing-field, and entity-separation
scenarios for Rules 001 through 005.
"""

import uuid
from datetime import datetime, timedelta, timezone
import pytest

from backend.app.detection.config import DetectionConfig
from backend.app.detection.core import DetectionContext, DetectionSeverity
from backend.app.detection.rules.rule_001_brute_force import RuleBruteForceLogin
from backend.app.detection.rules.rule_002_login_after_failures import RuleLoginAfterFailures
from backend.app.detection.rules.rule_003_privilege_change import RuleSuspiciousPrivilegeChange
from backend.app.detection.rules.rule_004_auth_pattern import RuleSuspiciousAuthPattern
from backend.app.detection.rules.rule_005_indicator_match import RuleExplicitIndicatorMatch
from backend.app.models.event import SecurityEvent


def create_event(
    event_type: str = "authentication",
    action: str = "login",
    status: str = "failure",
    username: str = "alice",
    source_ip: str = "192.168.1.50",
    destination_ip: str = "10.0.0.1",
    hostname: str = "auth-srv-01",
    timestamp: datetime = None,
    message: str = "Failed login attempt",
    source: str = "linux_auth",
    metadata: dict = None,
) -> SecurityEvent:
    """Helper to instantiate SecurityEvent objects for testing."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    return SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=timestamp,
        event_type=event_type,
        source=source,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        hostname=hostname,
        action=action,
        status=status,
        severity="medium",
        message=message,
        raw_event={"test": True},
        event_metadata=metadata or {},
        created_at=datetime.now(timezone.utc),
    )


# =========================================================================
# RULE 001: Brute Force Tests
# =========================================================================

def test_rule_001_positive_case():
    """Trigger brute force alert when failures reach threshold."""
    config = DetectionConfig(brute_force_failed_threshold=3, brute_force_window_minutes=15)
    rule = RuleBruteForceLogin()
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        create_event(username="bob", source_ip="198.51.100.10", timestamp=now - timedelta(minutes=4)),
        create_event(username="bob", source_ip="198.51.100.10", timestamp=now - timedelta(minutes=2)),
        create_event(username="bob", source_ip="198.51.100.10", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    results = rule.evaluate(context)

    assert len(results) == 1
    assert results[0].rule_id == "RULE-001"
    assert results[0].affected_user == "bob"
    assert results[0].affected_ip == "198.51.100.10"
    assert results[0].severity == DetectionSeverity.MEDIUM
    assert len(results[0].evidence_items) == 3


def test_rule_001_negative_case_successful_logins():
    """Do NOT trigger brute force on successful logins."""
    config = DetectionConfig(brute_force_failed_threshold=3)
    rule = RuleBruteForceLogin()
    now = datetime.now(timezone.utc)

    events = [
        create_event(username="bob", status="success", timestamp=now - timedelta(minutes=2)),
        create_event(username="bob", status="success", timestamp=now - timedelta(minutes=1)),
        create_event(username="bob", status="success", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    results = rule.evaluate(context)
    assert len(results) == 0


def test_rule_001_boundary_case():
    """Exact threshold triggers, threshold - 1 does NOT trigger."""
    config = DetectionConfig(brute_force_failed_threshold=3)
    rule = RuleBruteForceLogin()
    now = datetime.now(timezone.utc)

    # 2 failures (threshold - 1)
    events_sub = [
        create_event(username="bob", timestamp=now - timedelta(minutes=2)),
        create_event(username="bob", timestamp=now),
    ]
    context_sub = DetectionContext(events=events_sub, config=config)
    assert len(rule.evaluate(context_sub)) == 0

    # Adding 1 more reaches threshold
    events_sub.append(create_event(username="bob", timestamp=now + timedelta(seconds=30)))
    context_exact = DetectionContext(events=events_sub, config=config)
    assert len(rule.evaluate(context_exact)) == 1


def test_rule_001_timing_case_outside_window():
    """Failures spread beyond configured window must NOT trigger."""
    config = DetectionConfig(brute_force_failed_threshold=3, brute_force_window_minutes=15)
    rule = RuleBruteForceLogin()
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        create_event(username="bob", timestamp=now - timedelta(minutes=30)),
        create_event(username="bob", timestamp=now - timedelta(minutes=16)),
        create_event(username="bob", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    results = rule.evaluate(context)
    assert len(results) == 0


def test_rule_001_multiple_users_separation():
    """Failures on different accounts do not aggregate together."""
    config = DetectionConfig(brute_force_failed_threshold=3)
    rule = RuleBruteForceLogin()
    now = datetime.now(timezone.utc)

    events = [
        create_event(username="user1", source_ip="192.168.1.1", timestamp=now - timedelta(minutes=2)),
        create_event(username="user2", source_ip="192.168.1.2", timestamp=now - timedelta(minutes=1)),
        create_event(username="user3", source_ip="192.168.1.3", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    assert len(rule.evaluate(context)) == 0


def test_rule_001_missing_fields_resilience():
    """Event with null username but valid source_ip still evaluates safely."""
    config = DetectionConfig(brute_force_failed_threshold=2)
    rule = RuleBruteForceLogin()
    now = datetime.now(timezone.utc)

    events = [
        create_event(username=None, source_ip="198.51.100.99", timestamp=now - timedelta(minutes=1)),
        create_event(username=None, source_ip="198.51.100.99", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    results = rule.evaluate(context)
    assert len(results) == 1
    assert results[0].affected_ip == "198.51.100.99"


# =========================================================================
# RULE 002: Login After Failures Tests
# =========================================================================

def test_rule_002_positive_case():
    """Detect success following multiple failures for same account."""
    config = DetectionConfig(login_after_failures_threshold=2, login_after_failures_window_minutes=20)
    rule = RuleLoginAfterFailures()
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        create_event(username="helpdesk", status="failure", timestamp=now - timedelta(minutes=5)),
        create_event(username="helpdesk", status="failure", timestamp=now - timedelta(minutes=3)),
        create_event(username="helpdesk", status="success", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    results = rule.evaluate(context)

    assert len(results) == 1
    assert results[0].rule_id == "RULE-002"
    assert results[0].severity == DetectionSeverity.HIGH
    assert results[0].metadata["preceding_failure_count"] == 2
    # 2 failures + 1 success = 3 evidence items
    assert len(results[0].evidence_items) == 3


def test_rule_002_negative_case_no_preceding_failures():
    """Legitimate direct successful login does NOT trigger."""
    config = DetectionConfig(login_after_failures_threshold=2)
    rule = RuleLoginAfterFailures()
    now = datetime.now(timezone.utc)

    events = [
        create_event(username="admin", status="success", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    assert len(rule.evaluate(context)) == 0


def test_rule_002_timing_case_failures_too_old():
    """Failures occurring before lookback window do NOT correlate with success."""
    config = DetectionConfig(login_after_failures_threshold=2, login_after_failures_window_minutes=15)
    rule = RuleLoginAfterFailures()
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        create_event(username="helpdesk", status="failure", timestamp=now - timedelta(minutes=60)),
        create_event(username="helpdesk", status="failure", timestamp=now - timedelta(minutes=45)),
        create_event(username="helpdesk", status="success", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    assert len(rule.evaluate(context)) == 0


def test_rule_002_multiple_users_isolation():
    """Failures for user A do not trigger alert for successful login of user B."""
    config = DetectionConfig(login_after_failures_threshold=2)
    rule = RuleLoginAfterFailures()
    now = datetime.now(timezone.utc)

    events = [
        create_event(username="attacker_target", source_ip="1.1.1.1", status="failure", timestamp=now - timedelta(minutes=2)),
        create_event(username="attacker_target", source_ip="1.1.1.1", status="failure", timestamp=now - timedelta(minutes=1)),
        create_event(username="innocent_user", source_ip="2.2.2.2", status="success", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    assert len(rule.evaluate(context)) == 0


# =========================================================================
# RULE 003: Suspicious Privilege Change Tests
# =========================================================================

def test_rule_003_positive_critical_privilege_escalation():
    """Adding user to Domain Admins or root wheel results in critical alert."""
    rule = RuleSuspiciousPrivilegeChange()
    now = datetime.now(timezone.utc)

    event = create_event(
        event_type="privilege_change",
        action="group_membership_add",
        status="success",
        username="temp_worker",
        hostname="DC-01",
        message="User temp_worker added to Domain Admins security group",
        timestamp=now,
    )

    context = DetectionContext(events=[event])
    results = rule.evaluate(context)

    assert len(results) == 1
    assert results[0].rule_id == "RULE-003"
    assert results[0].severity == DetectionSeverity.CRITICAL
    assert "Domain Admins" in results[0].description or "group_membership_add" in results[0].description


def test_rule_003_negative_routine_event():
    """Standard network or query event does NOT trigger privilege escalation rule."""
    rule = RuleSuspiciousPrivilegeChange()
    now = datetime.now(timezone.utc)

    event = create_event(
        event_type="network",
        action="dns_query",
        status="success",
        username="alice",
        message="DNS resolution query",
        timestamp=now,
    )

    context = DetectionContext(events=[event])
    assert len(rule.evaluate(context)) == 0


# =========================================================================
# RULE 004: Suspicious Auth Pattern Tests
# =========================================================================

def test_rule_004_positive_multi_ip_auth():
    """Same user accessing account from multiple distinct IPs in window triggers."""
    config = DetectionConfig(auth_pattern_distinct_ips_threshold=2, auth_pattern_window_minutes=60)
    rule = RuleSuspiciousAuthPattern()
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        create_event(username="alice", source_ip="198.51.100.1", timestamp=now - timedelta(minutes=10)),
        create_event(username="alice", source_ip="203.0.113.88", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    results = rule.evaluate(context)

    assert len(results) == 1
    assert results[0].rule_id == "RULE-004"
    assert results[0].affected_user == "alice"
    assert results[0].metadata["distinct_ip_count"] == 2


def test_rule_004_negative_same_ip_repeat():
    """Multiple logins from the identical IP do not trigger multi-IP pattern."""
    config = DetectionConfig(auth_pattern_distinct_ips_threshold=2)
    rule = RuleSuspiciousAuthPattern()
    now = datetime.now(timezone.utc)

    events = [
        create_event(username="alice", source_ip="192.168.1.50", timestamp=now - timedelta(minutes=5)),
        create_event(username="alice", source_ip="192.168.1.50", timestamp=now),
    ]

    context = DetectionContext(events=events, config=config)
    assert len(rule.evaluate(context)) == 0


# =========================================================================
# RULE 005: Configured Indicator Match Tests
# =========================================================================

def test_rule_005_positive_configured_ip_match():
    """Event containing demo indicator IP triggers alert with simulated label."""
    config = DetectionConfig(demo_indicators_ips={"198.51.100.101"})
    rule = RuleExplicitIndicatorMatch()
    now = datetime.now(timezone.utc)

    event = create_event(
        source_ip="198.51.100.101",
        destination_ip="10.0.1.100",
        action="rdp_login",
        status="success",
        timestamp=now,
    )

    context = DetectionContext(events=[event], config=config)
    results = rule.evaluate(context)

    assert len(results) == 1
    assert results[0].rule_id == "RULE-005"
    assert results[0].severity == DetectionSeverity.HIGH
    assert "[Simulated IOC]" in results[0].title


def test_rule_005_positive_configured_username_match():
    """Event containing configured unauthorized username triggers."""
    config = DetectionConfig(demo_indicators_usernames={"backdoor_backup"})
    rule = RuleExplicitIndicatorMatch()
    now = datetime.now(timezone.utc)

    event = create_event(
        username="backdoor_backup",
        action="user_created",
        status="success",
        timestamp=now,
    )

    context = DetectionContext(events=[event], config=config)
    results = rule.evaluate(context)

    assert len(results) == 1
    assert results[0].rule_id == "RULE-005"
    assert results[0].affected_user == "backdoor_backup"


def test_rule_005_negative_benign_event():
    """Normal benign event matching no indicator produces zero alerts."""
    config = DetectionConfig(demo_indicators_ips={"198.51.100.101"})
    rule = RuleExplicitIndicatorMatch()
    now = datetime.now(timezone.utc)

    event = create_event(
        source_ip="10.0.1.50",
        username="standard_user",
        timestamp=now,
    )

    context = DetectionContext(events=[event], config=config)
    assert len(rule.evaluate(context)) == 0
