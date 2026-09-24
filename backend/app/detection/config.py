"""Detection Engine Configuration.

Defines configurable thresholds, time windows, and demo indicators for
deterministic detection rules. Separates detection logic from parameter definitions.
"""

from typing import Dict, List, Set
from pydantic import BaseModel, Field


class DetectionConfig(BaseModel):
    """Configurable thresholds and indicators for detection rules."""

    # Rule 001: Brute Force Login Attempt
    brute_force_failed_threshold: int = Field(
        default=3,
        description="Minimum failed authentication attempts required to trigger brute-force alert",
        ge=2,
    )
    brute_force_window_minutes: int = Field(
        default=15,
        description="Observation window in minutes for aggregating failed authentication attempts",
        ge=1,
    )

    # Rule 002: Successful Login After Repeated Failures
    login_after_failures_threshold: int = Field(
        default=2,
        description="Minimum prior failed attempts required before a successful login to trigger alert",
        ge=1,
    )
    login_after_failures_window_minutes: int = Field(
        default=30,
        description="Preceding lookback window in minutes before a successful login",
        ge=1,
    )

    # Rule 003: Suspicious Privilege Change
    privilege_sensitive_roles: List[str] = Field(
        default=[
            "domain admins",
            "enterprise admins",
            "wheel",
            "root",
            "administrators",
            "global admin",
            "security admin",
            "admin",
        ],
        description="Target privileged roles or security groups that indicate elevated authority",
    )
    privilege_sensitive_actions: List[str] = Field(
        default=[
            "sudo",
            "group_membership_add",
            "privilege_escalation",
            "role_assigned",
            "user_created",
            "su",
        ],
        description="Event actions indicative of role elevation or administrative access",
    )

    # Rule 004: Suspicious Authentication Pattern
    auth_pattern_distinct_ips_threshold: int = Field(
        default=2,
        description="Number of distinct external/source IPs accessing the same account within the window",
        ge=2,
    )
    auth_pattern_window_minutes: int = Field(
        default=60,
        description="Time window in minutes for evaluating multi-source login patterns",
        ge=5,
    )

    # Rule 005: Explicit Indicator Match (Configured Demo / Threat Intelligence)
    # Clearly labeled as simulated indicators for the local demonstration environment
    demo_indicators_ips: Set[str] = Field(
        default={
            "198.51.100.101",   # Simulated external brute-force attacker IP
            "203.0.113.195",    # Simulated untrusted IdP push-challenge initiator IP
            "198.51.100.42",    # Simulated external bastion breach IP
        },
        description="Configured demo IPs tagged as simulated threat indicators",
    )
    demo_indicators_usernames: Set[str] = Field(
        default={
            "backdoor_backup",  # Simulated unauthorized persistence account
        },
        description="Configured demo usernames tagged as simulated threat indicators",
    )
    demo_indicators_hostnames: Set[str] = Field(
        default={
            "c2-beacon.attacker.local",
            "bad-external.domain.test",
        },
        description="Configured demo hostnames/domains tagged as simulated threat indicators",
    )


# Singleton default configuration
default_detection_config = DetectionConfig()
