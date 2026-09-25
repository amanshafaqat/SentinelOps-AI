"""Deterministic and Explainable Security Incident Correlation Engine.

Transforms discrete, deterministic alerts into cohesive security incidents based on
shared entity signals (username, source IP, host), temporal proximity windows,
and multi-stage attack progressions.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import select, and_, or_, desc
from sqlalchemy.orm import Session, joinedload

from backend.app.core.logging import logger
from backend.app.models.alert import Alert
from backend.app.models.incident import Incident, IncidentAuditLog
from backend.app.correlation.core import (
    IncidentSeverity,
    IncidentStatus,
    CorrelatedCluster,
    calculate_incident_severity,
    build_incident_narrative,
)


@dataclass
class CorrelationRunSummary:
    """Summary metrics of a correlation run."""
    alerts_evaluated: int
    alerts_correlated: int
    incidents_created: int
    incidents_updated: int
    execution_duration_ms: float
    created_incident_ids: List[str] = field(default_factory=list)
    correlation_window_minutes: int = 60
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CorrelationEngine:
    """Modular, deterministic correlation engine for SentinelOps AI."""

    def __init__(self, default_time_window_minutes: int = 60):
        self.default_time_window_minutes = default_time_window_minutes

    def _alerts_are_related(
        self,
        a1: Alert,
        a2: Alert,
        window_seconds: float,
    ) -> Tuple[bool, List[str]]:
        """Determine whether two alerts satisfy deterministic correlation criteria.

        Criteria:
        1. Temporal proximity: Time delta must be within window_seconds.
        2. Entity sharing: Must share at least one non-null normalized entity:
           - Same affected_user (case-insensitive)
           - Same affected_ip (exact string match)
           - Same affected_hostname (case-insensitive)
        """
        # Temporal proximity check
        if not a1.detected_at or not a2.detected_at:
            return False, []

        delta_seconds = abs((a1.detected_at - a2.detected_at).total_seconds())
        if delta_seconds > window_seconds:
            return False, []

        signals: List[str] = []

        # 1. Shared User Check
        u1 = (a1.affected_user or "").strip().lower()
        u2 = (a2.affected_user or "").strip().lower()
        if u1 and u2 and u1 == u2:
            signals.append(f"user:{u1}")

        # 2. Shared IP Check
        ip1 = (a1.affected_ip or "").strip()
        ip2 = (a2.affected_ip or "").strip()
        if ip1 and ip2 and ip1 == ip2:
            signals.append(f"ip:{ip1}")

        # 3. Shared Hostname Check
        h1 = (a1.affected_hostname or "").strip().lower()
        h2 = (a2.affected_hostname or "").strip().lower()
        if h1 and h2 and h1 == h2:
            signals.append(f"host:{h1}")

        # If at least one entity is shared within the time window, they correlate
        if len(signals) > 0:
            return True, signals

        return False, []

    def cluster_alerts(
        self,
        alerts: List[Alert],
        time_window_minutes: int,
    ) -> List[List[Alert]]:
        """Group a set of alerts into connected clusters using disjoint-set (Union-Find).

        Two alerts belong to the same cluster if they are directly related or connected
        through an unbroken transitive chain of related alerts within the correlation window.
        """
        if not alerts:
            return []

        n = len(alerts)
        parent = list(range(n))

        def find(i: int) -> int:
            path = []
            while parent[i] != i:
                path.append(i)
                i = parent[i]
            for node in path:
                parent[node] = i
            return i

        def union(i: int, j: int):
            root_i = find(i)
            root_j = find(j)
            if root_i != root_j:
                parent[root_i] = root_j

        window_seconds = time_window_minutes * 60.0

        for i in range(n):
            for j in range(i + 1, n):
                related, _ = self._alerts_are_related(alerts[i], alerts[j], window_seconds)
                if related:
                    union(i, j)

        clusters_map: Dict[int, List[Alert]] = defaultdict(list)
        for i in range(n):
            root = find(i)
            clusters_map[root].append(alerts[i])

        return list(clusters_map.values())

    def build_cluster_details(
        self,
        cluster_alerts: List[Alert],
        time_window_minutes: int,
    ) -> CorrelatedCluster:
        """Synthesize explainable metadata, entity sets, and severity for a cluster of alerts."""
        cluster_alerts_sorted = sorted(cluster_alerts, key=lambda a: a.detected_at)
        alert_ids = [a.id for a in cluster_alerts_sorted]
        first_seen = cluster_alerts_sorted[0].detected_at
        last_seen = cluster_alerts_sorted[-1].detected_at

        # Unique entities
        users: Set[str] = {a.affected_user for a in cluster_alerts if a.affected_user}
        ips: Set[str] = {a.affected_ip for a in cluster_alerts if a.affected_ip}
        hosts: Set[str] = {a.affected_hostname for a in cluster_alerts if a.affected_hostname}
        rule_ids: List[str] = [a.rule_id for a in cluster_alerts]
        severities: List[str] = [a.severity for a in cluster_alerts]

        time_span_minutes = (last_seen - first_seen).total_seconds() / 60.0 if (first_seen and last_seen) else 0.0

        # Check attack progression
        rule_set = set(rule_ids)
        has_auth_failure = any(r in rule_set for r in ["RULE-001", "RULE-004"])
        has_auth_success = "RULE-002" in rule_set
        has_priv_escalation = "RULE-003" in rule_set

        has_attack_progression = (
            (has_auth_failure and has_auth_success)
            or (has_auth_failure and has_priv_escalation)
            or (has_auth_success and has_priv_escalation)
        )

        # Calculate explainable severity
        severity, severity_reason = calculate_incident_severity(
            alert_severities=severities,
            rule_ids=rule_ids,
            has_attack_progression=has_attack_progression,
        )

        # Build Explainable Correlation Reasons
        reasons: List[str] = []
        if len(cluster_alerts) > 1:
            reasons.append(
                f"Temporal Proximity: {len(cluster_alerts)} alerts occurred within configured {time_window_minutes}-minute correlation window (total span: {time_span_minutes:.1f}m)."
            )
        else:
            reasons.append(
                f"Autonomous Detection: High-fidelity security alert provisioned into managed incident record."
            )

        if users:
            reasons.append(f"Targeted Identity: Common user account '{', '.join(sorted(users))}' observed across detection alerts.")
        if ips:
            reasons.append(f"Network Origin: Activity tied to source IP address '{', '.join(sorted(ips))}'.")
        if hosts:
            reasons.append(f"Affected Host: Correlated across asset(s) '{', '.join(sorted(hosts))}'.")

        if has_attack_progression:
            reasons.append(
                "Attack Progression Sequence: Telemetry demonstrates credential anomaly followed by successful logon or privilege modification."
            )

        reasons.append(f"Severity Rationale: {severity_reason}")

        # Narrative Title & Description
        title, description = build_incident_narrative(
            affected_users=sorted(list(users)),
            affected_ips=sorted(list(ips)),
            rule_ids=rule_ids,
            alert_count=len(cluster_alerts),
            time_span_minutes=time_span_minutes,
        )

        metadata = {
            "correlation_window_minutes": time_window_minutes,
            "constituent_rule_ids": sorted(list(rule_set)),
            "alert_count": len(cluster_alerts),
            "attack_progression_detected": has_attack_progression,
            "time_span_minutes": round(time_span_minutes, 2),
            "severity_derivation": severity_reason,
        }

        return CorrelatedCluster(
            alert_ids=alert_ids,
            title=title,
            description=description,
            severity=severity,
            first_seen=first_seen,
            last_seen=last_seen,
            affected_users=sorted(list(users)),
            affected_ips=sorted(list(ips)),
            affected_hostnames=sorted(list(hosts)),
            correlation_reasons=reasons,
            correlation_metadata=metadata,
        )

    def run_correlation(
        self,
        db: Session,
        time_window_minutes: Optional[int] = None,
        min_severity: Optional[str] = None,
        force_recorrelate: bool = False,
    ) -> CorrelationRunSummary:
        """Execute correlation engine over database alerts and persist incidents.

        Idempotent:
        - When force_recorrelate=False, existing incidents remain untouched, and only
          unassociated alerts are evaluated. Unassociated alerts matching an open incident
          are merged into that incident.
        - When force_recorrelate=True, alert links are reset and incidents reconstructed.
        """
        start_time = time.perf_counter()
        window = time_window_minutes or self.default_time_window_minutes
        window_seconds = window * 60.0

        if force_recorrelate:
            # Clear existing incident links on all alerts
            db.query(Alert).update({Alert.incident_id: None}, synchronize_session=False)
            # Remove existing open/unresolved incidents to avoid orphaned shells
            db.query(Incident).delete(synchronize_session=False)
            db.commit()

        # Query candidate alerts
        stmt = select(Alert).order_by(Alert.detected_at.asc())
        if not force_recorrelate:
            # Only evaluate unassociated alerts
            stmt = stmt.where(Alert.incident_id.is_(None))

        if min_severity:
            min_rank = SEVERITY_RANKS.get(min_severity.lower(), 1)
            allowed_sevs = [s for s, r in SEVERITY_RANKS.items() if r >= min_rank]
            stmt = stmt.where(Alert.severity.in_(allowed_sevs))

        unassociated_alerts: List[Alert] = list(db.scalars(stmt).all())
        total_evaluated = len(unassociated_alerts)

        if total_evaluated == 0:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return CorrelationRunSummary(
                alerts_evaluated=0,
                alerts_correlated=0,
                incidents_created=0,
                incidents_updated=0,
                execution_duration_ms=duration_ms,
                correlation_window_minutes=window,
            )

        incidents_created = 0
        incidents_updated = 0
        alerts_correlated_count = 0
        new_incident_ids: List[str] = []

        # If not force recorrelate, first check if any unassociated alert matches existing open incidents
        remaining_alerts: List[Alert] = []
        if not force_recorrelate:
            open_incidents: List[Incident] = list(
                db.scalars(
                    select(Incident)
                    .options(joinedload(Incident.alerts))
                    .where(Incident.status.in_([IncidentStatus.NEW.value, IncidentStatus.INVESTIGATING.value]))
                ).unique().all()
            )

            for alert in unassociated_alerts:
                matched_incident: Optional[Incident] = None
                for inc in open_incidents:
                    # Check temporal window with incident boundary
                    if alert.detected_at and inc.last_seen:
                        diff = abs((alert.detected_at - inc.last_seen).total_seconds())
                        if diff <= window_seconds:
                            u = (alert.affected_user or "").strip().lower()
                            ip = (alert.affected_ip or "").strip()
                            host = (alert.affected_hostname or "").strip().lower()
                            has_match = (
                                (u and any(u == str(x).lower() for x in (inc.affected_users or [])))
                                or (ip and any(ip == str(x) for x in (inc.affected_ips or [])))
                                or (host and any(host == str(x).lower() for x in (inc.affected_hostnames or [])))
                            )
                            if has_match:
                                matched_incident = inc
                                break

                if matched_incident:
                    # Attach alert to existing incident
                    alert.incident_id = matched_incident.id
                    if alert.detected_at and matched_incident.last_seen and alert.detected_at > matched_incident.last_seen:
                        matched_incident.last_seen = alert.detected_at
                    if alert.detected_at and matched_incident.first_seen and alert.detected_at < matched_incident.first_seen:
                        matched_incident.first_seen = alert.detected_at

                    # Update affected entities
                    if alert.affected_user and alert.affected_user not in (matched_incident.affected_users or []):
                        matched_incident.affected_users = list(matched_incident.affected_users or []) + [alert.affected_user]
                    if alert.affected_ip and alert.affected_ip not in (matched_incident.affected_ips or []):
                        matched_incident.affected_ips = list(matched_incident.affected_ips or []) + [alert.affected_ip]
                    if alert.affected_hostname and alert.affected_hostname not in (matched_incident.affected_hostnames or []):
                        matched_incident.affected_hostnames = list(matched_incident.affected_hostnames or []) + [alert.affected_hostname]

                    # Record audit log
                    audit = IncidentAuditLog(
                        incident_id=matched_incident.id,
                        action="alert_added",
                        previous_value=None,
                        new_value=f"Alert {alert.rule_id} ({alert.id})",
                        notes=f"Correlation engine appended newly detected alert {alert.title} to active incident.",
                        actor="correlation_engine",
                    )
                    db.add(audit)
                    incidents_updated += 1
                    alerts_correlated_count += 1
                else:
                    remaining_alerts.append(alert)
        else:
            remaining_alerts = unassociated_alerts

        # Now cluster remaining alerts into new incidents
        clusters = self.cluster_alerts(remaining_alerts, window)

        for cluster_alerts in clusters:
            if not cluster_alerts:
                continue

            details = self.build_cluster_details(cluster_alerts, window)

            # Create Incident Record
            incident = Incident(
                title=details.title,
                description=details.description,
                severity=details.severity,
                status=IncidentStatus.NEW.value,
                first_seen=details.first_seen or datetime.now(timezone.utc),
                last_seen=details.last_seen or datetime.now(timezone.utc),
                affected_users=details.affected_users,
                affected_ips=details.affected_ips,
                affected_hostnames=details.affected_hostnames,
                correlation_reasons=details.correlation_reasons,
                correlation_metadata=details.correlation_metadata,
            )
            db.add(incident)
            db.flush()  # Generates incident.id

            # Associate Alerts with new Incident
            for a in cluster_alerts:
                a.incident_id = incident.id
                alerts_correlated_count += 1

            # Create Audit Log for Incident Creation
            audit_entry = IncidentAuditLog(
                incident_id=incident.id,
                action="correlation_created",
                previous_value=None,
                new_value=f"Status: {incident.status} | Severity: {incident.severity}",
                notes=f"Correlated from {len(cluster_alerts)} alerts within {window}m window.",
                actor="correlation_engine",
            )
            db.add(audit_entry)

            incidents_created += 1
            new_incident_ids.append(incident.id)

        db.commit()
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            f"Correlation run complete: {incidents_created} incidents created, {incidents_updated} updated, "
            f"{alerts_correlated_count} alerts correlated in {duration_ms}ms"
        )

        return CorrelationRunSummary(
            alerts_evaluated=total_evaluated,
            alerts_correlated=alerts_correlated_count,
            incidents_created=incidents_created,
            incidents_updated=incidents_updated,
            execution_duration_ms=duration_ms,
            created_incident_ids=new_incident_ids,
            correlation_window_minutes=window,
        )


# Singleton instance
default_correlation_engine = CorrelationEngine(default_time_window_minutes=60)
