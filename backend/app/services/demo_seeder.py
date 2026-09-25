"""Demo Scenarios Dataset and Seeder for SentinelOps AI.

Generates realistic telemetry illustrating all 4 core Phase 4 SOC scenarios:
- Scenario 1: Repeated failed logins from same source IP (Brute Force)
- Scenario 2: Failed logins followed by successful logon (Credential Compromise Sequence)
- Scenario 3: Anomalous authentication followed by Privilege Escalation
- Scenario 4: Completely unrelated benign routine operations (stays isolated)
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any
import uuid
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from backend.app.models.event import SecurityEvent
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.incident import Incident, IncidentAuditLog
from backend.app.detection.engine import default_detection_engine
from backend.app.correlation.engine import default_correlation_engine
from backend.app.core.logging import logger


def generate_demo_events() -> List[dict]:
    """Generate structured events covering Scenarios 1-4 with deterministic timestamps."""
    base_time = datetime.now(timezone.utc) - timedelta(minutes=45)

    events: List[dict] = []

    # ==========================================
    # SCENARIO 1: Repeated failed logins (Brute Force)
    # Target: Administrator | Source IP: 198.51.100.42
    # ==========================================
    for i in range(5):
        t = base_time + timedelta(seconds=i * 30)
        events.append({
            "timestamp": t.isoformat(),
            "event_type": "authentication",
            "source": "auth_daemon",
            "source_ip": "198.51.100.42",
            "destination_ip": "10.0.1.10",
            "source_port": 40100 + i,
            "destination_port": 22,
            "username": "Administrator",
            "hostname": "prod-bastion-01",
            "action": "ssh_login",
            "status": "failure",
            "severity": "medium",
            "message": f"Failed password for Administrator from 198.51.100.42 port {40100 + i} ssh2",
            "raw_event": {"src_ip": "198.51.100.42", "user": "Administrator", "auth_method": "password"},
            "metadata": {"scenario": "scenario_1_brute_force", "attempt": i + 1},
        })

    # ==========================================
    # SCENARIO 2: Failed logins followed by SUCCESSFUL login
    # Target: svc-deploy | Source IP: 198.51.100.88
    # ==========================================
    s2_base = base_time + timedelta(minutes=8)
    for i in range(4):
        t = s2_base + timedelta(seconds=i * 25)
        events.append({
            "timestamp": t.isoformat(),
            "event_type": "authentication",
            "source": "auth_daemon",
            "source_ip": "198.51.100.88",
            "destination_ip": "10.0.1.20",
            "source_port": 51200 + i,
            "destination_port": 22,
            "username": "svc-deploy",
            "hostname": "k8s-deploy-runner",
            "action": "ssh_login",
            "status": "failure",
            "severity": "medium",
            "message": f"PAM authentication failure for svc-deploy from 198.51.100.88",
            "raw_event": {"src_ip": "198.51.100.88", "user": "svc-deploy"},
            "metadata": {"scenario": "scenario_2_credential_stuffing", "attempt": i + 1},
        })

    # Successful login right after failures
    events.append({
        "timestamp": (s2_base + timedelta(seconds=120)).isoformat(),
        "event_type": "authentication",
        "source": "auth_daemon",
        "source_ip": "198.51.100.88",
        "destination_ip": "10.0.1.20",
        "source_port": 51210,
        "destination_port": 22,
        "username": "svc-deploy",
        "hostname": "k8s-deploy-runner",
        "action": "ssh_login",
        "status": "success",
        "severity": "high",
        "message": "Accepted publickey/password for svc-deploy from 198.51.100.88 port 51210 ssh2",
        "raw_event": {"src_ip": "198.51.100.88", "user": "svc-deploy", "method": "password_compromise"},
        "metadata": {"scenario": "scenario_2_credential_stuffing", "success_after_failure": True},
    })

    # ==========================================
    # SCENARIO 3: Authentication anomaly followed by Privilege Escalation
    # Target: jdoe | Source IP: 198.51.100.150
    # ==========================================
    s3_base = base_time + timedelta(minutes=18)
    # Auth event
    events.append({
        "timestamp": s3_base.isoformat(),
        "event_type": "authentication",
        "source": "vpn_gateway",
        "source_ip": "198.51.100.150",
        "destination_ip": "10.0.0.1",
        "username": "jdoe",
        "hostname": "internal-vpn-gw",
        "action": "vpn_connect",
        "status": "success",
        "severity": "medium",
        "message": "VPN connection established for jdoe from 198.51.100.150",
        "raw_event": {"user": "jdoe", "vpn_profile": "staff"},
        "metadata": {"scenario": "scenario_3_priv_esc"},
    })

    # Privilege escalation event
    events.append({
        "timestamp": (s3_base + timedelta(minutes=4)).isoformat(),
        "event_type": "privilege_change",
        "source": "auditd",
        "source_ip": "198.51.100.150",
        "destination_ip": "10.0.1.15",
        "username": "jdoe",
        "hostname": "core-api-server",
        "action": "sudo_command",
        "status": "success",
        "severity": "critical",
        "message": "USER=root COMMAND=/usr/sbin/usermod -aG sudo,wheel jdoe (elevated to root privileges)",
        "raw_event": {"caller": "jdoe", "target_role": "wheel", "elevation": "root"},
        "metadata": {"scenario": "scenario_3_priv_esc", "is_elevation": True},
    })

    # ==========================================
    # SCENARIO 4: Completely benign unrelated activity
    # User: backup_agent & mchen | Safe internal operations
    # ==========================================
    s4_base = base_time + timedelta(minutes=28)
    events.append({
        "timestamp": s4_base.isoformat(),
        "event_type": "system",
        "source": "cron_scheduler",
        "source_ip": "10.0.50.12",
        "destination_ip": "10.0.50.100",
        "username": "backup_agent",
        "hostname": "backup-srv-01",
        "action": "backup_cron_start",
        "status": "success",
        "severity": "low",
        "message": "Routine scheduled volume snapshot completed successfully",
        "raw_event": {"agent": "backup_agent", "job": "nightly_backup"},
        "metadata": {"scenario": "scenario_4_benign", "is_benign": True},
    })

    events.append({
        "timestamp": (s4_base + timedelta(minutes=5)).isoformat(),
        "event_type": "authentication",
        "source": "okta_sso",
        "source_ip": "10.0.2.14",
        "username": "mchen",
        "hostname": "mchen-laptop-macos",
        "action": "sso_login",
        "status": "success",
        "severity": "low",
        "message": "User mchen successfully authenticated via SSO with FIDO2 MFA token",
        "raw_event": {"user": "mchen", "auth_factor": "webauthn"},
        "metadata": {"scenario": "scenario_4_benign", "is_benign": True},
    })

    return events


def seed_demo_pipeline(db: Session, force_reset: bool = True) -> Dict[str, Any]:
    """Execute end-to-end Demo Seeding: Events -> Detection Engine -> Correlation Engine -> Incidents."""
    logger.info("Executing demo pipeline seed...")

    if force_reset:
        db.query(IncidentAuditLog).delete()
        db.query(AlertEvidence).delete()
        db.query(Alert).delete()
        db.query(Incident).delete()
        db.query(SecurityEvent).delete()
        db.commit()

    # 1. Ingest Security Events
    raw_events = generate_demo_events()
    saved_events = []
    for item in raw_events:
        evt = SecurityEvent(
            timestamp=datetime.fromisoformat(item["timestamp"]),
            event_type=item["event_type"],
            source=item["source"],
            source_ip=item.get("source_ip"),
            destination_ip=item.get("destination_ip"),
            source_port=item.get("source_port"),
            destination_port=item.get("destination_port"),
            username=item.get("username"),
            hostname=item.get("hostname"),
            action=item.get("action"),
            status=item.get("status", "unknown"),
            severity=item.get("severity", "medium"),
            message=item.get("message", ""),
            raw_event=item.get("raw_event", {}),
            event_metadata=item.get("metadata", {}),
        )
        db.add(evt)
        saved_events.append(evt)
    db.commit()

    # 2. Run Detection Engine
    det_summary = default_detection_engine.run_detection(db=db, time_window_minutes=120)

    # 3. Run Correlation Engine
    corr_summary = default_correlation_engine.run_correlation(
        db=db,
        time_window_minutes=120,
        force_recorrelate=False,
    )

    # 4. Fetch created incidents
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()

    return {
        "status": "success",
        "events_created": len(saved_events),
        "alerts_generated": det_summary.alerts_generated,
        "incidents_created": corr_summary.incidents_created,
        "incidents": [inc.to_dict(include_alerts=True) for inc in incidents],
    }
