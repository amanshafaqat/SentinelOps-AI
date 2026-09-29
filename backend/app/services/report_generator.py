"""Evidence-Grounded Investigation Report Generator Service.

Synthesizes deterministic incident telemetry, alert correlation rationale,
traceable security events, chronological timelines, analyst notes, and
validated AI Copilot findings into structured JSON and print-ready HTML reports.
"""

from datetime import datetime, timezone
import html
import re
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import select

from backend.app.models.incident import Incident, IncidentAuditLog, IncidentAIAnalysis, CaseNote
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent


class ReportGeneratorService:
    """Generates structured, traceable, and evidence-grounded incident reports."""

    @classmethod
    def generate_report(
        cls,
        db: Session,
        incident: Incident,
        report_type: str = "investigation_summary",
        custom_title: Optional[str] = None,
        generated_by: str = "soc_analyst",
        include_ai_analysis: bool = True,
    ) -> Dict[str, Any]:
        """Builds structured report content and rendered HTML from actual incident data."""
        now_utc = datetime.now(timezone.utc)
        report_title = custom_title.strip() if custom_title and custom_title.strip() else f"Investigation Report: {incident.title}"

        # 1. Gather Alerts & Traceable Evidence
        alerts = (
            db.scalars(
                select(Alert)
                .options(joinedload(Alert.evidence))
                .where(Alert.incident_id == incident.id)
                .order_by(Alert.detected_at.asc())
            )
            .unique()
            .all()
        )

        alert_ids = [a.id for a in alerts]
        evidence_rows = (
            db.scalars(
                select(AlertEvidence)
                .where(AlertEvidence.alert_id.in_(alert_ids))
            ).all()
        ) if alert_ids else []

        event_ids = list({e.event_id for e in evidence_rows})
        events_map: Dict[str, SecurityEvent] = {}
        if event_ids:
            events_list = db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.id.in_(event_ids))
                .order_by(SecurityEvent.timestamp.asc())
            ).all()
            events_map = {ev.id: ev for ev in events_list}

        # Build evidence traceability items (Incident -> Alert -> Event)
        traceability_list: List[Dict[str, Any]] = []
        for alert in alerts:
            alert_evidence_items: List[Dict[str, Any]] = []
            for ev in alert.evidence:
                ev_obj = events_map.get(ev.event_id)
                if ev_obj:
                    alert_evidence_items.append({
                        "event_id": ev_obj.id,
                        "timestamp": ev_obj.timestamp.isoformat() if ev_obj.timestamp else "N/A",
                        "event_type": ev_obj.event_type,
                        "source": ev_obj.source,
                        "source_ip": ev_obj.source_ip or "N/A",
                        "destination_ip": ev_obj.destination_ip or "N/A",
                        "username": ev_obj.username or "N/A",
                        "hostname": ev_obj.hostname or "N/A",
                        "action": ev_obj.action or "N/A",
                        "status": ev_obj.status,
                        "severity": ev_obj.severity,
                        "message": cls._sanitize(ev_obj.message),
                        "evidence_role": ev.evidence_role or "supporting",
                    })

            traceability_list.append({
                "alert_id": alert.id,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "title": alert.title,
                "description": cls._sanitize(alert.description),
                "severity": alert.severity,
                "status": alert.status,
                "detected_at": alert.detected_at.isoformat() if alert.detected_at else "N/A",
                "affected_user": alert.affected_user or "N/A",
                "affected_ip": alert.affected_ip or "N/A",
                "evidence_count": len(alert_evidence_items),
                "supporting_events": alert_evidence_items,
            })

        # 2. Gather Chronological Timeline
        timeline_items: List[Dict[str, Any]] = []
        seen_events: set = set()
        for t_alert in traceability_list:
            for ev_item in t_alert["supporting_events"]:
                if ev_item["event_id"] not in seen_events:
                    seen_events.add(ev_item["event_id"])
                    timeline_items.append({
                        "type": "EVENT",
                        "timestamp": ev_item["timestamp"],
                        "title": f"Telemetry Event: {ev_item['event_type'].upper()}",
                        "description": ev_item["message"],
                        "entity": ev_item["username"] if ev_item["username"] != "N/A" else ev_item["source_ip"],
                        "severity": ev_item["severity"],
                    })

        for alert in alerts:
            timeline_items.append({
                "type": "ALERT",
                "timestamp": alert.detected_at.isoformat() if alert.detected_at else "N/A",
                "title": f"Detection Alert: {alert.rule_name} [{alert.rule_id}]",
                "description": cls._sanitize(alert.description),
                "entity": alert.affected_user or alert.affected_ip or "N/A",
                "severity": alert.severity,
            })

        audit_logs = (
            db.scalars(
                select(IncidentAuditLog)
                .where(IncidentAuditLog.incident_id == incident.id)
                .order_by(IncidentAuditLog.created_at.asc())
            ).all()
        )
        for log in audit_logs:
            timeline_items.append({
                "type": "INCIDENT ACTION",
                "timestamp": log.created_at.isoformat() if log.created_at else "N/A",
                "title": f"Incident Action: {log.action.replace('_', ' ').title()}",
                "description": log.notes or f"Value changed from '{log.previous_value}' to '{log.new_value}'",
                "entity": log.actor,
                "severity": incident.severity,
            })

        timeline_items.sort(key=lambda x: x.get("timestamp", ""))

        # 3. Gather Analyst Notes
        notes = (
            db.scalars(
                select(CaseNote)
                .where(CaseNote.incident_id == incident.id)
                .order_by(CaseNote.created_at.asc())
            ).all()
        )
        notes_data = [
            {
                "id": n.id,
                "author": n.author,
                "content": cls._sanitize(n.content),
                "created_at": n.created_at.isoformat() if n.created_at else "N/A",
            }
            for n in notes
        ]

        # 4. Gather Latest AI Analysis
        ai_data: Optional[Dict[str, Any]] = None
        if include_ai_analysis:
            ai_record = (
                db.scalars(
                    select(IncidentAIAnalysis)
                    .where(
                        IncidentAIAnalysis.incident_id == incident.id,
                        IncidentAIAnalysis.analysis_type == "incident_summary",
                    )
                    .order_by(IncidentAIAnalysis.created_at.desc())
                ).first()
            )
            if ai_record:
                ai_data = {
                    "model_used": ai_record.model,
                    "created_at": ai_record.created_at.isoformat() if ai_record.created_at else "N/A",
                    "summary": cls._sanitize(ai_record.summary),
                    "observed_facts": [cls._sanitize(f) for f in ai_record.observed_facts or []],
                    "potential_explanations": [cls._sanitize(p) for p in ai_record.potential_explanations or []],
                    "evidence_references": ai_record.evidence_references or [],
                    "missing_information": [cls._sanitize(m) for m in ai_record.missing_information or []],
                    "recommended_next_steps": [cls._sanitize(s) for s in ai_record.recommended_next_steps or []],
                    "uncertainty_assessment": cls._sanitize(ai_record.uncertainty_assessment or ""),
                    "evidence_truncated": ai_record.evidence_truncated,
                    "disclaimer": "AI-generated analysis is advisory and must be reviewed by a human analyst. Deterministic telemetry remains the primary source of truth.",
                }

        # 5. Deterministic Executive Summary
        executive_summary = cls._build_executive_summary(incident, alerts, len(events_map), ai_data)

        # 6. Detection Summary
        rule_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            rule_counts[a.rule_name] = rule_counts.get(a.rule_name, 0) + 1
            sev = a.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        detection_summary = {
            "total_alerts": len(alerts),
            "severity_distribution": severity_counts,
            "rules_triggered": [{"rule_name": k, "count": v} for k, v in rule_counts.items()],
            "correlation_reasons": [cls._sanitize(r) for r in incident.correlation_reasons or []],
        }

        # 7. Assembled Structured Content
        content: Dict[str, Any] = {
            "header": {
                "organization": "SentinelOps AI",
                "document_title": "Security Incident Investigation Report",
                "report_title": report_title,
                "report_type": report_type,
                "generated_by": generated_by,
                "generated_at": now_utc.isoformat(),
            },
            "incident_info": {
                "incident_id": incident.id,
                "title": incident.title,
                "severity": incident.severity.upper(),
                "status": incident.status.upper(),
                "first_seen": incident.first_seen.isoformat() if incident.first_seen else "N/A",
                "last_seen": incident.last_seen.isoformat() if incident.last_seen else "N/A",
                "created_at": incident.created_at.isoformat() if incident.created_at else "N/A",
                "updated_at": incident.updated_at.isoformat() if incident.updated_at else "N/A",
            },
            "affected_entities": {
                "users": incident.affected_users or [],
                "ips": incident.affected_ips or [],
                "hostnames": incident.affected_hostnames or [],
            },
            "executive_summary": executive_summary,
            "detection_summary": detection_summary,
            "evidence_traceability": traceability_list,
            "timeline": timeline_items,
            "ai_assisted_analysis": ai_data,
            "analyst_notes": notes_data,
            "investigation_history": [
                {
                    "action": log.action,
                    "actor": log.actor,
                    "previous_value": log.previous_value,
                    "new_value": log.new_value,
                    "notes": log.notes,
                    "timestamp": log.created_at.isoformat() if log.created_at else "N/A",
                }
                for log in audit_logs
            ],
            "current_status": {
                "status": incident.status.upper(),
                "severity": incident.severity.upper(),
            },
        }

        # 8. Render Print-Ready Standalone HTML
        rendered_html = cls._render_html_report(content)

        metadata_info: Dict[str, Any] = {
            "alert_count": len(alerts),
            "event_count": len(events_map),
            "note_count": len(notes_data),
            "history_count": len(audit_logs),
            "has_ai_analysis": ai_data is not None,
            "generated_by": generated_by,
            "version": 1,
        }

        return {
            "title": report_title,
            "summary": executive_summary,
            "content": content,
            "rendered_html": rendered_html,
            "metadata_info": metadata_info,
        }

    @classmethod
    def _build_executive_summary(
        cls,
        incident: Incident,
        alerts: List[Alert],
        event_count: int,
        ai_data: Optional[Dict[str, Any]],
    ) -> str:
        """Constructs an evidence-grounded summary without hallucination."""
        first = incident.first_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.first_seen else "N/A"
        last = incident.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.last_seen else "N/A"
        users_str = ", ".join(incident.affected_users) if incident.affected_users else "none observed"
        ips_str = ", ".join(incident.affected_ips) if incident.affected_ips else "none observed"

        rules_list = list({a.rule_name for a in alerts})
        rules_str = ", ".join(rules_list) if rules_list else "correlated rules"

        summary = (
            f"Between {first} and {last}, SentinelOps correlated {len(alerts)} security detection alert(s) "
            f"supported by {event_count} telemetry event(s) into incident '{incident.title}' at {incident.severity.upper()} severity. "
            f"Observed targeted identities include: {users_str}; associated network origins include: {ips_str}. "
            f"Deterministic detection rules triggered: {rules_str}. "
            f"Current case status is {incident.status.upper()}."
        )

        if ai_data and ai_data.get("summary"):
            summary += f"\n\nAI Forensic Perspective (Advisory): {ai_data['summary']}"

        return summary

    @classmethod
    def _sanitize(cls, val: Optional[str]) -> str:
        """Removes sensitive keys, JWT tokens, and cleans text."""
        if not val:
            return ""
        s = str(val)
        # Redact potential keys and tokens
        s = re.sub(r"AIza[0-9A-Za-z-_]{35}", "[REDACTED_API_KEY]", s)
        s = re.sub(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", "[REDACTED_JWT]", s)
        return s

    @classmethod
    def _escape(cls, val: Any) -> str:
        """Escapes string for safe HTML inclusion."""
        return html.escape(str(val) if val is not None else "")

    @classmethod
    def _render_html_report(cls, content: Dict[str, Any]) -> str:
        """Produces a beautiful, self-contained HTML document with print styling."""
        header = content["header"]
        inc = content["incident_info"]
        ents = content["affected_entities"]
        exec_sum = content["executive_summary"]
        det = content["detection_summary"]
        traceability = content["evidence_traceability"]
        timeline = content["timeline"]
        ai = content["ai_assisted_analysis"]
        notes = content["analyst_notes"]
        history = content["investigation_history"]

        # Precompute history rows to avoid nested f-string backslash escaping
        history_rows = []
        for h in history:
            prev_val = h.get("previous_value")
            new_val = h.get("new_value")
            transition_str = f"{prev_val} &rarr; {new_val}" if prev_val or new_val else "Action recorded"
            details = h.get("notes") or transition_str
            ts = cls._escape(h.get("timestamp", "")[:19])
            act = cls._escape(h.get("action", ""))
            actor_str = cls._escape(h.get("actor", ""))
            det_str = cls._escape(details)
            history_rows.append(
                f"<tr><td style='font-family: monospace; font-size: 11px;'>{ts}</td>"
                f"<td style='font-family: monospace;'>{act}</td>"
                f"<td>{actor_str}</td>"
                f"<td>{det_str}</td></tr>"
            )
        history_table_rows = "".join(history_rows) if history_rows else "<tr><td colspan='4' style='font-style: italic; color: #64748b;'>No activity entries recorded.</td></tr>"

        # Badges
        sev_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#0284c7",
            "LOW": "#64748b",
        }.get(inc["severity"], "#64748b")

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{cls._escape(header['report_title'])} - SentinelOps AI</title>
  <style>
    @page {{
      size: A4;
      margin: 1.5cm;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      color: #1e293b;
      background: #ffffff;
      margin: 0;
      padding: 24px;
    }}
    .report-container {{
      max-width: 900px;
      margin: 0 auto;
    }}
    .header-banner {{
      border-bottom: 2px solid #0f172a;
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }}
    .brand-title {{
      font-size: 20px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.5px;
      margin: 0;
    }}
    .brand-sub {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #64748b;
      margin-top: 2px;
      font-weight: 600;
    }}
    .meta-box {{
      text-align: right;
      font-size: 12px;
      color: #475569;
    }}
    .meta-box span {{
      font-weight: 600;
    }}
    .report-title {{
      font-size: 22px;
      font-weight: 700;
      color: #0f172a;
      margin: 16px 0 8px 0;
    }}
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 700;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-family: monospace;
    }}
    .badge-sev {{
      background: {sev_color};
      color: #ffffff;
    }}
    .badge-status {{
      background: #e2e8f0;
      color: #334155;
      border: 1px solid #cbd5e1;
    }}
    .section {{
      margin-bottom: 28px;
      page-break-inside: avoid;
    }}
    .section-title {{
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: #0f172a;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 6px;
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }}
    .info-card {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 12px 14px;
      font-size: 12px;
    }}
    .info-row {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 6px;
    }}
    .info-row:last-child {{
      margin-bottom: 0;
    }}
    .info-label {{
      color: #64748b;
      font-weight: 500;
    }}
    .info-value {{
      font-weight: 600;
      color: #1e293b;
      font-family: monospace;
    }}
    .summary-text {{
      background: #f1f5f9;
      border-left: 4px solid #0284c7;
      padding: 12px 16px;
      font-size: 13px;
      color: #1e293b;
      border-radius: 0 6px 6px 0;
      line-height: 1.6;
      white-space: pre-wrap;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-top: 8px;
    }}
    th {{
      background: #f8fafc;
      color: #475569;
      font-weight: 600;
      text-align: left;
      padding: 8px 10px;
      border-bottom: 2px solid #cbd5e1;
    }}
    td {{
      padding: 8px 10px;
      border-bottom: 1px solid #e2e8f0;
      vertical-align: top;
    }}
    tr:nth-child(even) {{
      background: #f8fafc;
    }}
    .ai-box {{
      background: #fbfbfe;
      border: 1px solid #c7d2fe;
      border-left: 4px solid #6366f1;
      border-radius: 0 6px 6px 0;
      padding: 14px 16px;
      font-size: 12px;
    }}
    .ai-disclaimer {{
      font-size: 10px;
      color: #6366f1;
      font-family: monospace;
      font-weight: 600;
      margin-top: 10px;
      border-top: 1px dashed #c7d2fe;
      padding-top: 8px;
    }}
    .evidence-block {{
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 12px;
      font-size: 12px;
    }}
    .note-card {{
      background: #f8fafc;
      border-left: 3px solid #0f172a;
      padding: 10px 14px;
      margin-bottom: 8px;
      font-size: 12px;
    }}
    .note-meta {{
      font-size: 11px;
      color: #64748b;
      margin-bottom: 4px;
      font-weight: 600;
    }}
    .footer-note {{
      margin-top: 40px;
      border-top: 1px solid #cbd5e1;
      padding-top: 12px;
      font-size: 10px;
      color: #94a3b8;
      display: flex;
      justify-content: space-between;
    }}
    @media print {{
      body {{
        padding: 0;
      }}
      .no-print {{
        display: none !important;
      }}
    }}
  </style>
</head>
<body>
  <div class="report-container">
    <!-- Header Banner -->
    <div class="header-banner">
      <div>
        <h1 class="brand-title">SENTINELOPS AI</h1>
        <div class="brand-sub">Security Incident Investigation Report</div>
      </div>
      <div class="meta-box">
        <div>Generated: <span>{cls._escape(header['generated_at'][:19])} UTC</span></div>
        <div>Author: <span>{cls._escape(header['generated_by'])}</span></div>
        <div>Classification: <span>CONFIDENTIAL // SOC CASE</span></div>
      </div>
    </div>

    <!-- Title & Status -->
    <div style="margin-bottom: 20px;">
      <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 6px;">
        <span class="badge badge-sev">{cls._escape(inc['severity'])}</span>
        <span class="badge badge-status">STATUS: {cls._escape(inc['status'])}</span>
        <span style="font-size: 11px; color: #64748b; font-family: monospace;">UUID: {cls._escape(inc['incident_id'])}</span>
      </div>
      <h2 class="report-title">{cls._escape(inc['title'])}</h2>
    </div>

    <!-- Incident Info & Affected Entities Grid -->
    <div class="section">
      <div class="grid-2">
        <div class="info-card">
          <div class="info-row"><span class="info-label">First Seen:</span><span class="info-value">{cls._escape(inc['first_seen'])}</span></div>
          <div class="info-row"><span class="info-label">Last Seen:</span><span class="info-value">{cls._escape(inc['last_seen'])}</span></div>
          <div class="info-row"><span class="info-label">Incident Created:</span><span class="info-value">{cls._escape(inc['created_at'])}</span></div>
          <div class="info-row"><span class="info-label">Total Alerts:</span><span class="info-value">{cls._escape(det['total_alerts'])}</span></div>
        </div>
        <div class="info-card">
          <div class="info-row"><span class="info-label">Targeted Users:</span><span class="info-value">{cls._escape(", ".join(ents['users']) if ents['users'] else "None")}</span></div>
          <div class="info-row"><span class="info-label">Associated IPs:</span><span class="info-value">{cls._escape(", ".join(ents['ips']) if ents['ips'] else "None")}</span></div>
          <div class="info-row"><span class="info-label">Affected Hosts:</span><span class="info-value">{cls._escape(", ".join(ents['hostnames']) if ents['hostnames'] else "None")}</span></div>
          <div class="info-row"><span class="info-label">Report Type:</span><span class="info-value">{cls._escape(header['report_type'])}</span></div>
        </div>
      </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
      <div class="section-title">1. Executive Summary</div>
      <div class="summary-text">{cls._escape(exec_sum)}</div>
    </div>

    <!-- Detection Summary & Correlation Reasons -->
    <div class="section">
      <div class="section-title">2. Detection &amp; Correlation Summary</div>
      <table>
        <thead>
          <tr>
            <th>Detection Rule Triggered</th>
            <th style="width: 80px; text-align: right;">Alerts</th>
          </tr>
        </thead>
        <tbody>
          {"".join(f"<tr><td><strong>{cls._escape(r['rule_name'])}</strong></td><td style='text-align: right; font-family: monospace;'>{r['count']}</td></tr>" for r in det['rules_triggered'])}
        </tbody>
      </table>
      <div style="margin-top: 12px; font-size: 12px;">
        <strong>Explainable Correlation Rationale:</strong>
        <ul style="margin-top: 4px; padding-left: 20px; color: #475569;">
          {"".join(f"<li>{cls._escape(reason)}</li>" for reason in det['correlation_reasons'])}
        </ul>
      </div>
    </div>

    <!-- AI-Assisted Analysis Section (if present) -->
    {cls._render_ai_section(ai) if ai else ""}

    <!-- Evidence Traceability -->
    <div class="section">
      <div class="section-title">3. Traceable Evidence (Incident &rarr; Alert &rarr; Telemetry Events)</div>
      {"".join(cls._render_alert_trace(a) for a in traceability)}
    </div>

    <!-- Chronological Timeline -->
    <div class="section">
      <div class="section-title">4. Chronological Investigation Timeline</div>
      <table>
        <thead>
          <tr>
            <th style="width: 140px;">Timestamp</th>
            <th style="width: 110px;">Type</th>
            <th>Activity Description</th>
            <th style="width: 120px;">Entity / Actor</th>
          </tr>
        </thead>
        <tbody>
          {"".join(f"<tr><td style='font-family: monospace; font-size: 11px;'>{cls._escape(t['timestamp'][:19])}</td><td><span class='badge' style='background: #e2e8f0; color: #334155;'>{cls._escape(t['type'])}</span></td><td><strong>{cls._escape(t['title'])}</strong><br><span style='color: #64748b;'>{cls._escape(t['description'])}</span></td><td style='font-family: monospace; font-size: 11px;'>{cls._escape(t.get('entity', 'N/A'))}</td></tr>" for t in timeline[:40])}
        </tbody>
      </table>
    </div>

    <!-- Analyst Notes -->
    <div class="section">
      <div class="section-title">5. Analyst Investigation Notes ({len(notes)})</div>
      {"".join(f"<div class='note-card'><div class='note-meta'>Author: {cls._escape(n['author'])} &bull; {cls._escape(n['created_at'][:19])} UTC</div><div>{cls._escape(n['content'])}</div></div>" for n in notes) if notes else "<p style='font-size: 12px; color: #64748b; font-style: italic;'>No analyst investigation notes recorded for this case.</p>"}
    </div>

    <!-- Case Activities / Audit History -->
    <div class="section">
      <div class="section-title">6. Case History &amp; Audit Log ({len(history)})</div>
      <table>
        <thead>
          <tr>
            <th style="width: 140px;">Timestamp</th>
            <th style="width: 130px;">Action</th>
            <th style="width: 110px;">Actor</th>
            <th>Details / Notes</th>
          </tr>
        </thead>
        <tbody>
          {history_table_rows}
        </tbody>
      </table>
    </div>

    <!-- Footer -->
    <div class="footer-note">
      <div>SentinelOps AI &bull; Autonomous Detection &bull; Grounded Forensics</div>
      <div>Evidence-Grounded Report &bull; Page 1</div>
    </div>
  </div>
</body>
</html>"""
        return html_out

    @classmethod
    def _render_ai_section(cls, ai: Dict[str, Any]) -> str:
        """Renders AI section with clear advisory framing."""
        facts_html = "".join(f"<li>{cls._escape(f)}</li>" for f in ai.get("observed_facts", []))
        hypos_html = "".join(f"<li>{cls._escape(p)}</li>" for p in ai.get("potential_explanations", []))
        steps_html = "".join(f"<li>{cls._escape(s)}</li>" for s in ai.get("recommended_next_steps", []))
        missing_html = "".join(f"<li>{cls._escape(m)}</li>" for m in ai.get("missing_information", []))

        return f"""
    <div class="section">
      <div class="section-title" style="color: #4f46e5; border-color: #c7d2fe;">
        <span>AI-Assisted Investigation Findings</span>
        <span class="badge" style="background: #4f46e5; color: #fff;">Advisory Only &bull; Model: {cls._escape(ai['model_used'])}</span>
      </div>
      <div class="ai-box">
        <p style="margin-top: 0; font-size: 13px; font-weight: 500;">{cls._escape(ai['summary'])}</p>
        <div class="grid-2" style="margin-top: 12px;">
          <div>
            <strong style="color: #059669;">Observed Facts (Directly Corroborated):</strong>
            <ul style="padding-left: 20px; margin-top: 4px;">{facts_html}</ul>
          </div>
          <div>
            <strong style="color: #d97706;">Potential Explanations (Hypotheses):</strong>
            <ul style="padding-left: 20px; margin-top: 4px;">{hypos_html}</ul>
          </div>
        </div>
        <div class="grid-2" style="margin-top: 12px;">
          <div>
            <strong style="color: #7c3aed;">Missing Information &amp; Telemetry Gaps:</strong>
            <ul style="padding-left: 20px; margin-top: 4px;">{missing_html if missing_html else "<li>None reported</li>"}</ul>
          </div>
          <div>
            <strong style="color: #4f46e5;">Recommended Analyst Next Steps:</strong>
            <ol style="padding-left: 20px; margin-top: 4px;">{steps_html if steps_html else "<li>None reported</li>"}</ol>
          </div>
        </div>
        <div style="margin-top: 10px;">
          <strong>Confidence &amp; Uncertainty Assessment:</strong>
          <p style="margin: 4px 0 0 0; color: #475569;">{cls._escape(ai.get('uncertainty_assessment', 'Evaluated against bounded incident telemetry.'))}</p>
        </div>
        <div class="ai-disclaimer">
          {cls._escape(ai['disclaimer'])}
        </div>
      </div>
    </div>
"""

    @classmethod
    def _render_alert_trace(cls, alert: Dict[str, Any]) -> str:
        """Renders an alert and its linked supporting events."""
        events = alert.get("supporting_events", [])
        events_rows = "".join(
            f"<tr>"
            f"<td style='font-family: monospace; font-size: 10px;'>{cls._escape(ev['timestamp'][:19])}</td>"
            f"<td><span class='badge' style='background: #e0f2fe; color: #0369a1;'>{cls._escape(ev['event_type'])}</span></td>"
            f"<td style='font-family: monospace; font-size: 11px;'>{cls._escape(ev['source_ip'])} &rarr; {cls._escape(ev['destination_ip'])}</td>"
            f"<td style='font-family: monospace;'>{cls._escape(ev['username'])}</td>"
            f"<td><span class='badge' style='background: {'#fef2f2' if ev['status'] == 'failure' else '#f0fdf4'}; color: {'#b91c1c' if ev['status'] == 'failure' else '#15803d'};'>{cls._escape(ev['status'])}</span></td>"
            f"<td style='font-size: 11px;'>{cls._escape(ev['message'][:100])}</td>"
            f"</tr>"
            for ev in events
        )

        return f"""
      <div class="evidence-block">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
          <div>
            <span class="badge" style="background: #0f172a; color: #fff;">ALERT {cls._escape(alert['rule_id'])}</span>
            <strong style="margin-left: 6px;">{cls._escape(alert['title'])}</strong>
          </div>
          <span class="badge badge-sev" style="background: {'#ef4444' if alert['severity'] == 'critical' else '#f97316' if alert['severity'] == 'high' else '#0284c7'};">{cls._escape(alert['severity'])}</span>
        </div>
        <p style="margin: 4px 0 8px 0; color: #475569; font-size: 12px;">{cls._escape(alert['description'])}</p>
        {f'<table><thead><tr><th>Timestamp</th><th>Event Type</th><th>Network Flow</th><th>User</th><th>Status</th><th>Message</th></tr></thead><tbody>{events_rows}</tbody></table>' if events else '<p style="font-size: 11px; color: #64748b; font-style: italic;">No specific supporting raw events linked.</p>'}
      </div>
"""
