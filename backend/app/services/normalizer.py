"""Security Telemetry Normalizer.

Transforms raw, heterogeneous security event inputs (JSON, CSV, Syslog, IdP, CloudTrail)
into structured, canonical SecurityEventCreate domain instances.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional, Tuple
from backend.app.schemas.event import SecurityEventCreate

# Canonical field aliases
FIELD_ALIASES: Dict[str, list[str]] = {
    "timestamp": ["timestamp", "@timestamp", "event_time", "datetime", "time", "date", "logged_at"],
    "event_type": ["event_type", "type", "category", "class", "log_type", "event_category"],
    "source": ["source", "log_source", "app", "system", "service", "sensor", "facility", "vendor"],
    "source_ip": ["source_ip", "src_ip", "src", "client_ip", "remote_ip", "origin_ip", "ip"],
    "destination_ip": ["destination_ip", "dest_ip", "dst_ip", "target_ip", "server_ip"],
    "source_port": ["source_port", "src_port", "client_port"],
    "destination_port": ["destination_port", "dest_port", "dst_port", "target_port"],
    "username": ["username", "user", "account", "actor", "subject", "user_name", "target_user"],
    "user_id": ["user_id", "uid", "account_id", "sub", "subject_id"],
    "hostname": ["hostname", "host", "device", "computer_name", "endpoint", "server"],
    "action": ["action", "activity", "operation", "event", "command", "method", "task"],
    "status": ["status", "outcome", "result", "state", "verdict", "decision"],
    "severity": ["severity", "level", "priority", "urgency"],
    "message": ["message", "msg", "description", "log", "detail", "details"],
}


def _find_field_value(record: Dict[str, Any], aliases: list[str]) -> Optional[Any]:
    """Search for matching alias in a record, case-insensitively."""
    # Fast direct check
    for alias in aliases:
        if alias in record and record[alias] is not None:
            return record[alias]

    # Case-insensitive search
    record_lower = {str(k).lower(): v for k, v in record.items()}
    for alias in aliases:
        if alias.lower() in record_lower and record_lower[alias.lower()] is not None:
            return record_lower[alias.lower()]

    return None


def _parse_raw_timestamp(val: Any) -> datetime:
    """Parse various timestamp representations into a timezone-aware UTC datetime."""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val

    if isinstance(val, (int, float)):
        # Epoch timestamp (check if seconds or milliseconds)
        if val > 1e11:  # Milliseconds
            return datetime.fromtimestamp(val / 1000, tz=timezone.utc)
        return datetime.fromtimestamp(val, tz=timezone.utc)

    if isinstance(val, str):
        val = val.strip()
        # Trailing Z handling
        if val.endswith("Z"):
            val = val[:-1] + "+00:00"

        # Try standard ISO format
        try:
            parsed = datetime.fromisoformat(val)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            pass

        # Try common log datetime formats
        common_formats = [
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
        ]
        for fmt in common_formats:
            try:
                parsed = datetime.strptime(val, fmt)
                if parsed.tzinfo is None:
                    # If format like "%b %d %H:%M:%S" lacks year, default to current year
                    if parsed.year == 1900:
                        parsed = parsed.replace(year=datetime.now(timezone.utc).year)
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue

    raise ValueError(f"Unable to parse timestamp from value: '{val}'")


def _parse_port(val: Any) -> Optional[int]:
    """Parse port into integer range 1-65535, or None."""
    if val is None or val == "":
        return None
    try:
        p = int(val)
        if 1 <= p <= 65535:
            return p
        raise ValueError(f"Port number {p} out of valid range (1-65535)")
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port value: '{val}'")


def normalize_event_dict(raw: Dict[str, Any]) -> SecurityEventCreate:
    """Normalizes a dictionary from JSON or CSV into a validated SecurityEventCreate model.

    Raises ValidationError or ValueError if required fields are missing or unparseable.
    """
    if not isinstance(raw, dict):
        raise ValueError("Event record must be a JSON object / dictionary")

    # 1. Extract and normalize Timestamp
    raw_ts = _find_field_value(raw, FIELD_ALIASES["timestamp"])
    if not raw_ts:
        raise ValueError("Missing required timestamp field")
    parsed_timestamp = _parse_raw_timestamp(raw_ts)

    # 2. Extract Event Type & Action
    event_type = _find_field_value(raw, FIELD_ALIASES["event_type"])
    action = _find_field_value(raw, FIELD_ALIASES["action"])
    if not action:
        # Fallback to action derived from event_type or generic action
        action = str(event_type) if event_type else "unknown_action"
    if not event_type:
        event_type = "general"

    # 3. Source sensor
    source = _find_field_value(raw, FIELD_ALIASES["source"])
    if not source:
        source = "generic_ingest"

    # 4. Status & Severity
    status = _find_field_value(raw, FIELD_ALIASES["status"]) or "unknown"
    severity = _find_field_value(raw, FIELD_ALIASES["severity"]) or "info"

    # 5. Network Fields
    source_ip = _find_field_value(raw, FIELD_ALIASES["source_ip"])
    destination_ip = _find_field_value(raw, FIELD_ALIASES["destination_ip"])
    source_port = _parse_port(_find_field_value(raw, FIELD_ALIASES["source_port"]))
    destination_port = _parse_port(_find_field_value(raw, FIELD_ALIASES["destination_port"]))

    # 6. Identity & Host
    username = _find_field_value(raw, FIELD_ALIASES["username"])
    user_id = _find_field_value(raw, FIELD_ALIASES["user_id"])
    hostname = _find_field_value(raw, FIELD_ALIASES["hostname"])

    # 7. Message
    message = _find_field_value(raw, FIELD_ALIASES["message"])
    if not message:
        # Construct summary message from action, username, and status
        actor = f" by user '{username}'" if username else ""
        src = f" from {source_ip}" if source_ip else ""
        message = f"Event '{action}' ({status}){actor}{src}"

    # 8. Segregate Extra Metadata (all keys not explicitly mapped)
    all_alias_keys = {
        alias.lower()
        for aliases in FIELD_ALIASES.values()
        for alias in aliases
    }
    extracted_metadata: Dict[str, Any] = {}
    for k, v in raw.items():
        if str(k).lower() not in all_alias_keys and v not in (None, ""):
            extracted_metadata[str(k)] = v

    # Pass in raw_event preserving the full original input record
    event_payload = {
        "timestamp": parsed_timestamp,
        "event_type": str(event_type).strip()[:64],
        "source": str(source).strip()[:64],
        "source_ip": str(source_ip).strip() if source_ip else None,
        "destination_ip": str(destination_ip).strip() if destination_ip else None,
        "source_port": source_port,
        "destination_port": destination_port,
        "username": str(username).strip()[:128] if username else None,
        "user_id": str(user_id).strip()[:128] if user_id else None,
        "hostname": str(hostname).strip()[:128] if hostname else None,
        "action": str(action).strip()[:64],
        "status": str(status).strip()[:32],
        "severity": str(severity).strip()[:32],
        "message": str(message).strip()[:4096] if message else None,
        "raw_event": raw,
        "metadata": extracted_metadata,
    }

    # Pydantic validation handles IP validation, severity/status normalization, and bounds
    return SecurityEventCreate(**event_payload)
