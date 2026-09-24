"""Secure File Ingestion and Batch Importer Service.

Handles JSON and CSV security log imports with strict size limits, format validation,
safe parsing, and comprehensive error accounting.
"""

import csv
import io
import json
from typing import Any, Dict, List, Tuple
from fastapi import UploadFile
from sqlalchemy.orm import Session

from backend.app.core.errors import ValidationError
from backend.app.core.logging import logger
from backend.app.models.event import SecurityEvent
from backend.app.schemas.event import (
    EventImportSummary,
    EventImportErrorDetail,
    SecurityEventCreate,
)
from backend.app.services.normalizer import normalize_event_dict

# Security Constraints
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB maximum upload size
ALLOWED_EXTENSIONS = {".json", ".csv"}
ALLOWED_MIME_TYPES = {
    "application/json",
    "text/csv",
    "text/plain",
    "application/octet-stream",
    "text/x-csv",
    "application/vnd.ms-excel",
}


async def read_and_validate_upload(file: UploadFile) -> Tuple[bytes, str]:
    """Reads uploaded file content in memory with size bounds and extension verification."""
    filename = file.filename or "unknown"
    lower_name = filename.lower()

    # 1. Validate file extension
    matched_ext = next((ext for ext in ALLOWED_EXTENSIONS if lower_name.endswith(ext)), None)
    if not matched_ext:
        raise ValidationError(
            message=f"Unsupported file format for '{filename}'. Only .json and .csv files are supported.",
            details={"allowed_extensions": list(ALLOWED_EXTENSIONS)},
        )

    # 2. Read in chunks with strict size enforcement to prevent memory exhaustion
    contents = bytearray()
    chunk_size = 64 * 1024  # 64KB
    total_read = 0

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > MAX_UPLOAD_SIZE_BYTES:
            raise ValidationError(
                message=f"File exceeds maximum allowed upload size of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)}MB.",
                details={"max_size_bytes": MAX_UPLOAD_SIZE_BYTES, "read_bytes": total_read},
            )
        contents.extend(chunk)

    if len(contents) == 0:
        raise ValidationError(message="Uploaded file is empty.")

    return bytes(contents), matched_ext


def parse_raw_records(content: bytes, extension: str) -> List[Dict[str, Any]]:
    """Safely decodes and parses byte content into raw record dictionaries."""
    text_content = content.decode("utf-8-sig", errors="replace")

    if extension == ".json":
        try:
            parsed = json.loads(text_content)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                message="Malformed JSON file. Please ensure the file contains valid JSON syntax.",
                details={"line": exc.lineno, "column": exc.colno, "error": exc.msg},
            )

        if isinstance(parsed, dict):
            # Check if it wraps events list like {"events": [...]}
            if "events" in parsed and isinstance(parsed["events"], list):
                return parsed["events"]
            return [parsed]
        elif isinstance(parsed, list):
            return parsed
        else:
            raise ValidationError(
                message="JSON content must be an array of event objects or a single event object."
            )

    elif extension == ".csv":
        # CSV parsing with safety checks
        f = io.StringIO(text_content)
        try:
            # Sniff dialect or fall back to standard comma delimiter
            sample = text_content[:2048]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
            except Exception:
                dialect = csv.excel

            reader = csv.DictReader(f, dialect=dialect)
            if not reader.fieldnames:
                raise ValidationError(message="CSV file contains no column headers.")

            records: List[Dict[str, Any]] = []
            for row in reader:
                # Filter empty rows
                if any(v.strip() for v in row.values() if isinstance(v, str)):
                    records.append(dict(row))
            return records
        except csv.Error as exc:
            raise ValidationError(
                message="Malformed CSV file. Parsing failed.",
                details={"error": str(exc)},
            )

    raise ValidationError(message=f"Unsupported format: {extension}")


def process_and_persist_events(
    records: List[Dict[str, Any]],
    db: Session,
) -> EventImportSummary:
    """Normalizes, validates, and persists a batch of raw records in a safe transaction.

    Saves valid records, logs rejected records with reasons, and commits transaction safely.
    """
    imported_models: List[SecurityEvent] = []
    errors: List[EventImportErrorDetail] = []
    imported_ids: List[str] = []

    for index, raw_record in enumerate(records, start=1):
        if not isinstance(raw_record, dict):
            errors.append(
                EventImportErrorDetail(
                    record_index=index,
                    error="Record must be an object/dictionary",
                    raw_sample={"raw": str(raw_record)[:100]},
                )
            )
            continue

        try:
            # Normalize and validate via Pydantic
            normalized_event: SecurityEventCreate = normalize_event_dict(raw_record)

            # Map to SQLAlchemy model
            event_model = SecurityEvent(
                timestamp=normalized_event.timestamp,
                event_type=normalized_event.event_type,
                source=normalized_event.source,
                source_ip=normalized_event.source_ip,
                destination_ip=normalized_event.destination_ip,
                source_port=normalized_event.source_port,
                destination_port=normalized_event.destination_port,
                username=normalized_event.username,
                user_id=normalized_event.user_id,
                hostname=normalized_event.hostname,
                action=normalized_event.action,
                status=normalized_event.status,
                severity=normalized_event.severity,
                message=normalized_event.message,
                raw_event=normalized_event.raw_event,
                event_metadata=normalized_event.metadata,
            )
            imported_models.append(event_model)
        except Exception as exc:
            # Capture error without failing the entire batch
            err_msg = str(exc)
            field_name = None
            if "validation error" in err_msg.lower():
                # Extract first field if pydantic error
                field_name = err_msg.split("\n")[0]
            errors.append(
                EventImportErrorDetail(
                    record_index=index,
                    field=field_name,
                    error=err_msg,
                    raw_sample={k: str(v)[:80] for k, v in list(raw_record.items())[:5]},
                )
            )

    # Persist all valid models in a single transaction
    if imported_models:
        try:
            db.add_all(imported_models)
            db.commit()
            for m in imported_models:
                imported_ids.append(m.id)
            logger.info(
                f"Successfully ingested {len(imported_models)} security events into database"
            )
        except Exception as db_exc:
            db.rollback()
            logger.error(f"Database error during event batch persist: {str(db_exc)}")
            raise ValidationError(
                message="Failed to persist events to the database.",
                details={"database_error": str(db_exc)},
            )

    return EventImportSummary(
        total_records=len(records),
        imported_records=len(imported_ids),
        rejected_records=len(errors),
        errors=errors[:100],  # Limit returned error sample to 100 to prevent payload bloating
        sample_imported_ids=imported_ids[:10],
    )
