# SentinelOps AI — AI SOC Analyst & Incident Response Copilot

SentinelOps AI is a portfolio-grade, production-structured Security Operations (SOC) platform designed to ingest security telemetry, detect malicious and suspicious behavior using an isolated deterministic engine, correlate security alerts into structured incidents, and empower security analysts with an evidence-grounded investigation copilot powered by Google Gemini.

---

## Current Development Status

**Phase 2: Security Event Ingestion & Data Model (COMPLETED)**
* Phase 2 implements normalized security event schemas, PostgreSQL storage with JSONB and composite B-tree indexes, an intelligent multi-format normalizer supporting JSON and CSV telemetry logs, bounded file ingestion APIs, and a high-density SOC Event Explorer interface.

---

## Architectural Principles

1. **Modular Monolith:** Single unified repository avoiding microservice operational overhead and premature distributed architecture complexity.
2. **Deterministic Detection Independence:** Detection rules run as pure deterministic Python modules. Security alerts are generated independent of LLM uptime or latency.
3. **AI as an Investigation Copilot (Server-Side Only):** Gemini operates strictly on the backend as an analyst assistant (Phase 5). API keys are never exposed to the client.
4. **Untrusted Telemetry Handling:** All ingested logs and security events are treated as potentially malicious or malformed, enforcing strict schema validation and sanitization.
5. **Security-First Observability:** Built-in log sanitization redacts authorization tokens, bearer credentials, and API keys.

---

## Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python 3.11, FastAPI, Pydantic v2 | High-performance asynchronous REST API, request validation |
| **Database** | PostgreSQL 15, SQLAlchemy 2.0, Alembic | Relational storage for security events, incidents, and audit logs |
| **Normalizer** | Custom Python Engine with Dialect Sniffing | Normalizes heterogeneous JSON & CSV telemetry into canonical schemas |
| **Frontend** | React 19 / Vite / TypeScript, Tailwind CSS v4 | High-fidelity SOC dashboard and diagnostic console |
| **Testing** | Pytest, Pytest-Asyncio, HTTPX / TestClient | Backend API integration, validation, and security test coverage |
| **AI (Phase 5)** | Google Gemini API (`@google/genai` / Python SDK) | Evidence-grounded incident investigation copilot |

---

## Normalized SecurityEvent Data Model

Each ingested log event is mapped into a normalized PostgreSQL schema (`security_events` table):

| Field | Database Type | Description |
| :--- | :--- | :--- |
| `id` | `VARCHAR(36)` (PK) | UUID v4 event identifier |
| `timestamp` | `TIMESTAMPTZ` | UTC timestamp when the event occurred on the source asset (indexed) |
| `event_type` | `VARCHAR(64)` | High-level classification (`authentication`, `network`, `privilege_change`, `cloud_audit`, etc.) |
| `source` | `VARCHAR(64)` | Sensor or platform (`linux_auth`, `windows_event`, `okta_sso`, `palo_alto_fw`, etc.) |
| `source_ip` | `VARCHAR(45)` | Originating IPv4 or IPv6 address (indexed) |
| `destination_ip` | `VARCHAR(45)` | Target IPv4 or IPv6 address (indexed) |
| `source_port` | `INTEGER` | Source port (1-65535) |
| `destination_port` | `INTEGER` | Destination port (1-65535) |
| `username` | `VARCHAR(128)` | Subject username or actor account (indexed) |
| `user_id` | `VARCHAR(128)` | Subject UID, SID, or identity provider ID |
| `hostname` | `VARCHAR(128)` | Machine hostname or asset identifier (indexed) |
| `action` | `VARCHAR(64)` | Operation performed (`login`, `sudo`, `block`, `mfa_challenge`, etc.) |
| `status` | `VARCHAR(32)` | Outcome (`success`, `failure`, `blocked`, `denied`, `unknown`) |
| `severity` | `VARCHAR(32)` | Normalized severity (`critical`, `high`, `medium`, `low`, `info`) |
| `message` | `TEXT` | Human-readable log summary message |
| `raw_event` | `JSONB` | Full original unadulterated payload (preserves forensic fidelity) |
| `event_metadata` | `JSONB` | Unmapped contextual attributes, tags, headers, and enrichment |
| `created_at` | `TIMESTAMPTZ` | Ingestion timestamp into SentinelOps |

### Database Indexes

* Single-column B-tree indexes: `id`, `timestamp`, `event_type`, `source`, `source_ip`, `destination_ip`, `username`, `hostname`, `action`, `status`, `severity`.
* Analytical composite indexes for future detection rules:
  - `ix_security_events_user_time (username, timestamp)`: Fast brute-force credential abuse queries.
  - `ix_security_events_src_ip_time (source_ip, timestamp)`: Fast origin IP scanning & anomaly queries.
  - `ix_security_events_type_time (event_type, timestamp)`: High-speed temporal classification slices.
  - `ix_security_events_status_time (status, timestamp)`: Rapid failure/success sequence checks.

---

## Supported Telemetry Ingestion Formats

The ingestion engine accepts both JSON and CSV payloads. The normalizer automatically maps common vendor field aliases:

### 1. JSON Format Example
```json
[
  {
    "timestamp": "2026-09-24T10:01:15Z",
    "event_type": "authentication",
    "source": "linux_auth",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.1.15",
    "source_port": 49210,
    "destination_port": 22,
    "username": "root",
    "hostname": "prod-bastion-01",
    "action": "login",
    "status": "failure",
    "severity": "medium",
    "message": "Failed password for root from 198.51.100.42 port 49210 ssh2"
  }
]
```

### 2. CSV Format Example
```csv
timestamp,event_type,source,source_ip,destination_ip,source_port,destination_port,username,hostname,action,status,severity,message
2026-09-24T10:30:10Z,authentication,windows_event,198.51.100.101,10.0.1.100,52341,3389,Administrator,DC-PRIMARY-01,rdp_login,failure,medium,Failed RDP logon attempt
```

Supported alias mappings include:
- `timestamp`: `@timestamp`, `event_time`, `datetime`, `time`, `date`, `logged_at`
- `source_ip`: `src_ip`, `src`, `client_ip`, `remote_ip`, `origin_ip`, `ip`
- `username`: `user`, `account`, `actor`, `subject`, `user_name`, `target_user`
- `action`: `activity`, `operation`, `event`, `command`, `method`
- `status`: `outcome`, `result`, `state`, `verdict`

---

## Ingestion & Retrieval API Reference

### Ingestion Endpoints
* `POST /api/v1/events/import`: Multipart form upload supporting `.json` and `.csv` files (up to 10MB).
* `POST /api/v1/events/batch`: Ingest a JSON array of up to 5,000 log records directly in request body.
* `POST /api/v1/events`: Ingest a single validated event.

### Query & Analytics Endpoints
* `GET /api/v1/events`: Paginated event explorer query with filtering:
  - Query parameters: `page`, `page_size`, `search`, `severity`, `status`, `event_type`, `source`, `username`, `source_ip`, `destination_ip`, `start_time`, `end_time`.
* `GET /api/v1/events/{event_id}`: Retrieve individual event with raw payload and metadata.
* `GET /api/v1/events/stats/summary`: Aggregate counts by severity, outcome status, and top telemetry sources.

---

## Security Safeguards

1. **Upload Size Bounds:** 10MB chunked streaming prevents memory exhaustion and denial-of-service.
2. **Untrusted Data Isolation:** Malicious input strings (SQL injection fragments, HTML/script tags, directory traversal attempts) are stored as inert data without evaluation.
3. **Path Traversal Resistance:** Uploaded filenames are never written to the host filesystem.
4. **Log Sanitization:** Sensitive credentials (passwords, bearer tokens, API keys) are masked before logs are emitted.
5. **Partial Import Accounting:** Malformed rows in large logs are isolated with error details without dropping valid events.

---

## Automated Test Suite

SentinelOps AI maintains a comprehensive Pytest suite:

```bash
# Run the complete test suite
pytest backend/

# Run tests via npm script
npm run test:backend
```

Tests cover:
* Database persistence and Alembic migrations.
* Pydantic schema validation (timestamps, IPv4/IPv6, ports, severity normalization).
* JSON and CSV file ingestion and parser resilience.
* Multi-parameter query filtering and pagination.
* Security tests verifying SQL injection and path traversal resistance.

---

## Phase Roadmap

* [x] **Phase 1: Foundation & Architecture** (Completed)
* [x] **Phase 2: Event Ingestion & Data Model** (Completed)
* [ ] **Phase 3: Deterministic Detection Engine** (Brute-force, privilege escalation, rule execution)
* [ ] **Phase 4: Incident Correlation & Dashboard** (Alert aggregation, attack timelines)
* [ ] **Phase 5: Gemini Investigation Copilot** (Evidence-grounded summaries, hypothesis testing)
* [ ] **Phase 6: Case Management & Reports** (Status transitions, analyst audit trail, export)
* [ ] **Phase 7: Security Audit, Testing & Polish**
* [ ] **Phase 8: Deployment & Portfolio Release**
