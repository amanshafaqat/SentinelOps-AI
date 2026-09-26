# SentinelOps AI — AI SOC Analyst & Incident Response Copilot

SentinelOps AI is a portfolio-grade, production-structured Security Operations (SOC) platform designed to ingest security telemetry, detect malicious and suspicious behavior using an isolated deterministic detection engine, correlate security alerts into structured incidents, and empower security analysts with an evidence-grounded investigation copilot powered by Google Gemini.

---

## Current Development Status

**Phase 3: Deterministic Security Detection Engine (COMPLETED)**
* Phase 3 introduces a modular, testable deterministic detection engine implementing Rules 001 through 005.
* Introduces PostgreSQL `Alert` and `AlertEvidence` models linked via foreign keys to immutable `SecurityEvent` records.
* Provides deterministic cryptographic deduplication (`dedup_key`), detection execution API (`POST /api/v1/detection/run`), alert query/stats APIs (`/api/v1/alerts`), and an interactive Frontend Alerts Explorer.
* **Important:** Detection logic operates 100% independently of Google Gemini or LLMs. Gemini is introduced in Phase 5 strictly as a server-side investigation copilot.

---

## Architectural Principles

1. **Modular Monolith:** Single unified repository avoiding microservice operational overhead and premature distributed architecture complexity.
2. **Deterministic Detection Independence:** Detection rules run as pure deterministic Python modules. Security alerts are generated independent of LLM uptime, hallucinations, or latency.
3. **Evidence Grounding (Source of Truth):** Every generated alert is bound to immutable `SecurityEvent` records. The AI copilot will reason over verified evidence rather than fabricating events.
4. **AI as an Investigation Copilot (Server-Side Only):** Gemini operates strictly on the backend as an analyst assistant (Phase 5). API keys are never exposed to the client.
5. **Untrusted Telemetry Handling:** All ingested logs and security events are treated as potentially malicious or malformed, enforcing strict schema validation and sanitization.
6. **Security-First Observability:** Built-in log sanitization redacts authorization tokens, bearer credentials, and API keys.

---

## Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python 3.11, FastAPI, Pydantic v2 | High-performance asynchronous REST API, request validation |
| **Database** | PostgreSQL 15, SQLAlchemy 2.0, Alembic | Relational storage for security events, alerts, and evidence |
| **Detection** | Modular Deterministic Engine (`DetectionEngine`) | Rules 001–005, sliding windows, deterministic deduplication |
| **Normalizer** | Custom Python Engine with Dialect Sniffing | Normalizes heterogeneous JSON & CSV telemetry into canonical schemas |
| **Frontend** | React 19 / Vite / TypeScript, Tailwind CSS v4 | High-fidelity SOC alerts queue, event explorer, and diagnostic console |
| **Testing** | Pytest, Pytest-Asyncio, HTTPX / TestClient | Backend API integration, validation, and security test coverage (63 tests) |
| **AI (Phase 5)**| Google Gemini API (`@google/genai` / Python SDK) | Evidence-grounded incident investigation copilot |

---

## Detection Engine Architecture

The detection engine (`backend/app/detection/`) is designed with modularity, testability, and evidence traceability:

```
Security Events (PostgreSQL)
       │
       ▼
DetectionContext (Chronological Telemetry + Decoupled Config)
       │
       ├──► RULE-001 (Brute Force Sliding Window)
       ├──► RULE-002 (Success After Repeated Failures)
       ├──► RULE-003 (Suspicious Privilege / Role Modification)
       ├──► RULE-004 (Unusual Multi-Source Auth Pattern)
       └──► RULE-005 (Configured Demo Threat Indicator Match)
       │
       ▼
DetectionResult Candidates
       │
       ▼
Deterministic Deduplication Engine (Cryptographic Signature Check)
       │
       ├──► New Alerts ────► Persisted to PostgreSQL (Alert + AlertEvidence)
       └──► Existing ──────► Suppressed & Counted as Deduplicated
```

### Core Components
* **`DetectionRule` (ABC):** Abstract base class encapsulating rule identification, default severity, evaluation logic, and evidence reference generation.
* **`DetectionContext`:** Container providing chronologically sorted `SecurityEvent` records and configurable detection parameters.
* **`DetectionResult`:** Standardized candidate alert emitted by a rule containing target entity, severity, narrative description, evidence references, and deduplication signature.
* **`DetectionEngine`:** Coordinates rule execution, database transactions, and deterministic deduplication.

---

## Alert & Evidence Data Models

### Alert Model (`alerts` table)
| Column | Type | Index | Description |
| :--- | :--- | :--- | :--- |
| `id` | `VARCHAR(36)` | PK | UUID v4 alert identifier |
| `rule_id` | `VARCHAR(64)` | Indexed | Rule identifier (e.g. `RULE-001`) |
| `rule_name` | `VARCHAR(128)` | None | Human-readable rule name |
| `title` | `VARCHAR(255)` | None | Descriptive alert headline |
| `description` | `TEXT` | None | Objective explanation of observed activity |
| `severity` | `VARCHAR(32)` | Indexed | Standardized level: `low`, `medium`, `high`, `critical` |
| `status` | `VARCHAR(32)` | Indexed | Triage state: `new`, `in_review`, `dismissed`, `escalated` |
| `dedup_key` | `VARCHAR(255)` | Unique Index | Deterministic SHA-256 hash enforcing database-level uniqueness |
| `affected_user`| `VARCHAR(128)` | Indexed | Target account principal |
| `affected_ip` | `VARCHAR(45)` | Indexed | Target or origin IP |
| `affected_hostname` | `VARCHAR(128)` | Indexed | Target host or container |
| `detected_at` | `TIMESTAMPTZ` | Indexed | UTC timestamp when the activity occurred |
| `created_at` | `TIMESTAMPTZ` | Indexed | UTC timestamp when alert was generated |
| `incident_id` | `VARCHAR(36)` | Indexed | Reserved for Phase 4 incident correlation |
| `alert_metadata` | `JSONB` | None | Contextual metrics (thresholds, counts, matched values) |

### Evidence Association (`alert_evidence` table)
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `VARCHAR(36)` (PK) | UUID v4 evidence record identifier |
| `alert_id` | `VARCHAR(36)` (FK) | References `alerts.id` on delete CASCADE |
| `event_id` | `VARCHAR(36)` (FK) | References `security_events.id` on delete CASCADE |
| `evidence_role` | `VARCHAR(64)` | Role in detection (`trigger`, `preceding_failure`, `successful_login`, `privilege_escalation`, `indicator_match`) |
| `description` | `TEXT` | Specific forensic explanation for this event reference |
| `created_at` | `TIMESTAMPTZ` | Timestamp when association was created |

Unique constraint: `(alert_id, event_id)` prevents redundant evidence bindings.

---

## Implemented Detection Rules

### RULE 001: Brute Force Authentication Attempt
* **Objective:** Detects repeated failed authentication attempts targeting the same account or originating from the same source IP within a sliding observation window.
* **Default Threshold:** `≥ 3` failed logins.
* **Default Window:** `15` minutes.
* **Dynamic Severity:** `MEDIUM` for `≥ 3` failures; escalated to `HIGH` for `≥ 6` failures.
* **Evidence:** Links all failed authentication attempts within the window.

### RULE 002: Successful Login After Repeated Failures
* **Objective:** Detects a successful authentication event preceded by multiple failed attempts for the same username or source IP within a lookback window, indicative of password guessing or credential cracking.
* **Default Threshold:** `≥ 2` preceding failed attempts.
* **Default Window:** `30` minutes prior to the successful login.
* **Severity:** `HIGH`.
* **Evidence:** Links all preceding failure events plus the pivotal successful authentication event.

### RULE 003: Suspicious Privilege or Role Modification
* **Objective:** Detects administrative group membership modifications, privileged role assignments, or direct root/sudo elevation commands.
* **Criteria:** Identifies sensitive actions (`sudo`, `group_membership_add`, `privilege_escalation`) and sensitive targets (`Domain Admins`, `wheel`, `root`, `administrators`).
* **Severity:** `CRITICAL` for high-impact targets (`Domain Admins`, `root`, `/bin/bash` interactive shells) on success; `HIGH` for standard role assignments; `MEDIUM` for failed attempts.
* **Evidence:** Links the specific privilege modification event.

### RULE 004: Unusual Multi-Source Authentication Pattern
* **Objective:** Detects when a single user account is accessed from multiple distinct source IPs within a short observation window, indicating concurrent session hijacking or distributed credential abuse.
* **Default Threshold:** `≥ 2` distinct source IPs.
* **Default Window:** `60` minutes.
* **Severity:** `MEDIUM`.
* **Integrity Guard:** Strictly grounded in observable IP telemetry. Zero fabricated geographic or behavioral intelligence.
* **Evidence:** Links all authentication events across the distinct source IPs.

### RULE 005: Configured Threat Indicator Match [Simulated IOC]
* **Objective:** Detects telemetry matching explicitly configured demonstration indicators (simulated external attacker IPs, persistence accounts, malicious domains).
* **Configured Demo Indicators:**
  - Demo IPs: `198.51.100.101`, `198.51.100.42`, `203.0.113.195`
  - Demo Usernames: `backdoor_backup`
  - Demo Hostnames: `c2-beacon.attacker.local`, `bad-external.domain.test`
* **Severity:** `HIGH` for active/successful events; `MEDIUM` for blocked/prevented events.
* **Transparency:** Clearly tagged as `[Simulated IOC]` to maintain forensic credibility.
* **Evidence:** Links the matching event with matched indicator type and value.

---

## Deterministic Deduplication Strategy

To prevent alert flooding, SentinelOps AI enforces a deterministic deduplication algorithm:
1. Each detection rule generates a cryptographic SHA-256 signature (`dedup_key`) based on:
   - Rule ID
   - Target entity (username and/or source IP)
   - Sorted list of primary trigger event IDs or time bucket
2. When the detection sweep evaluates candidates:
   - Queries existing `alerts.dedup_key` in the database.
   - Any candidate matching an existing key is filtered out as deduplicated.
   - Intra-run duplicates are also suppressed.
3. Database enforcement: A `UNIQUE INDEX` on `alerts.dedup_key` guarantees that duplicates can never be inserted even under race conditions.

---

## Detection & Alert API Reference

### Detection Execution
* `POST /api/v1/detection/run`:
  ```json
  // Request
  {
    "time_window_minutes": 60,
    "limit": 1000
  }
  
  // Response
  {
    "events_evaluated": 24,
    "rules_executed": 5,
    "alerts_generated": 4,
    "alerts_deduplicated": 0,
    "execution_duration_ms": 12.4,
    "generated_alert_ids": ["..."],
    "rule_breakdown": {
      "RULE-001": 1,
      "RULE-002": 1,
      "RULE-003": 1,
      "RULE-004": 0,
      "RULE-005": 1
    },
    "executed_at": "2026-09-24T18:38:25Z"
  }
  ```

### Alerts Management
* `GET /api/v1/alerts`: List alerts with pagination and filtering (`severity`, `status`, `rule_id`, `search`, `start_time`, `end_time`).
* `GET /api/v1/alerts/stats`: Return aggregated counts by severity, status, and triggering rule.
* `GET /api/v1/alerts/{alert_id}`: Retrieve alert details with full evidence timeline and underlying `SecurityEvent` JSON payloads.
* `PATCH /api/v1/alerts/{alert_id}/status`: Update triage status (`new`, `in_review`, `dismissed`, `escalated`).

---

## Simulated Attack Scenarios

The simulated demo dataset (`data/demo_security_events.json`) contains reproducible scenarios:

* **Scenario A (Brute Force):** Repeated failed SSH and RDP logins targeting `root`, `admin`, and `Administrator` from external attacker IPs (`198.51.100.42`, `198.51.100.101`). Triggers **RULE-001** and **RULE-005**.
* **Scenario B (Compromise After Failures):** Successful RDP logon for `helpdesk_temp` from `198.51.100.101` after prior repeated failed attempts on the same host. Triggers **RULE-002**.
* **Scenario C (Privilege Escalation):** Interactive root shell (`sudo /bin/bash`) by `svc-deploy`, and `helpdesk_temp` added to Active Directory `Domain Admins`. Triggers **RULE-003**.
* **Scenario D (Configured Demo Indicator Match):** Access by configured simulated persistence account `backdoor_backup`, and push fatigue from untrusted IP `203.0.113.195`. Triggers **RULE-005**.
* **Benign Telemetry (False Positive Control):** Routine SAML logins (`sarah.dev`, `alex.ops`), legitimate firewall blocks, and endpoint EDR blocks that do NOT generate spurious alerts.

---

## Honest System Limitations

* **Deterministic Scope:** The detection engine relies strictly on defined thresholds and patterns. It does not perform unsupervised behavioral anomaly detection or dynamic graph clustering (deferred to future phases).
* **Zero Autonomous Action:** The system alerts and surfaces evidence; it does not block IPs, terminate accounts, or modify firewall policies.
* **Demo Indicator Scope:** Threat indicators are pre-configured demo values. The system does not currently ingest live external threat intelligence feeds (STIX/TAXII).

---

## Automated Test Suite

SentinelOps AI maintains a comprehensive suite of **63 tests**:

```bash
# Run the complete test suite
pytest backend/

# Or via npm script
npm run test:backend
```

### Test Coverage Breakdown:
* **Detection Rules (`test_detection_rules.py`):** Positive, negative, boundary, timing, missing-field, and multi-user isolation cases for Rules 001–005.
* **Detection Engine (`test_detection_engine.py`):** Multi-rule orchestration, atomic persistence, second-run deduplication verification (0 duplicate alerts), and empty dataset safety.
* **Alerts API (`test_alerts_api.py`):** Detection execution endpoint, paginated listing, severity filtering, statistics aggregation, full evidence retrieval, and status updates.
* **Detection Security (`test_detection_security.py`):** SQL injection resilience in event message/username/action fields, search parameter parameterization, and XSS string inertness.
* **Ingestion & Validation (`test_events_*.py`):** Schema normalization, JSON/CSV parsing, and oversized upload rejection.

---

## Phase Roadmap

* [x] **Phase 1: Foundation & Architecture** (Completed)
* [x] **Phase 2: Event Ingestion & Data Model** (Completed)
* [x] **Phase 3: Deterministic Detection Engine** (Completed)
* [x] **Phase 4: Incident Correlation & SOC Dashboard** (Completed)
* [x] **Phase 5: Gemini Investigation Copilot** (Completed)
* [ ] **Phase 6: Case Management & Reports** (Executive summary generation, timeline export)
* [ ] **Phase 7: Security Audit, Testing & Polish**
* [ ] **Phase 8: Deployment & Portfolio Release**

---

## Phase 4: Incident Correlation & SOC Dashboard

Phase 4 bridges discrete detection alerts into correlated, forensic incidents:
* **PostgreSQL Incident Model:** `Incident` and `IncidentAuditLog` tracking lifecycle (`NEW`, `INVESTIGATING`, `RESOLVED`, `CLOSED`), severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), first/last seen, affected entities, and full correlation metadata.
* **Deterministic Correlation Engine:** Evaluates unassociated alerts against open incidents using explainable signals (same username, same source IP, configurable sliding temporal proximity window, multi-stage attack progression).
* **Transparent Severity Calculation:** Deterministically computes incident severity based on alert counts and progression without claiming certainty of compromise.
* **Unified Chronological Timeline:** Interweaves raw Security Events, Alerts, and Analyst Audit Actions.

---

## Phase 5: Gemini Investigation Copilot

Phase 5 introduces a secure, evidence-grounded AI investigation assistant to SentinelOps.

```
Security Events
       │
       ▼
Detection Engine (Deterministic Rules)
       │
       ▼
Correlated Incident (Explainable Graph/Window Engine)
       │
       ▼
Bounded & Sanitized Telemetry Context (XML Boundary)
       │
       ▼
FastAPI Server-Side Proxy (Zero Client-Side Keys)
       │
       ▼
Gemini Investigation Copilot (models/gemini-3.8-flash)
       │
       ▼
Structured Response Validation & Grounding Cross-Reference
       │
       ▼
Analyst Copilot Interface (Advisory Hypotheses, Evidence Citations & Q&A)
```

### Core Architecture & Design Directives
1. **Advisory Role Only:** Gemini is strictly an investigation **assistant**. It is **not** the source of truth for detection, never generates security events, never modifies evidence, and never executes automated remediation.
2. **Server-Side Only:** The Gemini API is accessed strictly via backend proxy routes (`/api/v1/incidents/{id}/analyze` and `/api/v1/incidents/{id}/ask`). The `GEMINI_API_KEY` is never transmitted to the browser.
3. **Evidence-First Context Building:** Telemetry is bounded and sanitized by `InvestigationContextBuilder`. When incidents contain large event volumes, repetitive events are summarized deterministically and high-priority triggers are preserved to stay within token budgets.
4. **Prompt Injection Defense:** External security logs are treated as untrusted data and strictly encapsulated within `<untrusted_evidence>` XML boundaries. The system instructions explicitly command the model to ignore directives embedded inside usernames, user agents, or log messages. Internal credentials and JWT tokens are automatically redacted.
5. **Deterministic Grounding Verification:** The backend `InvestigationResponseValidator` cross-references every evidence ID cited by Gemini against an authoritative incident telemetry catalog. Any hallucinated ID is flagged as `valid=False` (`[UNVERIFIED]`).
6. **Graceful Failure Handling:** If Gemini is unavailable, unconfigured, rate-limited, or times out, the deterministic SOC dashboard, detection rules, and incident correlation remain fully functional. User-facing error messages are clean and never expose internal stack traces or API keys.
7. **Immutable Audit Trail:** All AI analyses, analyst inquiries, and model identifiers are persisted to `incident_ai_analyses` and `incident_audit_logs`.

### Configuration Variables (`.env`)
```bash
GEMINI_API_KEY="your-api-key"
GEMINI_MODEL="gemini-3.8-flash"
GEMINI_TIMEOUT_SECONDS=30.0
GEMINI_MAX_OUTPUT_TOKENS=4096
GEMINI_TEMPERATURE=0.2
GEMINI_MAX_CONTEXT_EVENTS=50
GEMINI_RATE_LIMIT_PER_MINUTE=30
```

### Structured Output Schema
Gemini responses are strictly parsed into typed Pydantic models:
* `summary`: Concise forensic narrative of observed activity.
* `observed_facts`: Factual events directly corroborated by telemetry.
* `potential_explanations`: Hypotheses covering both malicious attack vectors and benign administrative explanations.
* `evidence_references`: Traceable citations referencing specific event or alert IDs.
* `missing_information`: Identified telemetry gaps and blind spots.
* `recommended_next_steps`: Actionable manual investigation steps for the human analyst.
* `uncertainty_assessment`: Explicit statement of analytical confidence boundaries.

> **Advisory Notice:** AI-generated analysis is advisory and must be reviewed by a human analyst. Deterministic telemetry remains the primary source of truth.
