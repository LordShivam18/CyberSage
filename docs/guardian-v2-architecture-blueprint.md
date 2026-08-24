# CyberSage Guardian v2 — Architecture Blueprint

> **Audit-only document. No files modified.**
> Current release-verified state: v1.1.0
> Date: August 24, 2026

---

## Table of Contents

1. [Current Architecture Assessment](#1-current-architecture-assessment)
2. [Gap Analysis](#2-gap-analysis)
3. [Guardian Domain Model](#3-guardian-domain-model)
4. [Event Schema](#4-event-schema)
5. [ResponseDecision Schema](#5-responsedecision-schema)
6. [Action Interface](#6-action-interface)
7. [Verification Interface](#7-verification-interface)
8. [Rollback Design](#8-rollback-design)
9. [Database Changes Required](#9-database-changes-required)
10. [API Changes Required](#10-api-changes-required)
11. [Frontend Changes Required](#11-frontend-changes-required)
12. [Windows Agent Architecture](#12-windows-agent-architecture)
13. [Security/Threat Model](#13-securitythreat-model)
14. [Trust Boundaries](#14-trust-boundaries)
15. [Attack Surfaces](#15-attack-surfaces)
16. [Testing Strategy](#16-testing-strategy)
17. [Migration Strategy](#17-migration-strategy)
18. [Incremental Implementation Phases](#18-incremental-implementation-phases)

---

## 1. Current Architecture Assessment

### 1.1 Repository Structure (v1.1.0)

```
cybersage/
├── backend/               # FastAPI API + Kafka worker
│   ├── main.py            # FastAPI app, REST endpoints, WebSocket
│   ├── config.py          # Settings (env-driven, frozen dataclass)
│   ├── database.py        # SQLAlchemy engine + session
│   ├── models.py          # 14 ORM models (User, NormalizedEvent, Detection, Alert, Incident, etc.)
│   ├── schemas.py         # Pydantic request/response models
│   ├── auth.py            # JWT auth, PBKDF2 hashing, RBAC, rate limiting
│   ├── pipeline.py        # Core detection pipeline (normalize → detect → alert → correlate)
│   ├── telemetry.py       # Event normalization (Zeek, Suricata, Synthetic)
│   ├── inference.py       # Transformer ML model inference with governance
│   ├── anomaly.py         # Isolation Forest anomaly detection
│   ├── rules_engine.py    # JSON-driven rule evaluation
│   ├── correlation.py     # Alert → Incident correlation
│   ├── risk.py            # Multi-signal risk scoring (ML + anomaly + rules + TI)
│   ├── mitre.py           # MITRE ATT&CK technique mapping
│   ├── threat_intel_service.py  # Local indicator + optional external TI
│   ├── worker.py          # Kafka consumer/producer worker
│   ├── realtime.py        # WebSocket connection manager
│   ├── model_governance.py  # Dataset manifests, splits, evaluation, drift
│   ├── model_registry.py  # Candidate → validated → active → archived lifecycle
│   ├── model_architecture.py  # ThreatTransformer (PyTorch)
│   ├── model_benchmark.py # Reproducible benchmark runner
│   ├── api_assessments.py # Assessment import REST API
│   ├── cli.py             # CLI (migrate, create-user, process-jsonl, model ops)
│   ├── release.py         # VERSION reader
│   ├── serializers.py     # ORM → dict serializers
│   ├── detection_types.py # DetectorResult, RiskResult dataclasses
│   ├── migrations/        # 3 sequential migrations (platform, governance, assessment)
│   ├── rules/             # default_rules.json, mitre_mapping.json
│   └── threat_intel/      # local_indicators.json
├── frontend/              # React CRA dashboard
│   └── src/
│       ├── App.js         # Root component
│       ├── Dashboard.js   # Main SOC workspace (6 tabs)
│       ├── apiService.js  # Axios API client + WebSocket URL builder
│       └── components/    # AlertsTable, ModelMonitoring, PredictionForm, AssessmentsView
├── portable/              # Offline Windows-first scanner
│   ├── cybersage_portable/
│   │   ├── models.py      # Finding, CollectorResult, AssessmentRun dataclasses
│   │   ├── runner.py      # Orchestrates collectors → checks → findings
│   │   ├── report.py      # JSON + HTML report generation (no external deps)
│   │   ├── importer.py    # Optional server upload client
│   │   ├── compare.py     # Differential assessment comparison
│   │   ├── collectors/    # 8 collectors (OS, security controls, accounts, etc.)
│   │   ├── checks/        # 28 security checks across 8 categories
│   │   ├── privacy.py     # Redaction config per privacy mode
│   │   └── platform_abstraction.py  # Cross-platform OS calls
│   └── tests/             # 10 test files
├── shared/
│   └── report_contract.py # Canonical checksum, posture score, report validation
├── scripts/               # Release gate, version contract, release metadata
├── security/              # requirements.txt for Bandit + pip-audit
├── tests/                 # Backend integration tests
├── .github/workflows/     # runtime-release-gate.yml, portable-build.yml
├── docker-compose.yml     # 6 services (kafka, db, migrate, api, worker, frontend)
└── VERSION                # Authoritative: "1.1.0"
```

### 1.2 Backend Architecture

**Framework:** FastAPI (async-capable, but endpoints are synchronous)
**Database:** PostgreSQL 15 (SQLAlchemy ORM, custom migration runner)
**Message Broker:** Apache Kafka (KRaft mode, no ZooKeeper)
**Real-time:** WebSocket via FastAPI native support

**Runtime Processes:**
- `backend-api`: FastAPI HTTP/WS server (uvicorn)
- `detection-worker`: Kafka consumer group that processes raw events
- `migrate`: One-shot migration container

**Key Architectural Patterns:**
- Pipeline pattern: `normalize_event → predict → anomaly → rules → risk → alert → correlate`
- Deterministic deduplication via SHA-256 hashed keys (`event_id`, `detection_key`, `alert_key`, `incident_key`)
- ML governance lifecycle: candidate → validated → active → archived
- Model fallback chain: governed transformer → legacy compatibility → heuristic fallback
- Dead-letter pattern for invalid Kafka messages

### 1.3 Event Schema (v1)

**NormalizedEvent** (`ndr.event.v1`):
- `event_id` (unique, SHA-256 derived)
- `timestamp`, `ingestion_timestamp`
- `sensor_type` (zeek/suricata/synthetic)
- `source_ip`, `source_port`, `destination_ip`, `destination_port`
- `protocol`, `duration`, `bytes_sent/received`, `packets_sent/received`
- `tcp_flags`, `flow_id`, `host_id`, `device_id`
- `raw_event_reference`, `raw_event` (JSONB), `normalized` (JSONB)

### 1.4 Kafka Telemetry Model

**Topics:**
- `raw.network-events` — primary telemetry input
- `network_traffic` — legacy synthetic topic
- `normalized.network-events` — normalized event fan-out
- `detections` — hybrid detection fan-out
- `dead-letter-events` — failed messages

**Worker Flow:**
1. Consume from `raw.network-events` + `network_traffic`
2. `process_payload()` → normalize, detect, risk-score, alert, correlate
3. Publish to `normalized.network-events` and `detections`
4. Dead-letter on failure

### 1.5 Detection Engine

**Three-signal hybrid detection:**
1. **ML Model** (ThreatTransformer): PyTorch transformer with sequence input, binary/multiclass classification
2. **Anomaly Detector** (Isolation Forest): Unsupervised anomaly scoring with deterministic fallback
3. **Rules Engine**: JSON-configured conditional rules with context-aware operators

**Risk Scoring** combines: ML confidence (35%), anomaly score (20%), rule severity (25%), threat intel (15%), asset criticality (5%), repeat occurrences (10%)

### 1.6 Incident/Correlation Model

**Incident correlation** (`correlation.py`):
- Matches alerts to existing incidents by: same IP pair + (same classification or shared MITRE technique)
- Window: 60 minutes from first_seen
- Creates new incident if no match found
- Aggregates severity, MITRE techniques, related assets, indicators

### 1.7 Authentication/RBAC

**Roles:** `administrator`, `security_analyst`, `incident_responder`, `read_only_auditor`
**Auth:** JWT (HS256) with PBKDF2-SHA256 password hashing
**Rate limiting:** Per-path, per-client sliding window
**WebSocket auth:** Token via query param or Authorization header

### 1.8 Model Governance

**Lifecycle states:** candidate → validated → active → archived/rejected
**Quality gates:** minimum macro F1, maximum FPR, maximum latency, per-class recall
**Drift monitoring:** PSI-based population stability index against training reference
**Artifact verification:** Checksum binding between model weights, scaler, metadata, and training data

### 1.9 Portable Assessment Architecture

**Architecture:** Offline, standalone Windows executable
**Collectors:** 8 categories (OS, security controls, accounts, processes, persistence, network, browser, certificates)
**Checks:** 28 individual checks, read-only evaluators
**Report format:** Canonical JSON with SHA-256 checksum, HTML report with CSP
**Import:** Optional upload to backend with idempotency, posture score recomputation, and selective alert creation

### 1.10 Database Migrations

**Custom migration runner** (`backend/migrations/runner.py`):
- `001_platform_schema`: Creates platform tables, expands legacy alerts
- `002_model_governance`: Adds model lifecycle fields
- `003_portable_assessment`: Adds assessment_runs and assessment_findings
- Idempotent via `schema_migrations` tracking table
- Preserves legacy data during expansion

### 1.11 Runtime Release Gate

**Comprehensive CI pipeline** (`runtime-release-gate.yml`):
- Gitleaks secret scanning
- Bandit static analysis
- pip-audit + npm audit
- zizmor workflow scanning
- CycloneDX SBOM generation
- Docker Compose integration testing
- PostgreSQL schema validation (SQL assertions)
- Legacy migration compatibility testing
- Authentication + WebSocket authorization testing
- Kafka end-to-end + idempotency testing
- Dead-letter handling validation
- Service recovery testing (restart Kafka, stop/start DB)
- Frontend build + test

### 1.12 Security Controls

- JWT secret validation (min 32 chars, not in known-bad list)
- CORS restriction (no `*` with credentials)
- Gitleaks on every commit
- Bandit on backend + portable + shared
- pip-audit on requirements
- npm audit on frontend
- zizmor on GitHub Actions workflows
- CSP headers in HTML reports
- HTML escaping in all report output
- No `shell=True` in portable collectors
- URL scheme validation in importer
- PBKDF2 with 260,000 iterations
- Rate limiting on auth and predict endpoints

---

## 2. Gap Analysis

### 2.1 What Exists (v1.1)

| Capability | Status |
|---|---|
| Network telemetry normalization | ✅ Complete |
| ML-based threat detection | ✅ Complete |
| Anomaly detection | ✅ Complete |
| Rule-based detection | ✅ Complete |
| Risk scoring | ✅ Complete |
| Alert generation | ✅ Complete |
| Incident correlation | ✅ Complete |
| WebSocket live updates | ✅ Complete |
| RBAC authentication | ✅ Complete |
| Model governance lifecycle | ✅ Complete |
| Drift monitoring | ✅ Complete |
| Portable offline assessment | ✅ Complete |
| Assessment import + idempotency | ✅ Complete |
| Dead-letter handling | ✅ Complete |
| Comprehensive CI/CD | ✅ Complete |

### 2.2 What Guardian v2 Must Add

| Capability | v1.1 Gap |
|---|---|
| **Host-level monitoring** (process, file, persistence) | ❌ None — only network telemetry |
| **Local-first operation** (offline queue) | ❌ None — requires backend + Kafka |
| **Explainable recommendations** | ⚠️ Partial — has contributing_features but no structured Explain → Recommend flow |
| **Human approval workflow** | ❌ None — alerts are informational only |
| **Remediation actions** | ❌ None — no action execution capability |
| **Verification engine** | ❌ None — no post-remediation validation |
| **Rollback capability** | ❌ None — no snapshot/rollback mechanism |
| **Incident timeline** | ⚠️ Partial — has first_seen/last_seen but no event timeline |
| **Evidence chain** | ⚠️ Partial — has raw_evidence_reference but no structured evidence trail |
| **Guardian UI** | ❌ None — no protection/incident/approval views |
| **Agent health monitoring** | ❌ None — no agent → backend heartbeat |
| **Signed updates** | ⚠️ Partial — has release manifest but no auto-update mechanism |
| **Browser protection** | ❌ Planned only |

### 2.3 What Must NOT Change

- Gitleaks, Bandit, pip-audit, npm audit, zizmor, SBOM, provenance, checksums
- Docker runtime (Kafka, PostgreSQL, API, worker, frontend)
- Migrations (all existing must remain idempotent)
- WebSocket authorization
- Kafka processing pipeline
- Portable assessment (v1.1 architecture frozen)
- Event normalization (ndr.event.v1 schema)
- All existing API contracts

---

## 3. Guardian Domain Model

### 3.1 Core Entities

```
┌─────────────────────────────────────────────────────────────┐
│                    GUARDIAN DOMAIN MODEL                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐     ┌──────────────────┐                  │
│  │ GuardianAgent │────▶│  AgentHeartbeat  │                  │
│  └──────────────┘     └──────────────────┘                  │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────┐     ┌──────────────────────┐           │
│  │ GuardianEvent     │────▶│  GuardianDetection   │           │
│  │ (host-level)      │     │  (explain + recommend)│          │
│  └──────────────────┘     └──────────────────────┘           │
│         │                          │                          │
│         │                          ▼                          │
│         │               ┌──────────────────────┐             │
│         │               │  ResponseDecision     │             │
│         │               │  (requires_approval)  │             │
│         │               └──────────────────────┘             │
│         │                          │                          │
│         │                          ▼                          │
│         │               ┌──────────────────────┐             │
│         │               │  RemediationAction    │             │
│         │               │  (snapshot→execute→   │             │
│         │               │   verify→commit/rb)   │             │
│         │               └──────────────────────┘             │
│         │                          │                          │
│         │                          ▼                          │
│         │               ┌──────────────────────┐             │
│         │               │  VerificationResult   │             │
│         │               └──────────────────────┘             │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────┐     ┌──────────────────────┐           │
│  │ GuardianIncident  │────▶│  IncidentTimeline    │           │
│  │ (extends v1.1)   │     │  (event timeline)    │           │
│  └──────────────────┘     └──────────────────────┘           │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────┐                                         │
│  │ ApprovalRequest  │                                         │
│  │ + ApprovalRecord │                                         │
│  └──────────────────┘                                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Entity Relationships

```
GuardianAgent (1) ──▶ (N) GuardianEvent
GuardianAgent (1) ──▶ (N) AgentHeartbeat
GuardianEvent (1) ──▶ (N) GuardianDetection
GuardianDetection (1) ──▶ (0..1) ResponseDecision
ResponseDecision (1) ──▶ (0..1) ApprovalRequest
ApprovalRequest (1) ──▶ (0..1) ApprovalRecord
ApprovalRecord (1) ──▶ (N) RemediationAction
RemediationAction (1) ──▶ (N) VerificationResult
RemediationAction (1) ──▶ (0..1) RollbackRecord
GuardianIncident (1) ──▶ (N) GuardianDetection (via incident_id)
GuardianIncident (1) ──▶ (N) IncidentTimelineEntry
GuardianIncident (1) ──▶ (N) RemediationAction
```

### 3.3 Guardian v2 Extends v1.1

| v1.1 Entity | Guardian v2 Extension |
|---|---|
| `Incident` | Add `timeline` (JSONB), `evidence` (JSONB), `recommendations` (JSONB), `final_state` (JSONB) |
| `Alert` | Add `guardian_detection_id` FK, `requires_approval` (bool) |
| `NormalizedEvent` | No change — network events remain as-is |
| `Detection` | Add `guardian_event_id` FK for host-level detections |

---

## 4. Event Schema

### 4.1 GuardianEvent (Host-Level)

```python
# guardian/collectors/events.py

SCHEMA_VERSION = "guardian.event.v1"

@dataclass(frozen=True)
class GuardianEvent:
    """
    Normalized host-level security event.
    Reuses project conventions from ndr.event.v1 where applicable.
    """
    # Identity
    event_id: str                    # SHA-256 derived, stable
    schema_version: str = "guardian.event.v1"
    timestamp: datetime              # Event creation time
    ingestion_timestamp: datetime    # When agent ingested it

    # Source identification
    host_id: str                     # Agent-assigned stable host identifier
    host_hostname: str               # Machine hostname
    agent_version: str               # Guardian agent version

    # Process context
    process_name: Optional[str] = None
    process_pid: Optional[int] = None  # Ephemeral — NOT used for identity
    process_exe_path: Optional[str] = None
    process_exe_hash_sha256: Optional[str] = None
    process_command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_pid: Optional[int] = None
    parent_process_exe_path: Optional[str] = None

    # User context
    user_name: Optional[str] = None
    user_sid: Optional[str] = None

    # Network (reuses ndr.event.v1 conventions)
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[float] = None
    bytes_received: Optional[float] = None

    # File activity
    file_path: Optional[str] = None
    file_operation: Optional[str] = None  # "create", "modify", "delete", "rename"
    file_hash_sha256: Optional[str] = None

    # Persistence
    persistence_type: Optional[str] = None  # "registry_run_key", "scheduled_task", "startup_folder"
    persistence_path: Optional[str] = None
    persistence_data: Optional[dict] = None

    # Evidence
    evidence: Optional[dict] = None  # Structured evidence bag
    raw_event: Optional[dict] = None  # Original event data

    def to_event_id(self) -> str:
        """Generate deterministic event_id from non-volatile fields."""
        key_parts = [
            self.host_id or "",
            self.process_exe_path or "",
            self.process_exe_hash_sha256 or "",
            self.file_path or "",
            self.destination_ip or "",
            self.destination_port or "",
            self.persistence_path or "",
            self.timestamp.isoformat() if self.timestamp else "",
        ]
        payload = "|".join(key_parts)
        return f"guardian-{hashlib.sha256(payload.encode()).hexdigest()[:32]}"
```

### 4.2 Schema Versioning Convention

Following the existing `ndr.event.v1` convention:
- `guardian.event.v1` — host-level events
- `guardian.detection.v1` — host-level detections
- `guardian.response.v1` — response decisions
- `guardian.action.v1` — remediation actions

### 4.3 Evidence Bag Structure

```python
@dataclass
class EvidenceBag:
    """Structured evidence attached to events and detections."""
    evidence_id: str               # SHA-256 derived
    collected_at: datetime
    collector_type: str            # "process_monitor", "file_watcher", etc.
    data: dict                     # Raw evidence data
    hash_algorithm: str = "sha256"
    evidence_hash: str = ""        # Hash of data for tamper detection
    references: list[str] = field(default_factory=list)  # Related event_ids
```

---

## 5. ResponseDecision Schema

### 5.1 ResponseDecision

```python
# guardian/response/models.py

@dataclass(frozen=True)
class ResponseDecision:
    """
    Deterministic output from detection → recommendation pipeline.
    AI may classify, prioritize, explain, recommend.
    AI must NOT directly execute arbitrary system actions.
    """
    decision_id: str               # SHA-256 derived
    incident_id: str               # Links to GuardianIncident
    guardian_detection_id: str     # Source detection

    # Classification
    severity: str                  # "critical", "high", "medium", "low", "informational"
    confidence: float              # 0.0–1.0
    classification: str            # "malware", "unauthorized_access", "data_exfiltration", etc.

    # Recommendation
    action: str                    # One of SAFE_ACTIONS (see Phase 5)
    rationale: str                 # Human-readable explanation
    expected_effect: str           # What will happen if approved
    risk: str                      # What could go wrong
    evidence_refs: list[str]       # Evidence bag IDs supporting this decision

    # Safety
    requires_approval: bool = True  # Always True for v2 initial release
    rollback_available: bool = True
    verification_plan: str = ""    # How to verify the action worked

    # MITRE mapping
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)

    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return asdict(self)
```

### 5.2 Safe Response Actions (v2 Initial)

```python
SAFE_ACTIONS = {
    "disable_persistence_entry": {
        "description": "Disable a suspicious persistence entry (registry run key, scheduled task, startup item)",
        "requires_approval": True,
        "rollback_available": True,
        "risk_level": "medium",
        "prerequisites": ["admin_privileges"],
    },
    "block_ip_domain": {
        "description": "Temporarily block a selected IP or domain via Windows Firewall",
        "requires_approval": True,
        "rollback_available": True,
        "risk_level": "low",
        "prerequisites": ["admin_privileges"],
    },
    "quarantine_file": {
        "description": "Move a selected non-system file to a quarantine directory",
        "requires_approval": True,
        "rollback_available": True,
        "risk_level": "medium",
        "prerequisites": ["admin_privileges"],
        "constraints": ["not_system_file", "not_executable_in_use"],
    },
    "terminate_process": {
        "description": "Terminate an explicitly selected suspicious process",
        "requires_approval": True,
        "rollback_available": False,
        "risk_level": "high",
        "prerequisites": ["admin_privileges", "process_still_running"],
    },
    "restore_security_setting": {
        "description": "Restore a selected security setting to its secure default",
        "requires_approval": True,
        "rollback_available": True,
        "risk_level": "low",
        "prerequisites": ["admin_privileges", "known_good_value"],
    },
}
```

### 5.3 Decision Flow

```
GuardianDetection
       │
       ▼
┌──────────────────┐
│ Policy Evaluator  │  ← Rules-based, deterministic
│ (offline capable) │
└──────────────────┘
       │
       ▼
┌──────────────────┐
│ AI Classifier     │  ← Classifies, prioritizes, explains
│ (optional, cloud) │     Does NOT execute anything
└──────────────────┘
       │
       ▼
┌──────────────────┐
│ ResponseDecision  │  ← Structured recommendation
│ (requires_approval│     Always requires human approval
│  = True)          │
└──────────────────┘
       │
       ▼
┌──────────────────┐
│ ApprovalRequest   │  ← Presented to user via UI
│ (pending)         │
└──────────────────┘
       │
       ▼ (user approves)
┌──────────────────┐
│ RemediationAction │  ← Executes with snapshot + verification
└──────────────────┘
```

---

## 6. Action Interface

### 6.1 Base Action Protocol

```python
# guardian/response/actions/base.py

from abc import ABC, abstractmethod
from typing import Optional

class Action(ABC):
    """
    Base interface for all remediation actions.
    Every action must be transactional where practical.
    """

    @property
    @abstractmethod
    def action_type(self) -> str:
        """Unique action type identifier."""

    @abstractmethod
    def can_execute(self) -> tuple[bool, str]:
        """
        Pre-flight check. Returns (can_execute, reason).
        Must check: admin privileges, target existence, in-use state, etc.
        """

    @abstractmethod
    def create_snapshot(self) -> dict:
        """
        Capture the current state before modification.
        Returns a JSON-serializable snapshot dict.
        Raises on failure — action must NOT proceed without snapshot.
        """

    @abstractmethod
    def apply(self, snapshot: dict) -> dict:
        """
        Execute the remediation.
        Returns result dict with: success, details, affected_entities.
        Must NOT catch and swallow critical exceptions.
        """

    @abstractmethod
    def verify(self, snapshot: dict, result: dict) -> tuple[bool, str]:
        """
        Verify the action actually took effect.
        Returns (verified, message).
        NEVER marks successful merely because exit code == 0.
        Must check the actual system state.
        """

    @abstractmethod
    def rollback(self, snapshot: dict) -> dict:
        """
        Undo the action using the snapshot.
        Returns rollback result dict.
        """

    def requires_approval(self) -> bool:
        """All v2 actions require approval."""
        return True
```

### 6.2 Concrete Action Examples

```python
# guardian/response/actions/block_ip.py

class BlockIpAction(Action):
    """Temporarily block an IP via Windows Firewall."""

    @property
    def action_type(self) -> str:
        return "block_ip_domain"

    def can_execute(self) -> tuple[bool, str]:
        # Check: admin privileges, target IP is valid, not a local/private IP
        ...

    def create_snapshot(self) -> dict:
        # Snapshot: current firewall rules for this IP
        # Use: netsh advfirewall firewall show rule name=...
        return {
            "ip": self.target_ip,
            "existing_rules": [...],
            "firewall_state": "enabled",
        }

    def apply(self, snapshot: dict) -> dict:
        # Add inbound + outbound block rules
        # Use: netsh advfirewall firewall add rule
        return {"success": True, "rules_created": 2}

    def verify(self, snapshot: dict, result: dict) -> tuple[bool, str]:
        # Verify: new rules exist AND old rules unchanged
        # Check: netsh advfirewall firewall show rule name=...
        current_rules = self._get_current_rules()
        if not any(r["name"] == self._rule_name for r in current_rules):
            return False, "Block rule was not created"
        return True, "IP block verified"

    def rollback(self, snapshot: dict) -> dict:
        # Remove the rules we created, restore original state
        ...
```

---

## 7. Verification Interface

### 7.1 VerificationEngine

```python
# guardian/verification/engine.py

@dataclass
class VerificationPlan:
    """Defines how to verify a remediation action."""
    steps: list[VerificationStep]
    timeout_seconds: int = 30
    retry_count: int = 3
    retry_delay_seconds: int = 5

@dataclass
class VerificationStep:
    """One verification check."""
    step_id: str
    description: str
    check_type: str          # "state_check", "process_check", "network_check", "file_check"
    check_command: str       # How to verify
    expected_result: str     # What success looks like
    evidence_collector: str  # What to capture

@dataclass
class VerificationResult:
    """Result of verification."""
    verification_id: str
    action_id: str
    all_passed: bool
    steps_passed: int
    steps_total: int
    step_results: list[StepResult]
    verified_at: datetime
    evidence: list[dict]     # Collected evidence bags

@dataclass
class StepResult:
    step_id: str
    passed: bool
    message: str
    evidence: dict
    attempted_at: datetime
```

### 7.2 Verification Flow

```
prepare → snapshot → execute → verify → commit OR rollback
    │         │          │         │
    │         │          │         ├── state check (did the change persist?)
    │         │          │         ├── side-effect check (anything else change?)
    │         │          │         ├── evidence collection
    │         │          │         └── timeout + retry
    │         │          │
    │         │          └── apply the action
    │         │
    │         └── capture current state (for rollback)
    │
    └── pre-flight checks
```

### 7.3 Verification Rules

1. **Never trust exit codes alone.** Always verify the system state changed as expected.
2. **Check side effects.** Did the action inadvertently change anything else?
3. **Collect evidence.** Every verification step must capture evidence.
4. **Timeout protection.** Never wait indefinitely for verification.
5. **Retry with backoff.** Some changes take a moment to propagate.
6. **Atomic commit.** Only mark as "successful" after ALL verification steps pass.

---

## 8. Rollback Design

### 8.1 Rollback Interface

```python
# guardian/rollback/manager.py

@dataclass
class RollbackRecord:
    """Record of a rollback operation."""
    rollback_id: str
    action_id: str
    reason: str               # Why rollback was triggered
    snapshot: dict            # Original state
    rolled_back_at: datetime
    rolled_back_by: str       # "user", "auto_verification", "timeout"
    success: bool
    details: str

class RollbackManager:
    """
    Manages action rollbacks.
    Actions must be transactional where practical.
    """

    def can_rollback(self, action_id: str) -> bool:
        """Check if an action supports rollback."""

    def create_snapshot(self, action: Action) -> dict:
        """Capture state before action execution."""

    def rollback(self, action_id: str, snapshot: dict, reason: str) -> RollbackRecord:
        """
        Execute rollback using the captured snapshot.
        Returns the rollback record.
        """

    def verify_rollback(self, action_id: str, snapshot: dict) -> bool:
        """Verify that rollback restored the original state."""
```

### 8.2 Rollback Guarantees

| Action | Rollback Available | Rollback Method |
|---|---|---|
| `disable_persistence_entry` | ✅ | Re-enable the registry key / task |
| `block_ip_domain` | ✅ | Remove the firewall rules |
| `quarantine_file` | ✅ | Move file back to original path |
| `terminate_process` | ❌ | Cannot restart a terminated process |
| `restore_security_setting` | ✅ | Re-apply the previous value from snapshot |

### 8.3 Rollback Safety Rules

1. **Never rollback a rollback.** Rollback is a terminal operation.
2. **Snapshot before execute.** No action proceeds without a valid snapshot.
3. **Verify rollback.** After rollback, verify the system returned to the snapshot state.
4. **Audit everything.** Every rollback creates an immutable audit record.
5. **Timeout protection.** Rollback operations must complete within 60 seconds.

---

## 9. Database Changes Required

### 9.1 New Tables (Migration `004_guardian_core`)

```sql
-- Guardian agents
CREATE TABLE guardian_agents (
    id SERIAL PRIMARY KEY,
    agent_key VARCHAR(128) UNIQUE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os_name VARCHAR(128),
    os_version VARCHAR(128),
    agent_version VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    registered_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_heartbeat_at TIMESTAMP,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Agent heartbeats
CREATE TABLE guardian_heartbeats (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER NOT NULL REFERENCES guardian_agents(id),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    cpu_usage_pct FLOAT,
    memory_usage_pct FLOAT,
    events_queued INTEGER DEFAULT 0,
    events_processed INTEGER DEFAULT 0,
    detections_pending INTEGER DEFAULT 0,
    uptime_seconds INTEGER,
    metadata JSONB DEFAULT '{}'
);

-- Guardian host-level events
CREATE TABLE guardian_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(128) UNIQUE NOT NULL,
    schema_version VARCHAR(32) NOT NULL DEFAULT 'guardian.event.v1',
    agent_id INTEGER NOT NULL REFERENCES guardian_agents(id),
    timestamp TIMESTAMP NOT NULL,
    ingestion_timestamp TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Process context
    process_name VARCHAR(255),
    process_pid INTEGER,
    process_exe_path TEXT,
    process_exe_hash_sha256 VARCHAR(128),
    process_command_line TEXT,
    parent_process_name VARCHAR(255),
    parent_process_pid INTEGER,
    parent_process_exe_path TEXT,

    -- User context
    user_name VARCHAR(255),
    user_sid VARCHAR(128),

    -- Network
    source_ip VARCHAR(64),
    source_port INTEGER,
    destination_ip VARCHAR(64),
    destination_port INTEGER,
    protocol VARCHAR(32),
    bytes_sent FLOAT,
    bytes_received FLOAT,

    -- File activity
    file_path TEXT,
    file_operation VARCHAR(32),
    file_hash_sha256 VARCHAR(128),

    -- Persistence
    persistence_type VARCHAR(64),
    persistence_path TEXT,
    persistence_data JSONB,

    -- Evidence
    evidence JSONB DEFAULT '{}',
    raw_event JSONB DEFAULT '{}',

    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Guardian detections
CREATE TABLE guardian_detections (
    id SERIAL PRIMARY KEY,
    detection_key VARCHAR(128) UNIQUE NOT NULL,
    event_id VARCHAR(128) NOT NULL REFERENCES guardian_events(event_id),
    agent_id INTEGER NOT NULL REFERENCES guardian_agents(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    detection_source VARCHAR(64) NOT NULL,
    classification VARCHAR(128) NOT NULL,
    confidence FLOAT NOT NULL DEFAULT 0.0,
    severity VARCHAR(32) NOT NULL DEFAULT 'low',
    risk_score FLOAT NOT NULL DEFAULT 0.0,

    mitre_techniques JSONB DEFAULT '[]',
    mitre_tactics JSONB DEFAULT '[]',
    contributing_features JSONB DEFAULT '[]',
    recommended_actions JSONB DEFAULT '[]',

    -- Explainability
    explanation TEXT,
    evidence_refs JSONB DEFAULT '[]',

    -- Link to existing detection system
    network_detection_id INTEGER REFERENCES detections(id),

    latency_ms FLOAT,
    metadata JSONB DEFAULT '{}'
);

-- Response decisions
CREATE TABLE guardian_response_decisions (
    id SERIAL PRIMARY KEY,
    decision_id VARCHAR(128) UNIQUE NOT NULL,
    incident_id VARCHAR(128) NOT NULL,
    guardian_detection_id VARCHAR(128) NOT NULL REFERENCES guardian_detections(detection_key),

    severity VARCHAR(32) NOT NULL,
    confidence FLOAT NOT NULL,
    classification VARCHAR(128) NOT NULL,

    action VARCHAR(64) NOT NULL,
    rationale TEXT NOT NULL,
    expected_effect TEXT NOT NULL,
    risk TEXT NOT NULL,
    evidence_refs JSONB DEFAULT '[]',

    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    rollback_available BOOLEAN NOT NULL DEFAULT TRUE,
    verification_plan TEXT NOT NULL DEFAULT '',

    mitre_techniques JSONB DEFAULT '[]',
    mitre_tactics JSONB DEFAULT '[]',

    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Approval requests
CREATE TABLE guardian_approval_requests (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(128) UNIQUE NOT NULL,
    decision_id VARCHAR(128) NOT NULL REFERENCES guardian_response_decisions(decision_id),
    incident_id VARCHAR(128) NOT NULL,

    requested_by VARCHAR(255) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    action_summary TEXT NOT NULL,
    rationale TEXT NOT NULL,
    expected_effect TEXT NOT NULL,
    risk TEXT NOT NULL,
    evidence_summary JSONB DEFAULT '{}',

    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    responded_by VARCHAR(255),
    responded_at TIMESTAMP,
    response_notes TEXT,

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);

-- Approval records (immutable audit)
CREATE TABLE guardian_approval_records (
    id SERIAL PRIMARY KEY,
    record_id VARCHAR(128) UNIQUE NOT NULL,
    request_id VARCHAR(128) NOT NULL REFERENCES guardian_approval_requests(request_id),
    decision_id VARCHAR(128) NOT NULL,

    action VARCHAR(16) NOT NULL,  -- "approve" or "reject"
    actor VARCHAR(255) NOT NULL,
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Remediation actions
CREATE TABLE guardian_remediation_actions (
    id SERIAL PRIMARY KEY,
    action_id VARCHAR(128) UNIQUE NOT NULL,
    decision_id VARCHAR(128) NOT NULL REFERENCES guardian_response_decisions(decision_id),
    approval_record_id VARCHAR(128) REFERENCES guardian_approval_records(record_id),

    action_type VARCHAR(64) NOT NULL,
    target_entity VARCHAR(512) NOT NULL,
    snapshot JSONB NOT NULL,
    result JSONB DEFAULT '{}',
    rollback_snapshot JSONB,

    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    executed_at TIMESTAMP,
    completed_at TIMESTAMP,
    executed_by VARCHAR(255) NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Verification results
CREATE TABLE guardian_verification_results (
    id SERIAL PRIMARY KEY,
    verification_id VARCHAR(128) UNIQUE NOT NULL,
    action_id VARCHAR(128) NOT NULL REFERENCES guardian_remediation_actions(action_id),

    all_passed BOOLEAN NOT NULL,
    steps_passed INTEGER NOT NULL,
    steps_total INTEGER NOT NULL,
    step_results JSONB NOT NULL DEFAULT '[]',
    evidence JSONB DEFAULT '[]',

    verified_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Rollback records
CREATE TABLE guardian_rollback_records (
    id SERIAL PRIMARY KEY,
    rollback_id VARCHAR(128) UNIQUE NOT NULL,
    action_id VARCHAR(128) NOT NULL REFERENCES guardian_remediation_actions(action_id),

    reason TEXT NOT NULL,
    snapshot JSONB NOT NULL,
    success BOOLEAN NOT NULL,
    details TEXT,
    rolled_back_by VARCHAR(255) NOT NULL,
    rolled_back_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Guardian incidents (extends existing incidents table concept)
CREATE TABLE guardian_incidents (
    id SERIAL PRIMARY KEY,
    incident_key VARCHAR(128) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL DEFAULT 'new',
    severity VARCHAR(32) NOT NULL DEFAULT 'low',
    priority VARCHAR(32) NOT NULL DEFAULT 'medium',

    -- Host-level context
    agent_id INTEGER REFERENCES guardian_agents(id),
    hostname VARCHAR(255),
    affected_user VARCHAR(255),

    -- MITRE mapping
    mitre_techniques JSONB DEFAULT '[]',
    mitre_tactics JSONB DEFAULT '[]',

    -- Timeline and evidence
    timeline JSONB DEFAULT '[]',
    evidence JSONB DEFAULT '[]',
    affected_entities JSONB DEFAULT '[]',
    recommendations JSONB DEFAULT '[]',

    -- Actions
    actions_taken JSONB DEFAULT '[]',
    verification_results JSONB DEFAULT '[]',
    rollback_events JSONB DEFAULT '[]',

    -- Final state
    final_state JSONB DEFAULT '{}',
    resolution_summary TEXT,
    resolved_by VARCHAR(255),
    resolved_at TIMESTAMP,

    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Guardian incident timeline entries
CREATE TABLE guardian_incident_timeline (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES guardian_incidents(id),
    entry_type VARCHAR(64) NOT NULL,
    entry_data JSONB NOT NULL,
    actor VARCHAR(255),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### 9.2 Indexes

```sql
CREATE INDEX ix_guardian_agents_status ON guardian_agents(status);
CREATE INDEX ix_guardian_agents_hostname ON guardian_agents(hostname);
CREATE INDEX ix_guardian_events_agent_id ON guardian_events(agent_id);
CREATE INDEX ix_guardian_events_timestamp ON guardian_events(timestamp);
CREATE INDEX ix_guardian_events_process_exe_path ON guardian_events(process_exe_path);
CREATE INDEX ix_guardian_events_destination_ip ON guardian_events(destination_ip);
CREATE INDEX ix_guardian_detections_agent_id ON guardian_detections(agent_id);
CREATE INDEX ix_guardian_detections_severity ON guardian_detections(severity);
CREATE INDEX ix_guardian_detections_created_at ON guardian_detections(created_at);
CREATE INDEX ix_guardian_response_decisions_incident_id ON guardian_response_decisions(incident_id);
CREATE INDEX ix_guardian_response_decisions_status ON guardian_response_decisions(status);
CREATE INDEX ix_guardian_approval_requests_status ON guardian_approval_requests(status);
CREATE INDEX ix_guardian_approval_requests_incident_id ON guardian_approval_requests(incident_id);
CREATE INDEX ix_guardian_remediation_actions_decision_id ON guardian_remediation_actions(decision_id);
CREATE INDEX ix_guardian_remediation_actions_status ON guardian_remediation_actions(status);
CREATE INDEX ix_guardian_verification_results_action_id ON guardian_verification_results(action_id);
CREATE INDEX ix_guardian_rollback_records_action_id ON guardian_rollback_records(action_id);
CREATE INDEX ix_guardian_incidents_status ON guardian_incidents(status);
CREATE INDEX ix_guardian_incidents_severity ON guardian_incidents(severity);
CREATE INDEX ix_guardian_incidents_agent_id ON guardian_incidents(agent_id);
CREATE INDEX ix_guardian_incidents_first_seen ON guardian_incidents(first_seen);
CREATE INDEX ix_guardian_incident_timeline_incident_id ON guardian_incident_timeline(incident_id);
CREATE INDEX ix_guardian_heartbeats_agent_id ON guardian_heartbeats(agent_id);
CREATE INDEX ix_guardian_heartbeats_timestamp ON guardian_heartbeats(timestamp);
```

### 9.3 No Changes to Existing Tables

The following existing tables remain untouched:
- `users`, `normalized_events`, `detections`, `alerts`, `incidents`, `incident_alerts`
- `analyst_feedback`, `threat_intel_cache`, `model_versions`, `audit_events`
- `dead_letter_events`, `schema_migrations`, `assessment_runs`, `assessment_findings`

---

## 10. API Changes Required

### 10.1 New API Endpoints

```
POST   /api/v1/guardian/agents/register        # Register a Guardian agent
POST   /api/v1/guardian/agents/{id}/heartbeat   # Agent heartbeat
GET    /api/v1/guardian/agents                   # List registered agents
GET    /api/v1/guardian/agents/{id}              # Agent details
GET    /api/v1/guardian/agents/{id}/health       # Agent health status

POST   /api/v1/guardian/events                   # Ingest host-level events (batch)
GET    /api/v1/guardian/events                   # Query host events

POST   /api/v1/guardian/detections               # Submit detections (from agent)
GET    /api/v1/guardian/detections               # Query detections

POST   /api/v1/guardian/incidents                # Create/update incidents
GET    /api/v1/guardian/incidents                # List incidents
GET    /api/v1/guardian/incidents/{id}           # Incident detail with timeline
PATCH  /api/v1/guardian/incidents/{id}           # Update incident

POST   /api/v1/guardian/decisions                # Submit response decisions
GET    /api/v1/guardian/decisions                # Query decisions
GET    /api/v1/guardian/decisions/{id}           # Decision detail

POST   /api/v1/guardian/approvals                # Request approval
GET    /api/v1/guardian/approvals/pending        # List pending approvals
GET    /api/v1/guardian/approvals/{id}           # Approval detail
PATCH  /api/v1/guardian/approvals/{id}           # Approve or reject

POST   /api/v1/guardian/actions                  # Execute approved action
GET    /api/v1/guardian/actions                  # List actions
GET    /api/v1/guardian/actions/{id}             # Action detail with verification
POST   /api/v1/guardian/actions/{id}/rollback    # Trigger rollback

GET    /api/v1/guardian/protection-state         # Overall protection status
GET    /api/v1/guardian/metrics                  # Guardian-specific metrics
```

### 10.2 Existing API Endpoints — No Changes

All existing v1.1 endpoints remain unchanged:
- `/api/v1/health`, `/api/v1/ready`
- `/api/v1/auth/login`
- `/api/v1/events` (network events)
- `/api/v1/detections`
- `/api/v1/alerts`, `/api/v1/alerts/{id}`
- `/api/v1/incidents`, `/api/v1/incidents/{id}`
- `/api/v1/metrics`
- `/api/v1/model/status`, `/api/v1/models/*`
- `/api/v1/audit-events`
- `/api/v1/threat-intel/lookup`
- `/api/v1/assessments/*`
- `/api/v1/ws/alerts`
- `/predict`

### 10.3 WebSocket Extensions

```
WS /api/v1/ws/guardian          # Guardian-specific live updates
  → guardian.event.created
  → guardian.detection.created
  → guardian.incident.updated
  → guardian.approval.pending
  → guardian.action.completed
  → guardian.verification.completed
  → guardian.agent.heartbeat
```

---

## 11. Frontend Changes Required

### 11.1 New "Protection" Tab

```
Dashboard.js tabs:
  [Overview] [Alerts] [Incidents] [Events] [Model] [Assessments] [Protection]  ← NEW
```

### 11.2 Protection View Components

```
frontend/src/components/
├── ProtectionView.js          # Main protection dashboard
├── GuardianAgentList.js       # Agent health and status
├── GuardianIncidentDetail.js  # Incident timeline + evidence + actions
├── ApprovalQueue.js           # Pending approvals with approve/reject
├── RemediationHistory.js      # Recent actions + verification status
└── GuardianWebSocket.js       # Guardian-specific WS handler
```

### 11.3 Protection Dashboard Layout

```
┌─────────────────────────────────────────────────────────────┐
│ Protection Dashboard                                         │
├─────────────────┬───────────────────────────────────────────┤
│ Agent Health    │ Active Incidents                          │
│ ┌─────────────┐ │ ┌─────────────────────────────────────┐   │
│ │ DESKTOP-01  │ │ │ 1. Suspicious persistence (HIGH)    │   │
│ │ ✅ Online   │ │ │    Timeline | Evidence | Actions     │   │
│ │ v2.0.0      │ │ │    [Approve] [Reject] [Rollback]    │   │
│ │ 12 events/s │ │ ├─────────────────────────────────────┤   │
│ ├─────────────┤ │ │ 2. C2 callback (CRITICAL)           │   │
│ │ LAPTOP-02   │ │ │    Timeline | Evidence | Actions     │   │
│ │ ⚠️ Degraded │ │ │    [Approve] [Reject] [Rollback]    │   │
│ │ v2.0.0      │ │ └─────────────────────────────────────┘   │
│ │ 3 events/s  │ │                                           │
│ └─────────────┘ │ Pending Approvals                         │
│                 │ ┌─────────────────────────────────────┐   │
│ Protection State│ │ Block 203.0.113.66 — reason: C2     │   │
│ ┌─────────────┐ │ │ Risk: Temporary firewall rule        │   │
│ │ Agents: 2   │ │ │ [Approve] [Reject] [Details]        │   │
│ │ Events: 847 │ │ └─────────────────────────────────────┘   │
│ │ Detections:5│ │                                           │
│ │ Incidents: 2│ │ Recent Remediation                        │
│ │ Approvals: 1│ │ ┌─────────────────────────────────────┐   │
│ └─────────────┘ │ │ ✅ Quarantine malware.exe — verified │   │
│                 │ │ 🔄 Block 10.0.0.5 — pending verify   │   │
│                 │ │ ❌ Terminate cmd.exe — rolled back    │   │
│                 │ └─────────────────────────────────────┘   │
└─────────────────┴───────────────────────────────────────────┘
```

### 11.4 Incident Detail View

```
┌─────────────────────────────────────────────────────────────┐
│ Incident: Suspicious persistence detected on DESKTOP-01     │
├─────────────────────────────────────────────────────────────┤
│ Status: triaged | Severity: HIGH | Priority: HIGH           │
├─────────────────────────────────────────────────────────────┤
│ MITRE ATT&CK: T1547.001 (Boot/Logon Autostart Execution)   │
├─────────────────────────────────────────────────────────────┤
│ Timeline:                                                    │
│ 14:23:01 — Registry Run key created by powershell.exe        │
│ 14:23:01 — Process spawned by svchost.exe (PID 1234)         │
│ 14:23:02 — Guardian detection: suspicious persistence         │
│ 14:23:03 — Response decision: disable_persistence_entry       │
│ 14:23:03 — Approval requested by system                      │
│ 14:25:00 — APPROVED by admin@example.com                     │
│ 14:25:01 — Snapshot created                                  │
│ 14:25:01 — Registry key disabled                             │
│ 14:25:02 — Verification: key state confirmed disabled         │
│ 14:25:02 — Commit: remediation successful                     │
├─────────────────────────────────────────────────────────────┤
│ What happened?                                               │
│ A new Run key was created in HKCU\Software\Microsoft\        │
│ Windows\CurrentVersion\Run pointing to a suspicious payload. │
├─────────────────────────────────────────────────────────────┤
│ Why?                                                         │
│ The persistence entry was created by a PowerShell process     │
│ spawned from an unusual parent. The executable path matches   │
│ a known malware pattern.                                      │
├─────────────────────────────────────────────────────────────┤
│ Evidence:                                                     │
│ [Registry snapshot] [Process tree] [File hash] [Network conn] │
├─────────────────────────────────────────────────────────────┤
│ What happens if I approve?                                    │
│ The Run key will be disabled (not deleted). The system will   │
│ no longer auto-execute the payload at logon.                  │
├─────────────────────────────────────────────────────────────┤
│ Can it be undone?                                             │
│ Yes. The original key value is preserved in the snapshot.     │
│ Rollback will re-enable it with the original value.           │
├─────────────────────────────────────────────────────────────┤
│ Did it work?                                                  │
│ ✅ Verification confirmed the key is disabled.                │
├─────────────────────────────────────────────────────────────┤
│ [Approve Action] [Reject] [Rollback] [View Audit History]    │
└─────────────────────────────────────────────────────────────┘
```

---

## 12. Windows Agent Architecture

### 12.1 Agent Directory Structure

```
guardian/
├── agent/
│   ├── __init__.py
│   ├── main.py              # Agent entry point
│   ├── config.py            # Agent configuration
│   ├── heartbeat.py         # Heartbeat loop
│   └── scheduler.py         # Event collection scheduler
├── collectors/
│   ├── __init__.py
│   ├── base.py              # BaseCollector interface
│   ├── process_monitor.py   # Process creation/termination events
│   ├── file_watcher.py      # File system activity (user-space only)
│   ├── network_monitor.py   # Network connections (user-space)
│   ├── persistence_monitor.py # Registry, scheduled tasks, startup
│   ├── registry_watcher.py  # Registry key changes (user-space polling)
│   └── security_settings.py # Security setting changes
├── detectors/
│   ├── __init__.py
│   ├── base.py              # BaseDetector interface
│   ├── persistence_detector.py  # Detect suspicious persistence
│   ├── process_detector.py      # Detect suspicious process behavior
│   ├── network_detector.py      # Detect suspicious network activity
│   ├── file_detector.py         # Detect suspicious file operations
│   └── policy_detector.py       # Policy-based detection rules
├── policy/
│   ├── __init__.py
│   ├── engine.py            # Policy evaluation engine
│   ├── rules.py             # Policy rule definitions
│   └── defaults.json        # Default policy rules
├── response/
│   ├── __init__.py
│   ├── decision.py          # ResponseDecision generation
│   ├── approval.py          # Approval request management
│   └── actions/
│       ├── __init__.py
│       ├── base.py          # Action interface
│       ├── block_ip.py      # Windows Firewall IP blocking
│       ├── disable_persistence.py  # Registry/scheduled task disabling
│       ├── quarantine_file.py      # File quarantine
│       ├── terminate_process.py    # Process termination
│       └── restore_setting.py      # Security setting restoration
├── rollback/
│   ├── __init__.py
│   └── manager.py           # Rollback management
├── verification/
│   ├── __init__.py
│   └── engine.py            # Verification engine
├── transport/
│   ├── __init__.py
│   ├── local_queue.py       # Local SQLite event queue
│   ├── sync.py              # Backend synchronization
│   └── offline.py           # Offline operation manager
├── storage/
│   ├── __init__.py
│   ├── local_db.py          # Local SQLite storage
│   ├── encrypted_store.py   # Encrypted sensitive data storage
│   └── cache.py             # Local event cache
└── tests/
    ├── __init__.py
    ├── test_collectors.py
    ├── test_detectors.py
    ├── test_policy.py
    ├── test_response.py
    ├── test_rollback.py
    ├── test_verification.py
    ├── test_transport.py
    └── test_offline.py
```

### 12.2 User-Space Collection Strategy

**DO NOT create a kernel driver.** All collection operates in user space:

| Collection | Method | User-Space Approach |
|---|---|---|
| Process events | ETW (Event Tracing for Windows) | Register consumers on `Microsoft-Windows-Kernel-Process` provider |
| File activity | Read-directory-changes-wait API | Monitor configured directories in user mode |
| Network connections | `GetExtendedTcpTable` / `GetExtendedUdpTable` | Periodic polling of connection tables |
| Registry changes | Registry key notification (RegNotifyChangeKeyValue) | Poll with change notification on target keys |
| Scheduled tasks | `schtasks.exe /query /xml` | Parse task XML output |
| Security settings | PowerShell cmdlet output parsing | `Get-MpPreference`, `Get-NetFirewallRule`, etc. |

### 12.3 Agent Runtime Model

```
┌─────────────────────────────────────────────┐
│ Guardian Agent (Windows Service or Console)  │
├─────────────────────────────────────────────┤
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Process  │  │ File     │  │ Network  │  │
│  │ Monitor  │  │ Watcher  │  │ Monitor  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │              │              │        │
│       └──────────────┼──────────────┘        │
│                      ▼                       │
│            ┌──────────────────┐              │
│            │  Event Normalizer │              │
│            │  (guardian.event.v1)│            │
│            └──────────────────┘              │
│                      │                       │
│          ┌───────────┴───────────┐           │
│          ▼                       ▼           │
│  ┌──────────────┐     ┌──────────────┐      │
│  │ Local Queue  │     │ Local Detect │      │
│  │ (SQLite)     │     │ (Policy)     │      │
│  └──────┬───────┘     └──────┬───────┘      │
│         │                     │              │
│         ▼                     ▼              │
│  ┌──────────────┐     ┌──────────────┐      │
│  │ Local Risk   │     │ Response     │      │
│  │ State        │     │ Decision     │      │
│  └──────┬───────┘     └──────┬───────┘      │
│         │                     │              │
│         └───────────┬─────────┘              │
│                     ▼                        │
│           ┌──────────────────┐               │
│           │ Backend Sync     │               │
│           │ (optional, when  │               │
│           │  backend available)│              │
│           └──────────────────┘               │
│                                              │
└─────────────────────────────────────────────┘
```

### 12.4 Local-First Operation (Phase 3)

```
Agent → Local Queue → Local Detection → Local Risk State → Backend Sync
```

**Local Queue (SQLite):**
- Bounded buffer: max 100,000 events per agent
- WAL mode for concurrent read/write
- Automatic rotation: oldest events pruned when buffer full
- Events assigned stable `event_id` at creation time

**Deduplication:**
- Event IDs are deterministic (SHA-256 of non-volatile fields)
- Idempotent insert: `INSERT OR IGNORE` pattern
- Duplicate detection at both local and backend level

**Offline Operation:**
- All detection runs locally against policy rules
- Local risk state maintained in SQLite
- Backend sync when connectivity available
- Retry with exponential backoff (1s, 2s, 4s, 8s, ... max 60s)
- Conflict resolution: most recent timestamp wins

**Encrypted Local Storage:**
- Sensitive evidence (file hashes, process command lines) encrypted at rest
- AES-256-GCM with agent-specific key derived from machine identity
- Key never leaves the machine
- `encrypted_store.py` handles encrypt/decrypt transparently

---

## 13. Security/Threat Model

### 13.1 Guardian v2 Assets

| Asset | Sensitivity |
|---|---|
| Guardian agent private keys | Critical |
| Local event queue (SQLite) | High |
| Encrypted evidence store | High |
| Approval requests/responses | High |
| Remediation action snapshots | High |
| Agent→Backend communication channel | High |
| Policy rules | Medium |
| Agent configuration | Medium |
| Heartbeat data | Low |

### 13.2 Threat Categories

#### A. Agent Compromise

| Threat | Mitigation |
|---|---|
| Attacker gains control of agent | Agent binary signed + checksum verified; heartbeat anomaly detection; agent can be remotely disabled |
| Agent impersonation | Agent registration requires token; each agent has unique key; heartbeat validates identity |
| Policy tampering | Policy rules signed and checksum-verified; changes require admin approval |

#### B. Response Abuse

| Threat | Mitigation |
|---|---|
| AI recommends destructive action | AI cannot execute — only recommends; human approval always required |
| Approval bypass | Approval checks enforced at API, agent, and database level; RBAC required |
| Malicious approval | Approval records are immutable audit trail; multiple admin approval for critical actions |
| Rollback abuse | Rollback requires original snapshot; rollback of rollback prevented |

#### C. Communication Interception

| Threat | Mitigation |
|---|---|
| Eavesdropping on agent→backend | HTTPS/TLS for all communication; WebSocket over WSS |
| Message tampering | Event IDs are SHA-256 hashed; evidence bags have integrity hashes |
| Replay attacks | Event IDs are deterministic and idempotent; timestamps validated |

#### D. Data Exfiltration

| Threat | Mitigation |
|---|---|
| Agent sends sensitive data | Evidence bags encrypted locally; only hashes sent to backend; privacy modes |
| Backend data leakage | JWT auth, RBAC, no sensitive data in error messages |
| Audit trail tampering | Audit records are append-only with timestamps |

### 13.3 AI Safety Rules

**AI may:**
- Classify detections
- Prioritize incidents
- Explain what happened
- Recommend specific actions
- Map to MITRE ATT&CK

**AI must NOT:**
- Directly execute any system command
- Modify firewall rules
- Delete files
- Kill processes
- Change registry settings
- Access the network
- Modify system configuration

**Enforcement:**
- ResponseDecision is a data-only object — no executable code
- Actions are implemented as separate, auditable classes
- Every action requires human approval (forbidden: `requires_approval = False`)
- Execution goes through Action → Snapshot → Execute → Verify → Commit flow

---

## 14. Trust Boundaries

### 14.1 Guardian v2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUST BOUNDARY MAP                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  TB1: Agent ↔ Operating System                               │
│  ├── Agent runs in user space (no kernel driver)             │
│  ├── Read-only collection (no modification during collection)│
│  ├── Encrypted local storage for sensitive data              │
│  └── Agent binary signed and checksum-verified               │
│                                                              │
│  TB2: Agent ↔ Local Storage                                  │
│  ├── SQLite with WAL mode                                    │
│  ├── AES-256-GCM encryption for sensitive evidence           │
│  ├── Bounded buffer with automatic rotation                  │
│  └── Deterministic event IDs (no volatile data in identity)  │
│                                                              │
│  TB3: Agent ↔ Backend API                                    │
│  ├── HTTPS/TLS required for all communication                │
│  ├── JWT authentication for agent registration               │
│  ├── Event integrity via SHA-256 hashing                     │
│  └── Idempotent event submission                             │
│                                                              │
│  TB4: Backend ↔ PostgreSQL                                   │
│  ├── Same trust boundary as v1.1                             │
│  ├── Guardian tables follow same access patterns             │
│  └── Migration-controlled schema changes                     │
│                                                              │
│  TB5: Backend ↔ Kafka                                       │
│  ├── Existing Kafka trust boundary unchanged                 │
│  └── Guardian events can optionally publish to Kafka          │
│                                                              │
│  TB6: Frontend ↔ Backend API                                 │
│  ├── Same JWT/RBAC as v1.1                                   │
│  ├── Guardian endpoints require same role checks             │
│  └── Approval actions require `administrator` or             │
│      `security_analyst` role                                 │
│                                                              │
│  TB7: Human ↔ Approval Workflow                              │
│  ├── Human must explicitly approve every action              │
│  ├── Approval is a first-class entity with audit trail       │
│  ├── No autonomous response (even for critical severity)     │
│  └── Approval expires after configurable timeout             │
│                                                              │
│  TB8: Action ↔ System                                        │
│  ├── Actions go through snapshot → execute → verify flow     │
│  ├── Every action is auditable and rollbackable              │
│  ├── Verification must confirm state change, not just        │
│  │   exit code                                               │
│  └── Actions are restricted to SAFE_ACTIONS whitelist        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 15. Attack Surfaces

### 15.1 Agent Attack Surface

| Surface | Risk | Mitigation |
|---|---|---|
| Agent binary tampering | High | Code signing, checksum verification, heartbeat anomaly detection |
| Agent configuration tampering | High | Signed policy rules, admin-only configuration changes |
| Local SQLite access | Medium | File system ACLs, encrypted sensitive data |
| ETW provider abuse | Medium | Minimal ETW consumers, output validation |
| PowerShell injection | Medium | No `shell=True`, structured output parsing only |
| Registry access | Medium | Read-only polling, no write operations during collection |

### 15.2 Backend API Attack Surface

| Surface | Risk | Mitigation |
|---|---|---|
| Agent registration endpoint | High | Token-based auth, rate limiting |
| Event ingestion endpoint | Medium | Input validation, size limits, deduplication |
| Approval endpoint | High | RBAC enforcement, immutable audit trail |
| Action execution endpoint | High | Pre-flight checks, snapshot requirement, verification |
| Rollback endpoint | High | Snapshot validation, audit trail |

### 15.3 Communication Attack Surface

| Surface | Risk | Mitigation |
|---|---|---|
| Agent→Backend channel | High | HTTPS/TLS, JWT auth, event integrity |
| WebSocket Guardian updates | Medium | WSS, token-based auth, same pattern as v1.1 |
| Local queue tampering | Medium | SQLite file permissions, encrypted storage |

### 15.4 Response Abuse Surface

| Surface | Risk | Mitigation |
|---|---|---|
| AI manipulation of ResponseDecision | Critical | AI is advisory only; human approval required |
| Approval bypass | Critical | Database-level enforcement; no autonomous execution |
| Snapshot tampering | High | Snapshots stored in encrypted format; integrity verified |
| Rollback manipulation | High | Rollback requires original snapshot; audit trail |

---

## 16. Testing Strategy

### 16.1 Test Categories

#### A. Event Normalization Tests
```python
# guardian/tests/test_event_normalization.py
- Test GuardianEvent deterministic event_id generation
- Test schema version enforcement
- Test evidence bag integrity hashing
- Test event field validation
- Test deduplication (same event submitted twice)
- Test event ordering (timestamp-based)
```

#### B. Local Buffering Tests
```python
# guardian/tests/test_local_queue.py
- Test bounded buffer (insert 100,001 events, verify oldest pruned)
- Test SQLite WAL mode concurrent access
- Test event persistence across agent restart
- Test buffer rotation under load
- Test deduplication at queue level
```

#### C. Offline Recovery Tests
```python
# guardian/tests/test_offline.py
- Test detection without backend connectivity
- Test local risk state maintenance
- Test backend sync after reconnection
- Test retry with exponential backoff
- Test conflict resolution (local vs backend timestamps)
- Test event replay after sync
```

#### D. Detection Tests
```python
# guardian/tests/test_detectors.py
- Test persistence detector with known-bad registry entries
- Test process detector with suspicious process trees
- Test network detector with C2-like connections
- Test file detector with ransomware-like behavior
- Test policy detector with custom rules
- Test detection confidence calibration
```

#### E. Policy Decision Tests
```python
# guardian/tests/test_policy.py
- Test policy rule evaluation (match/no-match)
- Test policy rule priority ordering
- Test policy rule conditions (field, operator, threshold)
- Test safe action whitelist enforcement
- Test unsafe action rejection
```

#### F. Approval Enforcement Tests
```python
# guardian/tests/test_approval.py
- Test approval required for all actions
- Test approval expiration
- Test RBAC enforcement (auditor cannot approve)
- Test approval audit trail immutability
- Test concurrent approval prevention
```

#### G. Remediation Action Tests
```python
# guardian/tests/test_actions.py
- Test pre-flight checks (admin, target existence, etc.)
- Test snapshot creation
- Test action execution
- Test action verification (state check, side effects)
- Test all 5 safe action types
- Test unsafe action rejection
```

#### H. Verification Tests
```python
# guardian/tests/test_verification.py
- Test verification step execution
- Test verification timeout handling
- Test verification retry with backoff
- Test evidence collection during verification
- Test verification failure detection
- Test verification does not trust exit codes
```

#### I. Rollback Tests
```python
# guardian/tests/test_rollback.py
- Test rollback with valid snapshot
- Test rollback verification
- Test rollback of non-rollbackable action (terminated process)
- Test rollback audit trail creation
- Test rollback prevention (no rollback of rollback)
```

#### J. Audit Record Tests
```python
# guardian/tests/test_audit.py
- Test approval record creation
- Test action execution record
- Test verification record
- Test rollback record
- Test record immutability
- Test record query and filtering
```

#### K. Authorization Tests
```python
# guardian/tests/test_auth.py
- Test agent registration requires valid token
- Test event ingestion requires correct role
- Test approval requires administrator or analyst role
- Test action execution requires administrator role
- Test rollback requires administrator role
- Test read-only auditor cannot modify any Guardian state
```

#### L. Replay/Idempotency Tests
```python
# guardian/tests/test_idempotency.py
- Test event deduplication (same event_id)
- Test detection deduplication (same detection_key)
- Test approval idempotency (same request_id)
- Test action idempotency (same action_id)
```

#### M. Failure Recovery Tests
```python
# guardian/tests/test_failure_recovery.py
- Test agent crash recovery (events in queue survive)
- Test backend unavailability (agent continues locally)
- Test partial action failure (snapshot enables rollback)
- Test verification failure (action marked for rollback)
- Test network interruption during sync
```

### 16.2 Security Tests (Prove AI Cannot Execute)

```python
# guardian/tests/test_ai_safety.py

def test_response_decision_is_data_only():
    """ResponseDecision must be a dataclass, not executable."""
    decision = ResponseDecision(...)
    assert isinstance(decision, dataclass)
    assert not hasattr(decision, 'execute')
    assert not hasattr(decision, 'apply')

def test_no_action_executes_without_approval():
    """Every action must have requires_approval = True."""
    for action_class in ALL_ACTION_CLASSES:
        action = action_class(target="test")
        assert action.requires_approval() is True

def test_actions_cannot_be_created_by_ai():
    """Actions must be created through the Action factory, not by AI output."""
    # AI produces ResponseDecision (data only)
    # System creates Action from ResponseDecision
    # Verify the chain: AI → Decision → Approval → Action
    ...

def test_safe_actions_whitelist_enforced():
    """Only SAFE_ACTIONS can be executed."""
    for action_type in SAFE_ACTIONS:
        assert action_type in ALLOWED_ACTION_TYPES
    # Any other action type must be rejected
    ...
```

---

## 17. Migration Strategy

### 17.1 Migration `004_guardian_core`

**Approach:** Additive only. No existing table modifications.

```python
# backend/migrations/versions/guardian_core_004.py

REVISION = "004_guardian_core"

def upgrade(engine, base):
    """Create all Guardian v2 tables."""
    # 1. Create guardian_agents
    # 2. Create guardian_heartbeats
    # 3. Create guardian_events
    # 4. Create guardian_detections
    # 5. Create guardian_response_decisions
    # 6. Create guardian_approval_requests
    # 7. Create guardian_approval_records
    # 8. Create guardian_remediation_actions
    # 9. Create guardian_verification_results
    # 10. Create guardian_rollback_records
    # 11. Create guardian_incidents
    # 12. Create guardian_incident_timeline
    # 13. Create all indexes
    # 14. Insert migration tracking entry
```

### 17.2 Migration Safety Rules

1. **No destructive changes.** All v1.1 tables remain untouched.
2. **Idempotent.** `CREATE TABLE IF NOT EXISTS` for all tables.
3. **Indexed.** All foreign keys and query-filtered columns indexed.
4. **Backward compatible.** v1.1 API continues to work without Guardian tables.
5. **Reversible.** `downgrade()` drops Guardian tables (safe since no v1.1 data depends on them).

### 17.3 Migration Testing

Following the existing pattern from `runtime-release-gate.yml`:
1. Migrate fresh database → verify all tables exist
2. Migrate existing v1.1 database → verify no data loss
3. Migrate twice (idempotency) → verify no duplicates
4. Verify legacy alert data preserved
5. Verify all indexes created
6. Verify foreign key constraints

---

## 18. Incremental Implementation Phases

### 18.1 Recommended First Implementation Slice

**Scope:** Guardian event ingestion + local queue + backend API

**Why this slice:**
- Small enough to complete and verify independently
- Provides immediate value (host-level event visibility)
- No response/remediation complexity yet
- Tests the data pipeline end-to-end
- Can be extended incrementally

**Deliverables:**
1. `guardian/collectors/base.py` — BaseCollector interface
2. `guardian/collectors/process_monitor.py` — Windows process event collector
3. `guardian/transport/local_queue.py` — SQLite local event queue
4. `guardian/transport/sync.py` — Backend synchronization
5. `guardian/agent/main.py` — Agent entry point
6. `guardian/agent/config.py` — Agent configuration
7. `backend/migrations/versions/guardian_core_004.py` — Database migration
8. Backend API endpoints: agent register, heartbeat, event ingestion
9. Tests for all new components

**Verification:**
- Agent starts and collects process events on Windows
- Events stored in local SQLite queue
- Events synced to backend when connectivity available
- Backend API returns Guardian events
- All existing tests still pass
- No changes to v1.1 behavior

### 18.2 Phase 2: Detection + Policy

**Add:** Policy engine, persistence detector, network detector, response decisions

### 18.3 Phase 3: Approval + Actions

**Add:** Approval workflow, action interface, 5 safe actions, verification engine

### 18.4 Phase 4: Rollback + Audit

**Add:** Rollback manager, audit trail, incident timeline

### 18.5 Phase 5: Guardian UI

**Add:** Protection tab, approval queue, incident detail view

### 18.6 Phase 6: Advanced Features

**Add:** File watcher, browser protection (planned only), signed updates

---

## Summary

| Deliverable | Status |
|---|---|
| 1. Current architecture assessment | ✅ Complete |
| 2. Gap analysis | ✅ Complete |
| 3. Guardian domain model | ✅ Complete |
| 4. Event schema | ✅ Complete |
| 5. ResponseDecision schema | ✅ Complete |
| 6. Action interface | ✅ Complete |
| 7. Verification interface | ✅ Complete |
| 8. Rollback design | ✅ Complete |
| 9. Database changes required | ✅ Complete |
| 10. API changes required | ✅ Complete |
| 11. Frontend changes required | ✅ Complete |
| 12. Windows agent architecture | ✅ Complete |
| 13. Security/threat model | ✅ Complete |
| 14. Trust boundaries | ✅ Complete |
| 15. Attack surfaces | ✅ Complete |
| 16. Testing strategy | ✅ Complete |
| 17. Migration strategy | ✅ Complete |
| 18. Incremental implementation phases | ✅ Complete |

**Recommended first slice:** Guardian event ingestion + local queue + backend API

**No files were modified during this audit.**
