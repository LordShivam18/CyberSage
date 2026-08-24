# CyberSage Guardian v2 — Phase 1

## Overview

Guardian v2 Phase 1 adds **host-level event collection** and **local-first operation** to CyberSage. This is the foundation for the full Guardian protection agent that will eventually provide detection, explanation, recommendation, approval, remediation, verification, and rollback capabilities.

Phase 1 scope: **event ingestion + local queue + backend API**.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Guardian Agent (Phase 1)                                    │
│                                                             │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │ Process      │     │ (Future:     │                     │
│  │ Monitor      │     │  File, Net,  │                     │
│  │ Collector    │     │  Persistence)│                     │
│  └──────┬───────┘     └──────────────┘                     │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │ GuardianEvent│  (normalized, deterministic event_id)     │
│  └──────┬───────┘                                           │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────┐     ┌──────────────┐                     │
│  │ Local Queue  │────▶│ Sync Worker  │                     │
│  │ (SQLite)     │     │ (async)      │                     │
│  └──────────────┘     └──────┬───────┘                     │
│                              │                              │
└──────────────────────────────┼──────────────────────────────┘
                               │ HTTPS
                               ▼
                    ┌──────────────────┐
                    │ CyberSage Backend│
                    │ (FastAPI)        │
                    │                  │
                    │ POST /guardian/  │
                    │   agents/register│
                    │ POST /guardian/  │
                    │   heartbeat      │
                    │ POST /guardian/  │
                    │   events         │
                    │ GET  /guardian/  │
                    │   events         │
                    │ GET  /guardian/  │
                    │   agents         │
                    │ GET  /guardian/  │
                    │   stats          │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ PostgreSQL       │
                    │ guardian_agents  │
                    │ guardian_events  │
                    │ guardian_heartbeats│
                    └──────────────────┘
```

## Local-First Queue

Events are buffered in a local SQLite database. The agent operates independently of the backend:

- **Backend available:** Events flow from collector → queue → sync worker → backend API
- **Backend unavailable:** Collector continues, queue accumulates, sync worker retries with exponential backoff
- **Queue full:** New events are rejected with `QueueOverflow`; existing events are not dropped

Queue states: `pending` → `sending` → `sent` | `failed` → `pending` (retry)

## Event Schema

Schema version: `guardian.event.v1`

| Field | Type | Description |
|---|---|---|
| `event_id` | string | Deterministic SHA-256-derived ID (no PID) |
| `schema_version` | string | Always `guardian.event.v1` |
| `timestamp` | datetime | Event creation time |
| `event_category` | string | `process`, `file`, `network`, `persistence` |
| `host_id` | string | Stable host identifier |
| `process_name` | string? | Process name |
| `process_exe_path` | string? | Executable path |
| `process_exe_hash_sha256` | string? | SHA-256 of executable |
| `process_command_line` | string? | Command line |
| `parent_process_name` | string? | Parent process name |
| `user_name` | string? | User context |
| `evidence` | dict? | Structured evidence |
| `raw_event` | dict? | Original event data |

## Authentication

All Guardian API endpoints require JWT authentication. Agents authenticate using the existing user/RBAC system. Required roles:

| Endpoint | Roles |
|---|---|
| `POST /agents/register` | admin, analyst, responder |
| `POST /heartbeat` | admin, analyst, responder |
| `POST /events` | admin, analyst, responder |
| `GET /events` | admin, analyst, responder, auditor |
| `GET /agents` | admin, analyst, responder, auditor |
| `GET /stats` | admin, analyst, responder, auditor |

## Offline Behavior

When the backend is unavailable:

1. Agent starts normally
2. Registration fails with warning (agent continues)
3. Collector operates normally
4. Events enter local SQLite queue
5. Sync worker retries with exponential backoff (2s → 4s → 8s → ... → 60s max)
6. Heartbeats fail silently (non-critical)
7. When backend reconnects, events are synced

## Event ID Generation

Event IDs are computed from **non-volatile fields only**:

```
event_id = "guardian-" + SHA256(
    host_id | event_category | exe_path | exe_hash |
    file_path | dest_ip | dest_port | persistence_path | timestamp
)
```

**PID is deliberately excluded** because it is ephemeral and would make the ID non-idempotent across retries.

## Retry Behavior

- **Transient errors** (network timeout, server 5xx): Event returned to `pending` queue, retry with exponential backoff
- **Permanent errors** (401, 403, 422): Event marked as `failed`, no retry
- **Max retries:** 5 attempts before permanent `failed` state

## Current State (Phase 2.5)

Guardian event ingestion is now connected to the detection/risk/policy pipeline. When events are submitted via `POST /api/v1/guardian/events`, they are automatically processed through detectors, evidence aggregation, risk scoring, and policy evaluation. There is intentionally no separate API for clients to submit Detection objects directly — detections are produced by the deterministic pipeline from ingested events.

## Limitations

- Only process lifecycle events are collected by the placeholder ETW collector (no live file, network, or persistence monitoring)
- ETW integration is a placeholder (production requires `etw` or `pywintrace` library)
- Detection processing runs synchronously during event ingestion — future Phase 3 work may move this to a background worker for throughput/scalability
- No remediation, approval execution, or rollback is implemented
- No Guardian UI tab
- No encrypted local storage for sensitive evidence (planned for later phases)

## Windows Support

The process monitor collector is designed for Windows ETW (Event Tracing for Windows). On non-Windows platforms, the collector operates in **degraded mode** — it starts but does not produce live events. This allows testing and development on any platform.

## Files Changed

| File | Description |
|---|---|
| `guardian/__init__.py` | Guardian package |
| `guardian/models/event.py` | GuardianEvent schema |
| `guardian/collectors/base.py` | BaseCollector interface |
| `guardian/collectors/process_monitor.py` | Windows process collector |
| `guardian/transport/local_queue.py` | SQLite event queue |
| `guardian/transport/sync.py` | Backend sync worker |
| `guardian/agent/config.py` | Agent configuration |
| `guardian/agent/main.py` | Agent entry point |
| `guardian/tests/__init__.py` | Tests package |
| `guardian/tests/test_event_model.py` | Event model tests |
| `guardian/tests/test_queue.py` | Queue tests |
| `guardian/tests/test_collector.py` | Collector tests |
| `guardian/tests/test_sync.py` | Sync worker tests |
| `guardian/tests/test_config.py` | Config tests |
| `guardian/tests/test_api_integration.py` | API integration tests |
| `backend/api_guardian.py` | Guardian API router |
| `backend/models.py` | Added GuardianAgent, GuardianHeartbeat, GuardianEvent ORM models |
| `backend/main.py` | Registered guardian router |
| `backend/migrations/versions/guardian_core_004.py` | Migration 004 |
| `backend/migrations/runner.py` | Registered migration 004 |
| `docs/guardian-v2-phase1.md` | This document |
