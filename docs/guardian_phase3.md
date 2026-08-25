# Guardian v2 Phase 3 — Controlled Response, Approval, Verification, and Rollback

## Overview

Phase 3 introduces controlled defensive response to the Guardian system. Every actionable response must pass an explicit approval boundary. The system NEVER executes an action solely because an AI, detector, or policy engine recommended it.

## Architecture

```
ResponseDecision → ApprovalRequest → Approved Action → Pre-execution Snapshot → Deterministic Execution → Independent Verification → Rollback on verified failure → Immutable Audit Record
```

### Key Invariants

1. **No implicit approval** — Every action requires explicit human approval
2. **No auto-approval** — Severity alone cannot trigger execution
3. **No AI execution** — AI may explain, summarize, assist; never execute
4. **Deterministic execution** — Actions use strict allowlists, no arbitrary commands
5. **Independent verification** — Never trust process exit code alone
6. **Immutable audit** — All actions are recorded and cannot be deleted

## Action Architecture

### Abstract Action Interface

All response actions implement `BaseAction` with separated phases:

| Phase | Method | Purpose |
|-------|--------|---------|
| Planning | `validate()` | Check preconditions and target validity |
| Snapshot | `snapshot()` | Capture pre-execution state |
| Execution | `execute()` | Perform the action |
| Verification | `verify()` | Independently confirm the action took effect |
| Rollback | `rollback()` | Undo the action if supported |
| Description | `describe()` | Human-readable description |

### Registered Actions

| Action | Type | Name | Rollback |
|--------|------|------|----------|
| Terminate Process | `process` | `terminate_process` | No |
| Block Destination | `network` | `block_destination` | Yes |
| Disable Persistence | `persistence` | `disable_persistence_entry` | Yes |

### Safety Constraints

- No `shell=True`
- No arbitrary shell execution
- No arbitrary PowerShell/cmd
- No arbitrary command strings
- Strict allowlists for all targets
- Protected process names/PIDs cannot be terminated
- System-critical persistence locations cannot be modified
- IP addresses are validated (no loopback, no multicast)

## Approval Model

### Approval Request Lifecycle

```
pending → approved | rejected | expired | cancelled
```

### Approval Fields

- `approval_id` — Deterministic, collision-resistant ID
- `incident_id` — Associated incident
- `decision_id` — Links to ResponseDecision
- `requested_action` — Action to be taken
- `action_type` — Action category
- `target` — Target specification (JSON)
- `rationale` — Why this action is needed
- `risk` — Risk assessment data
- `status` — Current lifecycle state
- `expires_at` — TTL (default 30 minutes)

### Stale-Decision Protection

Before execution, the system revalidates:
- Incident state
- Decision version
- Target identity
- Action parameters
- Approval expiry
- Current policy
- Current risk state

If anything changed, execution **fails closed**.

## RBAC

| Role | View | Approve | Reject | Execute |
|------|------|---------|--------|---------|
| read_only_auditor | ✓ | ✗ | ✗ | ✗ |
| security_analyst | ✓ | ✓ | ✓ | ✗ |
| incident_responder | ✓ | ✓ | ✓ | ✓ |
| administrator | ✓ | ✓ | ✓ | ✓ |

## Action State Machine

```
planned → awaiting_approval → approved → executing → verifying → succeeded

Failure branches:
approved → execution_failed → rollback_available → rollback_requested → rolling_back → rolled_back / rollback_failed
approved → verification_failed → rollback_available → ...

Rejected path:
awaiting_approval → rejected

Expired path:
awaiting_approval → expired

Invalid/stale path:
approved → stale → blocked
```

## Snapshot Model

- Immutable once created
- Contains: target, prior_state, metadata
- Integrity hash for tamper detection
- Schema version: `guardian.snapshot.v1`

## Verification Model

- Independent of execution result
- Produces `VerificationResult` with:
  - `passed` — Boolean
  - `checks` — List of check results
  - `evidence` — Supporting data
  - `observed_state` — What was observed
  - `failure_reason` — Why it failed

## Rollback Model

- Only when `rollback_supported` is True
- Uses stored immutable snapshot
- States: `not_supported | available | requested | running | succeeded | failed`
- Rollback itself is audited
- No automatic rollback on verification failure

## Audit Trail

Immutable, append-oriented records:
- `audit_id` — Deterministic ID
- `incident_id`, `approval_id`, `action_id` — Links
- `actor` — Authenticated user
- `action_type`, `target` — What was done
- `snapshot_id`, `verification_result`, `rollback_result` — Outcomes
- `status`, `error` — Final state

No secrets are logged. No records are deleted.

## Idempotency

- Same execution request returns prior result
- `action_execution_id` prevents duplicate execution
- Unique constraints on approval/action IDs
- Concurrent execution reservation via status check

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/guardian/approvals` | Create approval request |
| GET | `/api/v1/guardian/approvals` | List approval requests |
| GET | `/api/v1/guardian/approvals/{id}` | Get approval detail |
| POST | `/api/v1/guardian/approvals/{id}/approve` | Approve request |
| POST | `/api/v1/guardian/approvals/{id}/reject` | Reject request |
| POST | `/api/v1/guardian/actions/{id}/execute` | Execute approved action |
| POST | `/api/v1/guardian/actions/{id}/rollback` | Request rollback |
| GET | `/api/v1/guardian/actions` | List action attempts |
| GET | `/api/v1/guardian/actions/{id}` | Get action detail |
| GET | `/api/v1/guardian/actions/registry` | List registered actions |
| GET | `/api/v1/guardian/audit` | List audit records |

## Migration 006

Creates 7 new tables:
- `guardian_approval_requests`
- `guardian_approvals`
- `guardian_action_attempts`
- `guardian_action_snapshots`
- `guardian_action_verifications`
- `guardian_action_rollbacks`
- `guardian_action_audit`

## Trust Boundaries

1. **AI Boundary** — AI cannot execute actions, generate commands, or bypass approval
2. **Approval Boundary** — No action executes without explicit approval
3. **Execution Boundary** — Actions use strict allowlists, no arbitrary operations
4. **Verification Boundary** — Independent verification of all outcomes
5. **Audit Boundary** — All actions are recorded immutably

## Security Invariants

- ✗ No `shell=True`
- ✗ No arbitrary shell execution
- ✗ No arbitrary PowerShell/cmd
- ✗ No arbitrary command strings
- ✗ No approval bypass
- ✗ No automatic execution from AI output
- ✗ No silent failure
- ✗ No audit suppression
- ✓ All actions authenticated
- ✓ All actions RBAC-controlled
- ✓ All actions auditable

## Known Limitations

- ETW remains a placeholder (Phase 4)
- No Guardian UI yet (Phase 4)
- Process termination is not reversible (no rollback)
- Network blocking uses platform-specific APIs (iptables/netsh)
- Snapshot integrity relies on hash comparison (not cryptographic signing)
