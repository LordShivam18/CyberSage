# Guardian Phase 5 Slice 4 — Bounded Pre-authorization (IMPLEMENTED — NOT TESTED)

## Authorization model

- Default: pre-authorization **disabled**. Absence of an active
  `guardian_preauth_grants` row means the envelope follows the Slice 2
  approved-manual path unchanged.
- An `ALLOW` evaluation alone never authorizes execution.
- Bounded execution requires **all** of:
  1. Policy exists, enabled, correct mode, unexpired, version matches.
  2. Fresh deterministic evaluation does not DENY.
  3. A matching rule with `approval_mode == pre_authorized`.
  4. An active grant bound to the policy's **current** version.
  5. Action in grant `allowed_actions` (concrete, registered, no wildcards).
  6. Target inside grant `target_scope`; agent inside `agent_scope` when set.
  7. `risk_score <= grant.max_risk_score`; grant frequency caps satisfied.
  8. Grant unexpired; kill switch clear; breaker closed; limiter/cooldown clear;
     target validation passes; snapshot/audit/verification/rollback as usual.
- Slice 4 gate order: `... policy_authorization → preauth_authorization → approval`.
  Manual path records `manual_path_preauth_not_applicable` and requires a
  valid APPROVED approval. Bounded path records `grant_authorizes_request`
  and `approval_not_required_preauthorized_bounded` without consuming approval.
- Stale policy/grant versions, revoked/inactive grants, expired grants,
  out-of-scope actions/targets, risk over cap, unknown modes, and
  conflicting/ambiguous authorization all fail closed (blocked, never executed).

## Activation / revocation

- `POST /automation/v5/preauth/activate` (administrator only): validates
  bounds, requires a PRE_AUTHORIZED rule per allowed action in the current
  policy version, binds that version, audits actor/timestamps/scope.
- `POST /automation/v5/preauth/revoke` (administrator only): sets
  `active=False`, records revoker/reason; never deletes.
- `GET /preauth`, `GET /preauth/{policy_id}` (view roles): authoritative state.
- The envelope reads the row per request (no cache); restarts cannot preserve
  stale authorization. Policy edits require re-activation.
- Kill-switch activation overrides all authorization (earlier gate).

## AI boundary

- AI remains text-only. The envelope and grant store take no AI input.
- Activation, grants, approvals, and execution require authenticated human
  roles; `AiBoundaryValidator` structural keys still forbid
  `policy/approval/kill_switch/rate_limit/circuit_breaker/rbac` in AI text.
- Provided harness includes fabricated-text cases asserting no influence.

## Migration

- `010_guardian_phase5_slice4` creates `guardian_preauth_grants`
  (UNIQUE policy_id). Additive, idempotent, PostgreSQL + SQLite compatible.
  No rows seeded: nothing is auto-activated.

## Status

- IMPLEMENTED — NOT TESTED. See `guardian/tests/test_phase5_slice4_preauth.py`
  (harness provided, not executed) and the manual checklist in the handoff.
