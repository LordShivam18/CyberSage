# Guardian Phase 7 — End-to-End Detection and Response (IMPLEMENTED — NOT TESTED)

## Logical path (all shared production logic, no pipeline duplication)

Host event → collection/normalization (`guardian.event.v1`) → ingestion
(`POST /api/v1/guardian/events`, idempotent `event_id`) → `DetectionDispatcher`
(detectors → evidence → risk → policy → incidents) → deterministic v5 policy
evaluation → approval / bounded grant → `SafetyEnvelope` → execution →
`VerificationManager` → explicit rollback → immutable audit.

## Corpus and expectations

See `guardian/validation/corpus.py` (10 scenarios, stable `e2e-*` ids):
benign process / parent-child / location; suspicious process / parent-child /
port 4444 / Run-key persistence; malformed-missing; duplicate; benign port 443.
Each states expected detectors, severity/confidence, incident behavior, risk
bounds, policy outcome, execution permission, and `must_not_happen` negatives.
Thresholds unchanged; unexpected behavior must be investigated, not tuned away.

## What the harness proves (developer-run)

- Manual path: approval-required → pending → approve → revalidate → execute
  once → verify + audit → replay safe; plus reject/expiry/stale/mismatch/role cases.
- Bounded path: explicit admin enable → persisted scope reload → bounds +
  every envelope gate → execute only when satisfied → revoke blocks later →
  kill/expiry/version-change blocks → replay/concurrency safe.
- Lifecycle: durable attempt, snapshot when required, pre-execution
  re-authorization, real execution result, independent verification
  (success vs execution-failure distinguished), explicit rollback only
  where permitted, immutable audit with actor/incident/approval/action/
  snapshot identities, no misleading success on finalize failure or
  interruption.
- Negatives: benign paths/ports/attributes, contradictory evidence,
  duplicate IDs, overlapping signals without double counting, thresholds,
  malformed targets.
- Duplicates/concurrency at callback/queue/HTTP/detection/incident/
  execution boundaries against UNIQUE constraints + deterministic IDs
  (at-least-once delivery + idempotent storage; no global exactly-once claim).
- Outage/recovery reconciliation table (generated/observed/queued/batches/
  acked/persisted/queued-or-quarantined) with durable-acceptance defined as
  per-event `created`/`duplicate` plus verifiable backend row.
- Revocation/kill/breaker/failed-verification mandatory cases (see
  `FAILURE_CASES` in `e2e_harness.py`; failed verification uses the
  `leave-unset` harness mode).

## Live Windows path

Disposable host only (see `guardian/validation/live_windows_checklist.md`
to be written from the handoff checklist). Benign events stop where
expected; suspicious-but-benign fixtures exercise detection. Unsafe live
execution is replaced by the harmless `test:noop_safe` action with the
limitation documented.

## Status

- IMPLEMENTED — NOT TESTED. Backend fixture harness + live checklist
  provided; live runs, outage injection, and full reconciliation are
  NOT PERFORMED here.
