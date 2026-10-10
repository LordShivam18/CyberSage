# Guardian Pilot Runbooks (PROVIDED — NOT EXECUTED)

## Onboarding a pilot endpoint

1. Confirm disposable/revertible image, eligible OS, Python 3.11+, `etw` installed, ETW privilege path.
2. Record hostname/OS/owner/consent in the pilot config (`validate_pilot_config` fails without them).
3. Install per `guardian.agent.install` plan (verified manifest; development vs signed path explicit).
4. Verify: stable identity persisted, collectors RUNNING or honest DEGRADED, first heartbeat seen,
   no duplicate server agent.
5. Enroll in monitoring mode only. Evidence: install manifest, health snapshot, backend agent row.

## Daily operations

1. Review agent health snapshots (identity/version/collectors/queue/sync/disk/auth) per endpoint.
2. Review backend readiness, guardian stats, safety status (kill switches, breakers, limiter).
3. Review queue depth/age and ack lag; reconcile against backend event counts.
4. Review detections/incidents/evaluations for the day; confirm stopping points for benign scenarios.
5. Record workload observations (alerts reviewed, triage minutes, duplicates, escalations, blocked flows).
6. File the daily evidence bundle under the scenario/correlation ids. Evidence: dated bundle + ledger.

## Incident handling (pilot)

1. Triage detections using the Phase 7 corpus expectations (do not invent detector capabilities).
2. Monitoring mode: no execution — verify `assert_no_executions` stays green for the window.
3. Approved-manual mode only: create approval → authorized user approves → verify single execution +
   independent verification + audit → replay check returns existing without side effects.
4. Any unexpected execution → emergency stop runbook below (S1).

## Emergency stop and kill-switch use

1. Activate the narrowest effective kill switch first (agent/action scope; global only if warranted).
2. Revoke grants (`POST /preauth/revoke`), disable policies, reject pending approvals — each audited.
3. Prove subsequent attempts block at the expected gate before any resume.
4. Escalate to security lead + policy owner + pilot operators. Evidence: all four audit record types.

## Grant revocation and authorization invalidation

1. Revoke via API (admin role); confirm `GET /preauth/{policy}` shows inactive + revoker/reason.
2. Confirm later attempts fail at `preauth_authorization` (stale/version/expiry reasons as applicable).
3. Re-activation, if ever justified, requires the full future-authorization gate (scorecards + sign-off).

## Agent disablement or removal

1. Stop service within the bounded timeout; confirm queue depth frozen (no loss).
2. Uninstall via plan default (data preserved) unless explicit opt-in data removal with signed approval.
3. Confirm backend shows no further heartbeats/events from the endpoint; archive the evidence bundle.

## Recovery and restoration

1. Follow `upgrade.recover_interrupted_upgrade` ordering; re-run idempotent migrations; re-verify digests.
2. Restore queue/identity snapshots only from ledgers; never fabricate rows.
3. Restart with readiness checks; drain queues; rebalance the reconciliation ledger.

## End-of-pilot reconciliation and decision report

1. Per scenario: fill `PilotEvidence`, run `reconcile()`, list unresolved items openly.
2. Compute metrics with `pilot/metrics.py` (labeling validity gates precision/recall; latencies with
   censoring; resources with provenance; ledgers for actions/workload).
3. Fill the scorecards in `docs/guardian_pilot_scorecard.md`; obtain sign-offs (`proceed`/`extend`/
   `remediate`/`stop`). No phase succeeds because implementation exists — evidence + sign-off decide.
