# Guardian Operational Runbooks (PROVIDED — NOT EXECUTED)

Conventions: each runbook lists symptoms, severity, diagnostic steps, containment,
recovery steps, verification evidence to collect later, escalation criteria, and explicit
stop conditions. Severity: S1 emergency, S2 urgent, S3 degraded, S4 informational.
Do not execute response actions against real systems without authorization.

## 1. Endpoint agent offline or degraded (S2/S3)

- Symptoms: missing heartbeats, `agent_health.json` stale, backend shows no recent events.
- Severity: S2 if a pilot endpoint is silent past 2 heartbeat intervals; S3 if DEGRADED with queue growth.
- Diagnostics: read `agent_health.json` (identity/version/collectors/queue/sync/disk/auth); check service state;
  check backend `/api/v1/ready` and guardian stats; compare queue depth/age trend.
- Containment: none required (telemetry gap only); note the gap window for later reconciliation.
- Recovery: restart service per install plan; if still degraded, follow runbook 2 (ETW) or 3 (backend).
- Evidence: health snapshots before/after, service logs, queue depth/age series, backend event counts.
- Escalation: endpoint owner + Guardian operator after 30 min unresolved.
- Stop: agent healthy or gap formally accepted and recorded; do not reinstall blindly more than twice.

## 2. ETW collection failure (S3)

- Symptoms: collector health `degraded`, `events_received` static, `etw_available=false` or reconnect count rising.
- Severity: S3 (telemetry gap, no response impact).
- Diagnostics: confirm Windows + pywin32/`etw` installed; check `SeSystemProfilePrivilege`/elevation;
  session-name collisions (`GuardianProcessTrace`/`GuardianNetworkTrace`); provider GUID config.
- Containment: record the gap; process queue continues to drain already-collected events.
- Recovery: fix privilege/dependency, restart collector (bounded backoff already automatic); verify
  `running` + rising `events_received`.
- Evidence: collector stats, ETW error lines (redacted), provider/GUID config, before/after counts.
- Escalation: endpoint admin for privilege grants.
- Stop: RUNNING confirmed or DEGRADED formally accepted with compensating monitoring.

## 3. Backend or database outage (S1/S2)

- Symptoms: sync failures rising, backoff growing, `/api/v1/ready` failing or `database.ok=false`.
- Severity: S1 if all ingestion down; S2 if single-component.
- Diagnostics: backend logs, `pg_isready`/compose health, migration revision vs runner, disk on db host.
- Containment: agents continue collecting into bounded queues; warn operators of ack lag; freeze policy changes.
- Recovery: restore backend/DB (see compose docs), confirm `/ready` healthy, watch ack lag drain to zero.
- Evidence: outage window, queue depth/age per agent, batches attempted/acked, backend row counts.
- Escalation: platform owner immediately for S1.
- Stop: `/ready` healthy AND ack lag drained AND reconciliation ledger balanced.

## 4. Queue growth, acknowledgement lag, unreconciled events (S2/S3)

- Symptoms: `total_active` climbing, oldest age growing, `consecutive_failures` > 0, duplicates_acknowledged flat.
- Severity: S2 past 80% capacity; S3 otherwise.
- Diagnostics: per-agent `queue_stats()` + `queue_depth_age()`; sync `health()`; backend ingestion results
  (`created` vs `duplicate`); 429/5xx vs 401/403/422 classification.
- Containment: stop re-sending invalid payloads (quarantine path handles it); do not purge pending to "fix" metrics.
- Recovery: fix backend/auth/throttle cause; allow jittered retry; expand capacity only via validated config.
- Evidence: depth/age series, batch sizes/bytes, ack/dupe counts, backend rows.
- Escalation: platform owner if near capacity; policy owner if invalid payloads implicate a detector change.
- Stop: depth back under 50% AND oldest age under interval AND ledger reconciled.

## 5. Disk exhaustion and persistence failures (S1/S2)

- Symptoms: disk free below minimum, SQLite write errors, WAL growth, queue insert failures.
- Severity: S1 if the backend DB disk is full; S2 for endpoint data disks.
- Diagnostics: `shutil` free-bytes in health snapshot; backend disk alerts; largest tables/dirs.
- Containment: stop non-essential writes; run retention in dry-run to plan; never delete pending queue rows.
- Recovery: free space, run bounded retention (`--apply`), confirm writes succeed, re-verify snapshots.
- Evidence: before/after free bytes, retention plan vs executed counts, error lines.
- Escalation: platform/infra owner immediately for backend disk.
- Stop: free bytes above minimum for 3 consecutive checks AND writes succeeding.

## 6. Invalid configuration or certificate/signature verification failure (S2)

- Symptoms: startup validation errors; `verify`/`verify-signature` failures; service fails to start.
- Severity: S2 (fail-closed by design).
- Diagnostics: run config validation output (redacted); compare file vs env precedence; check manifest digests
  and fingerprint configuration; confirm clock skew for expirations.
- Containment: keep the previous known-good version running; do not bypass verification.
- Recovery: fix config/signing material; re-verify; restart within the bounded timeout.
- Evidence: redacted config diff, verification output, certificate fingerprint record (public part only).
- Escalation: release owner for signing-trust issues.
- Stop: validation + verification green AND readiness (not just liveness) confirmed.

## 7. Failed upgrade, rollback, and service recovery (S2)

- Symptoms: pre-upgrade check failures, interrupted migration, version mismatch, service start loop.
- Severity: S2.
- Diagnostics: upgrade report per check; `schema_migrations` vs runner list; backup ledger digests.
- Containment: halt at the failing step; preserve data dir and backup dir untouched.
- Recovery: follow `recover_interrupted_upgrade()` order (migrations rerun idempotent; restore snapshots only
  if corrupt; re-verify digests; restart with readiness check).
- Evidence: upgrade report, backup ledger, migration revisions before/after, health snapshots.
- Escalation: release + platform owners if data integrity is in doubt.
- Stop: readiness green on the intended version OR bounded rollback complete with rows preserved.

## 8. Suspected compromise of an endpoint agent or its credentials (S1)

- Symptoms: unexpected registration, unknown agent_key activity, anomalous heartbeat metadata, leaked token suspicion.
- Severity: S1.
- Diagnostics: list agents, audit events for the agent_key, heartbeat history, queue/auth health.
- Containment: revoke the credential server-side; revoke any preauth grants for affected policies;
  activate scoped kill switch (agent scope) — never global unless warranted.
- Recovery: re-provision a fresh agent_key + DPAPI blob out-of-band; re-register; verify identity matches.
- Evidence: audit trail, revocation records, kill-switch records, re-registration identity.
- Escalation: security lead immediately; treat as incident, not routine ops.
- Stop: old credential invalidated AND new identity verified AND grants re-evaluated.

## 9. Unauthorized or unexpected response actions (S1)

- Symptoms: envelope run without a matching approval/grant, unknown actor, target outside scope.
- Severity: S1.
- Diagnostics: envelope gates for the execution_id (which gate passed/failed and why), approval/grant rows,
  policy version at execution time, kill-switch state at that time.
- Containment: activate applicable kill switch immediately; revoke the grant; disable the policy if needed.
- Recovery: only after root cause (stale version? forged binding? mis-scoped grant?) is fixed and reviewed.
- Evidence: full gate list, approval/grant snapshots, policy version history, audit records.
- Escalation: security lead + policy owner immediately.
- Stop: cause remediated AND kill switch deliberately cleared by an authorized operator (recorded).

## 10. Audit gaps or inconsistencies (S1/S2)

- Symptoms: execution without audit row, mismatched counts across events→detections→incidents→
  evaluations→executions→audit, missing per-category rows.
- Severity: S1 if executions lack audit; S2 for telemetry gaps.
- Diagnostics: run the Phase 9 reconciliation schema per scenario/correlation id; list unresolved items.
- Containment: freeze further executions on the affected path until the gap is explained.
- Recovery: backfill only genuinely missing derived rows from source evidence; never fabricate audit rows.
- Evidence: reconciliation report with explicit unresolved list.
- Escalation: security lead for audit-family gaps.
- Stop: ledger reconciled OR gaps formally recorded as known limitations with owner + date.

## 11. Emergency revocation, policy disabling, and kill-switch activation (S1)

- Symptoms: any unsafe authorization behavior, active incident requiring containment of the responder.
- Severity: S1.
- Diagnostics: confirm scope (global vs agent vs action) and the exact policy/grant/approval to invalidate.
- Containment (in order): kill switch (narrowest effective scope first) → revoke grant → disable policy →
  reject pending approvals. Each step is audited with actor/reason.
- Recovery: verify subsequent attempts block at the expected gate; clear switches/grants only deliberately.
- Evidence: kill-switch, revocation, disable, and rejection audit records with timestamps.
- Escalation: security lead + policy owner; notify pilot operators.
- Stop: blocked-at-expected-gate proven AND a return-to-operation plan signed off.

## 12. Evidence preservation, recovery, and safe return to operation (S2)

- Symptoms: post-incident or post-outage state needing a controlled resume.
- Severity: S2.
- Diagnostics: reconciliation ledger, backup ledgers, retention plans (dry-run), health snapshots.
- Containment: keep affected components stopped/degraded until evidence is copied.
- Recovery: restore from ledgers (never fabricate), re-run migrations idempotently, re-verify artifacts,
  restart with readiness checks, drain queues, rebalance the ledger.
- Evidence: preserved copies with digests, restoration log, final reconciliation report.
- Escalation: evidence owner + platform owner.
- Stop: ledger reconciled AND readiness green AND a signed return-to-operation note.
