# Guardian Phase 8 — Secure Deployment and Operations (IMPLEMENTED — NOT TESTED)

## 8.1 Release integrity and signed artifacts

- Root `VERSION` remains authoritative (`backend/release.py`, `scripts/version_contract.py`).
- Agent bundle manifest: `scripts/guardian_release.py manifest --repo . --out <file>` records
  `guardian/{agent,collectors,transport,models,ops}` sources plus
  `backend/requirements.txt`, `portable/pyproject.toml`, `VERSION` with SHA-256 + sizes,
  source revision (best effort, `unknown` when unavailable), timestamp, and `signing: unsigned`.
- Verify before install/upgrade: `guardian_release.py verify --repo . --manifest <file>` recomputes
  every digest and fails closed on any mismatch, missing input, unsafe path, or VERSION drift.
- Reproducibility is NOT claimed: the manifest records inputs so a human can recheck them later;
  PyInstaller binaries and timestamps are not byte-reproducible claims.
- Signing workflow: releases are `unsigned` unless an authorized release certificate is configured
  externally. `guardian_release.py verify-signature --manifest <file> --expect-fingerprint <fp>` fails
  closed when the manifest is not marked signed, the fingerprint is unconfigured, the detached
  `.sig` is absent, or the fingerprint mismatches. It never prints, embeds, commits, or generates a
  production key. Production installs with missing/invalid signatures must be rejected; development
  installs must be explicitly labeled development. Certificate provisioning, renewal, expiration, and
  revocation are operator prerequisites documented in `docs/guardian_runbooks.md` (certificate runbook).

## 8.2 Least-privilege service installation

- Plans first: `python -m guardian.agent.install --plan install|upgrade|rollback|uninstall` prints a
  validated JSON plan (dry-run default; `--apply` refuses to execute in this session and must later run
  on Windows with elevation).
- `plan_install` enforces: manifest + signature verification first, restrictive ACLs on program/data/log
  dirs, versioned file deployment with digests, DPAPI-protected secret provisioning (never logged),
  dedicated service account (`GUARDIAN_SERVICE_ACCOUNT`, default `NT SERVICE\CyberSageGuardian`),
  explicit dependencies (`GUARDIAN_SERVICE_DEPENDENCIES`, default empty with guidance), bounded start.
- Account guidance constant `SERVICE_ACCOUNT_GUIDANCE`: Log on as a service only, read/execute program
  dir, read/write data/log/queue dirs only, no interactive logon, no Administrators membership.
- ETW privilege separation: `SeSystemProfilePrivilege` (or local admin) for kernel providers is an
  endpoint prerequisite, distinct from install-time elevation. Administrator-only maintenance
  (install/remove/upgrade secrets) is separated from normal service execution at runtime.
- Restarts reuse persisted identity (`agent_identity.json`) — no duplicate endpoint identities — and
  recover sending leases — no lost queued events. Startup ordering: config validate → data dir/ACLs →
  identity → queue + lease recovery → collectors → sync → registration → heartbeat.

## 8.3 Safe upgrades and rollback

- `guardian/agent/upgrade.py::pre_upgrade_checks` validates version ordering (downgrades must use the
  rollback procedure), migration-runner readability with append-only revision inventory, data-dir and
  queue-DB readability, and free disk space. Any failure aborts before any change.
- Backend migrations reuse `backend/migrations/runner.py` (idempotent, ordered; no duplicate system).
- Backups: agent queue DB via SQLite backup API + WAL sidecars + identity/health snapshots + ledger with
  digests; server grants/approvals/audit preserved by a `pg_dump` prerequisite (guidance, not executed).
- Rollback (`plan_rollback`): restore files/config/queue snapshots from the ledger; database rollback is
  honestly bounded — append-only revisions (`008`, `009`, `010`) are kept, never rewritten; application
  files may revert while rows are preserved. `recover_interrupted_upgrade()` gives the ordered recovery.
- Queued events, identity, grants, approvals, and audit records are never silently deleted or reset to
  make an upgrade succeed.

## 8.4 Configuration and secret management

- Single approach: built-in defaults < JSON config file (`schema_version: 1`, known keys only) <
  environment variables (`guardian/agent/config_file.py`). Unknown file keys and plaintext
  `auth_token` in files are rejected fail-closed.
- `AgentConfig` extended additively: `service_account`, `service_dependencies`, `program_dir`,
  `log_dir` with traversal/NUL/length validation. Production requires HTTPS backend URL
  (`validate_production`); missing/invalid values refuse start rather than downgrading security.
- `to_redacted_dict()` and health snapshots redact `auth_token`/tokens/passwords/key material;
  `secure_storage.redact()` is the single redaction helper. Rotation = overwrite the DPAPI blob;
  loss = re-provision `GUARDIAN_AUTH_TOKEN` (documented failure assumption).
- Security-posture inventory `SECURITY_POSTURE_SETTINGS` flags telemetry/retention/privilege/policy/
  preauth/kill-switch changes for review. Config migration helper `migrate_config_dict()` is explicit.

## 8.5 Retention, cleanup, and storage recovery

- Backend policy table `backend/retention.py::RETENTION_POLICIES` (telemetry 30–365d, incidents 730d,
  evaluations/audit/envelope runs 1095d; organization periods are configuration decisions).
  `validate_retention_config` (7–3650d, unknown categories rejected), `plan_cleanup` (dry-run counts),
  `execute_cleanup` (bounded `LIMIT 1000`/category, telemetry before audit families, per-category audit
  events, explicit per-category errors). CLI defaults to dry-run.
- Agent: existing `purge_sent` + new `purge_failed` (≥24h, default 168h; never touches
  pending/sending). Disk exhaustion → explicit overflow + degraded health, never silent send;
  permissions failures → explicit errors; backups/restore in §8.3.

## 8.6 Health monitoring and diagnostics

- Shared model `guardian/ops/health.py`: `healthy < degraded < unready < fatal` (worst wins, never
  masks), secret-key redaction, backend composer (database, migration revision, pipeline, backlog,
  audit writes) and agent snapshot schema (identity, version, collectors, queue depth/age, sync lag,
  disk, auth, ETW/service state).
- Agent builder `guardian/agent/health.py::build_agent_snapshot` reads existing components only;
  snapshot at `<data_dir>/agent_health.json` via existing `service.write_health_snapshot`.
- Liveness (process alive) vs readiness (valid config + writable queue + recent backend contact) vs
  degraded (ETW/auth/pressure) vs fatal (invalid config/unwritable queue/failed audit writes).

## 8.7 Runbooks

`docs/guardian_runbooks.md`: 12 runbooks (agent offline/degraded, ETW failure, backend/DB outage,
queue lag/unreconciled, disk exhaustion, config/certificate failure, failed upgrade/rollback,
suspected compromise, unexpected actions, audit gaps, emergency revocation/kill, evidence
preservation/return-to-operation), each with symptoms, severity, diagnostics, containment, recovery,
evidence to collect, escalation, and stop conditions. None validated by execution.

## Status

IMPLEMENTED — NOT TESTED. All procedures above are code + docs + prepared harnesses;
no test, build, scan, deployment, or live check was executed in this session.
