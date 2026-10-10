# Guardian Phase 8 Acceptance Checklist (HUMAN-RUN, NOT EXECUTED)

Prerequisites: disposable host(s), isolated backend/DB, test credentials, release manifest + checksums,
(optional for signed path) configured certificate trust material. Nothing below has been executed here.

## Release integrity
- [ ] `scripts/version_contract.py` passes against root VERSION.
- [ ] `scripts/guardian_release.py manifest` records all agent inputs; `verify` passes on a clean tree.
- [ ] Tamper check: modify one tracked file copy (in a scratch copy, never the repo) and confirm `verify` fails.
- [ ] Unsigned manifest presented to a production install plan is rejected; development install is labeled development.
- [ ] `verify-signature` without configured fingerprint/signature fails closed with the prerequisite message.

## Service installation
- [ ] `python -m guardian.agent.install --plan install` prints a validated plan without side effects (any OS).
- [ ] On disposable Windows with elevation: install → service exists with the dedicated account; data/log dirs
      carry restrictive ACLs; secrets never appear in logs or the install manifest.
- [ ] Restart: same `agent_key`/`host_id`, no duplicate server agent; queue depth unchanged across restart.
- [ ] Uninstall default keeps data; `--remove-data` requires explicit opt-in and is recorded.

## Upgrade and rollback
- [ ] `pre_upgrade_checks` aborts on version downgrade, missing data dir, unreadable queue DB, low disk.
- [ ] Upgrade applies ordered idempotent migrations; `schema_migrations` matches the runner list.
- [ ] Backup ledger (queue DB digest + identity + config + install manifest) verifies before file deployment.
- [ ] Rollback restores files/config/queue snapshot while preserving append-only audit rows (verify row counts).
- [ ] Interrupted upgrade recovery order completes and readiness (not liveness) is green.

## Configuration and secrets
- [ ] Unknown file keys and plaintext `auth_token` in files are rejected; env overrides file (precedence test).
- [ ] Production validation refuses non-HTTPS backend and missing credentials instead of downgrading.
- [ ] `to_redacted_dict()` and health snapshots contain no secret values (grep the outputs).

## Retention and storage
- [ ] Retention CLI defaults to dry-run with per-category eligible counts; unknown categories rejected.
- [ ] Bounded `--apply` deletes in LIMIT batches, telemetry before audit families, with audit events per category.
- [ ] Agent `purge_sent`/`purge_failed` honor minimum windows and never touch pending/sending.
- [ ] Disk-pressure and permission-failure paths report explicit errors (no silent loss).

## Health and runbooks
- [ ] Agent snapshot distinguishes healthy/degraded/unready/fatal and never masks the worst signal.
- [ ] Backend composer reflects database/migration/pipeline/backlog/audit signals honestly.
- [ ] Each of the 12 runbooks is readable, scoped, and has stop conditions; certificate/secret material handling
      matches the trust-anchor documentation.
