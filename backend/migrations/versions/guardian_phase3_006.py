"""Guardian v2 Phase 3 — Migration 006: Controlled response, approval, verification, and rollback.

Creates:
    guardian_approval_requests
    guardian_approvals
    guardian_action_attempts
    guardian_action_snapshots
    guardian_action_verifications
    guardian_action_rollbacks
    guardian_action_audit

This migration is additive and idempotent.
Existing migrations 001–005 are not modified.
"""

from sqlalchemy import inspect, text

revision = "006_guardian_phase3"
depends_on = "005_guardian_phase2"


def upgrade(engine, base) -> None:
    json_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
    if engine.dialect.name == "postgresql":
        id_col = "id SERIAL PRIMARY KEY"
    else:
        id_col = "id INTEGER PRIMARY KEY AUTOINCREMENT"

    with engine.begin() as conn:
        # ── guardian_approval_requests ─────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_approval_requests (
                    {id_col},
                    approval_id VARCHAR(128) UNIQUE NOT NULL,
                    incident_id INTEGER,
                    decision_id VARCHAR(128) NOT NULL,
                    requested_action VARCHAR(64) NOT NULL,
                    action_type VARCHAR(64) NOT NULL,
                    target {json_type} NOT NULL DEFAULT '{{}}',
                    rationale TEXT NOT NULL DEFAULT '',
                    risk {json_type},
                    status VARCHAR(32) NOT NULL DEFAULT 'pending',
                    requested_by VARCHAR(255) NOT NULL DEFAULT 'system',
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_approvals ─────────────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_approvals (
                    {id_col},
                    approval_record_id VARCHAR(128) UNIQUE NOT NULL,
                    approval_request_id INTEGER NOT NULL,
                    approver VARCHAR(255) NOT NULL,
                    decision VARCHAR(32) NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_action_attempts ───────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_action_attempts (
                    {id_col},
                    action_id VARCHAR(128) UNIQUE NOT NULL,
                    approval_id VARCHAR(128) NOT NULL,
                    incident_id INTEGER,
                    decision_id VARCHAR(128) NOT NULL,
                    action_type VARCHAR(64) NOT NULL,
                    action_name VARCHAR(128) NOT NULL,
                    target {json_type} NOT NULL DEFAULT '{{}}',
                    parameters {json_type} NOT NULL DEFAULT '{{}}',
                    status VARCHAR(32) NOT NULL DEFAULT 'planned',
                    execution_started_at TIMESTAMP,
                    execution_finished_at TIMESTAMP,
                    result {json_type},
                    error TEXT,
                    snapshot_id VARCHAR(128),
                    verification_id VARCHAR(128),
                    rollback_id VARCHAR(128),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_action_snapshots ──────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_action_snapshots (
                    {id_col},
                    snapshot_id VARCHAR(128) UNIQUE NOT NULL,
                    action_id VARCHAR(128) NOT NULL,
                    action_type VARCHAR(64) NOT NULL,
                    target {json_type} NOT NULL DEFAULT '{{}}',
                    prior_state {json_type} NOT NULL DEFAULT '{{}}',
                    snapshot_metadata {json_type} NOT NULL DEFAULT '{{}}',
                    immutable BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_action_verifications ──────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_action_verifications (
                    {id_col},
                    verification_id VARCHAR(128) UNIQUE NOT NULL,
                    action_id VARCHAR(128) NOT NULL,
                    passed BOOLEAN NOT NULL DEFAULT FALSE,
                    checks {json_type} NOT NULL DEFAULT '[]',
                    evidence {json_type} NOT NULL DEFAULT '{{}}',
                    observed_state {json_type} NOT NULL DEFAULT '{{}}',
                    failure_reason TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_action_rollbacks ──────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_action_rollbacks (
                    {id_col},
                    rollback_id VARCHAR(128) UNIQUE NOT NULL,
                    action_id VARCHAR(128) NOT NULL,
                    snapshot_id VARCHAR(128) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'available',
                    result {json_type},
                    error TEXT,
                    requested_at TIMESTAMP,
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_action_audit ──────────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_action_audit (
                    {id_col},
                    audit_id VARCHAR(128) UNIQUE NOT NULL,
                    incident_id INTEGER,
                    approval_id VARCHAR(128),
                    action_id VARCHAR(128) NOT NULL,
                    actor VARCHAR(255) NOT NULL,
                    action_type VARCHAR(64) NOT NULL,
                    target {json_type} NOT NULL DEFAULT '{{}}',
                    snapshot_id VARCHAR(128),
                    execution_started_at TIMESTAMP,
                    execution_finished_at TIMESTAMP,
                    verification_passed BOOLEAN,
                    verification_result {json_type},
                    rollback_result {json_type},
                    status VARCHAR(32) NOT NULL DEFAULT 'planned',
                    error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── Indexes ─────────────────────────────────────────────────

        # Approval requests
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_approval_requests_approval_id ON guardian_approval_requests(approval_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_approval_requests_incident_id ON guardian_approval_requests(incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_approval_requests_decision_id ON guardian_approval_requests(decision_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_approval_requests_status ON guardian_approval_requests(status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_approval_requests_created_at ON guardian_approval_requests(created_at)"))

        # Approvals
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_approvals_approval_record_id ON guardian_approvals(approval_record_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_approvals_approval_request_id ON guardian_approvals(approval_request_id)"))

        # Action attempts
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_attempts_action_id ON guardian_action_attempts(action_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_attempts_approval_id ON guardian_action_attempts(approval_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_attempts_incident_id ON guardian_action_attempts(incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_attempts_status ON guardian_action_attempts(status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_attempts_created_at ON guardian_action_attempts(created_at)"))

        # Snapshots
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_snapshots_snapshot_id ON guardian_action_snapshots(snapshot_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_snapshots_action_id ON guardian_action_snapshots(action_id)"))

        # Verifications
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_verifications_verification_id ON guardian_action_verifications(verification_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_verifications_action_id ON guardian_action_verifications(action_id)"))

        # Rollbacks
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_rollbacks_rollback_id ON guardian_action_rollbacks(rollback_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_rollbacks_action_id ON guardian_action_rollbacks(action_id)"))

        # Audit
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_audit_audit_id ON guardian_action_audit(audit_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_audit_incident_id ON guardian_action_audit(incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_audit_action_id ON guardian_action_audit(action_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_audit_actor ON guardian_action_audit(actor)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_audit_status ON guardian_action_audit(status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_action_audit_created_at ON guardian_action_audit(created_at)"))


def downgrade(engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS guardian_action_audit"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_action_rollbacks"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_action_verifications"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_action_snapshots"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_action_attempts"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_approvals"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_approval_requests"))
        conn.execute(
            text("DELETE FROM schema_migrations WHERE revision = :revision"),
            {"revision": revision},
        )
