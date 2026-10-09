"""Guardian v2 Phase 5 Slice 4 — Migration 010: bounded pre-authorization grants.

Creates ``guardian_preauth_grants`` — one row per policy_id recording an
explicit administrator activation of narrowly scoped pre-authorized
execution. Absence of an active row means pre-authorization is disabled
(default); existing policies gain no new authorization from this migration.

Properties:
  - Additive: CREATE TABLE IF NOT EXISTS only. Migrations 001-009 untouched.
  - Idempotent: safe reruns (IF NOT EXISTS + deterministic index names).
  - PostgreSQL + SQLite compatible (JSONB on postgres, JSON on sqlite).
  - No data migration: no existing policy is activated, no grant rows are
    seeded. Revocation is a state change (active=False), never a delete.
"""

from sqlalchemy import text

revision = "010_guardian_phase5_slice4"
depends_on = "009_guardian_phase5_slice2"


def upgrade(engine, base) -> None:
    json_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
    if engine.dialect.name == "postgresql":
        id_col = "id SERIAL PRIMARY KEY"
    else:
        id_col = "id INTEGER PRIMARY KEY AUTOINCREMENT"

    with engine.begin() as conn:
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_preauth_grants (
                    {id_col},
                    policy_id VARCHAR(128) UNIQUE NOT NULL,
                    policy_version INTEGER NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT FALSE,
                    allowed_actions {json_type} NOT NULL DEFAULT '[]',
                    agent_scope {json_type} NOT NULL DEFAULT '{{}}',
                    target_scope {json_type} NOT NULL DEFAULT '{{}}',
                    max_risk_score FLOAT NOT NULL DEFAULT 0.0,
                    max_executions_per_hour INTEGER NOT NULL DEFAULT 1,
                    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
                    expires_at TIMESTAMP,
                    safety_gates {json_type} NOT NULL DEFAULT '[]',
                    rollback_required BOOLEAN NOT NULL DEFAULT FALSE,
                    reason TEXT,
                    activated_by VARCHAR(255),
                    activated_at TIMESTAMP,
                    revoked_by VARCHAR(255),
                    revoked_at TIMESTAMP,
                    revoke_reason TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        for ddl in (
            "CREATE INDEX IF NOT EXISTS ix_guardian_preauth_grants_policy_id"
            " ON guardian_preauth_grants(policy_id)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_preauth_grants_active"
            " ON guardian_preauth_grants(active)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_preauth_grants_created_at"
            " ON guardian_preauth_grants(created_at)",
        ):
            conn.execute(text(ddl))


def downgrade(engine, base) -> None:
    # Grants are auditable authorization state; Slice 4 downgrade is a no-op.
    pass
