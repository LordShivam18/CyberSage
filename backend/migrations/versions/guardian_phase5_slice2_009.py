"""Guardian v2 Phase 5 Slice 2 — Migration 009: safety-envelope execution audit.

Creates ``guardian_envelope_runs`` — one immutable row per authorized
execution attempt through the safety envelope, including attempts blocked
by safety gates (which never reach execution).

Stored per attempt: deterministic execution identity, policy binding
(policy_id + version + rule_id), evaluation binding, approval binding,
actor identity, action + canonical target hash, ordered gate results,
execution / verification / rollback outcomes, final state, correlation ID,
and error detail without secrets.

Properties:
  - Additive: CREATE TABLE IF NOT EXISTS only. Migrations 001-008 untouched.
  - Idempotent: safe reruns (IF NOT EXISTS + deterministic index names).
  - PostgreSQL + SQLite compatible (JSONB on postgres, JSON on sqlite).
  - Concurrency-safe uniqueness: UNIQUE(execution_id) is the final arbiter
    for idempotent execution; racers resolve to the single winning row.
  - Append-only by convention: no update/delete path is provided here;
    status advances via UPDATE of the single row by the envelope only.
"""

from sqlalchemy import text

revision = "009_guardian_phase5_slice2"
depends_on = "008_guardian_phase5_slice1"


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
                CREATE TABLE IF NOT EXISTS guardian_envelope_runs (
                    {id_col},
                    execution_id VARCHAR(128) UNIQUE NOT NULL,
                    evaluation_id VARCHAR(128),
                    policy_id VARCHAR(128) NOT NULL,
                    policy_version INTEGER NOT NULL,
                    rule_id VARCHAR(128),
                    incident_id INTEGER,
                    event_ids {json_type} NOT NULL DEFAULT '[]',
                    decision_id VARCHAR(128) NOT NULL,
                    approval_id VARCHAR(128),
                    action_id VARCHAR(128),
                    actor VARCHAR(255) NOT NULL,
                    action_type VARCHAR(64) NOT NULL,
                    action_name VARCHAR(128) NOT NULL,
                    target {json_type} NOT NULL DEFAULT '{{}}',
                    target_hash VARCHAR(128) NOT NULL,
                    parameters {json_type} NOT NULL DEFAULT '{{}}',
                    status VARCHAR(32) NOT NULL DEFAULT 'safety_check',
                    gate_results {json_type} NOT NULL DEFAULT '[]',
                    execution_result {json_type},
                    verification {json_type},
                    rollback {json_type},
                    error TEXT,
                    correlation_id VARCHAR(128),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        for ddl in (
            "CREATE INDEX IF NOT EXISTS ix_guardian_envelope_runs_execution_id"
            " ON guardian_envelope_runs(execution_id)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_envelope_runs_policy_id"
            " ON guardian_envelope_runs(policy_id)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_envelope_runs_incident_id"
            " ON guardian_envelope_runs(incident_id)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_envelope_runs_status"
            " ON guardian_envelope_runs(status)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_envelope_runs_target_hash"
            " ON guardian_envelope_runs(target_hash)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_envelope_runs_created_at"
            " ON guardian_envelope_runs(created_at)",
        ):
            conn.execute(text(ddl))
def downgrade(engine, base) -> None:
    # Execution audit is immutable; Slice 2 downgrade is a no-op by design.
    pass
