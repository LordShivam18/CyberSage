"""Guardian v2 Phase 5 Slice 1 — Migration 008: versioned policy evaluation + simulation audit.

Additive changes only (existing migrations 001-007 are not modified):

1. Extends ``guardian_automation_policies`` with lifecycle columns:
     version (INTEGER, default 1), priority (INTEGER, default 100),
     expires_at (TIMESTAMP, nullable), updated_by (VARCHAR, nullable)

2. Extends ``guardian_automation_rules`` with evaluation columns:
     priority (INTEGER, default 100), target_scope (JSON, nullable),
     approval_mode (VARCHAR, default 'required'),
     max_executions_per_hour (INTEGER, nullable),
     cooldown_seconds (INTEGER, nullable)

3. Creates ``guardian_policy_evaluations`` — immutable audit trail for
   policy evaluations and dry-run simulations. Simulation rows are the
   explicitly-designed simulation artifact; they never represent real
   execution and never mutate OS / network / approval / action state.

Properties:
  - Additive: only ADD COLUMN / CREATE TABLE IF NOT EXISTS.
  - Idempotent: safe to run multiple times (column existence is checked
    via SQLAlchemy inspection before ALTER; tables use IF NOT EXISTS).
  - PostgreSQL + SQLite compatible (JSONB on postgres, JSON on sqlite).
  - Backward compatible: all new columns are nullable or have defaults,
    so rows written by Phase 4 code keep working.
  - Independently testable: ``upgrade()`` can run against an empty
    database (Phase 4 base tables are created first if missing).

Slice 1 does NOT enable autonomous execution. No executor, no worker,
no OS/network mutation is introduced here.
"""

from sqlalchemy import inspect, text

revision = "008_guardian_phase5_slice1"
depends_on = "007_guardian_phase4"


def _existing_columns(engine, table_name):
    try:
        return {col["name"] for col in inspect(engine).get_columns(table_name)}
    except Exception:
        return set()


def _ensure_phase4_base_tables(conn, engine, json_type, id_col):
    """Create Phase 4 (007) tables if they are missing.

    Makes 008 independently runnable (e.g. fresh SQLite test databases).
    DDL mirrors backend/migrations/versions/guardian_phase4_007.py exactly.
    """
    conn.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS guardian_automation_policies (
                {id_col},
                policy_id VARCHAR(128) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                mode VARCHAR(64) NOT NULL DEFAULT 'approval_required',
                enabled BOOLEAN NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )
            """
        )
    )
    conn.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS guardian_automation_rules (
                {id_col},
                policy_id VARCHAR(128) NOT NULL,
                rule_id VARCHAR(128) UNIQUE NOT NULL,
                description TEXT NOT NULL,
                action_type VARCHAR(64) NOT NULL,
                action_name VARCHAR(64) NOT NULL,
                min_risk_score FLOAT NOT NULL DEFAULT 0.0,
                max_risk_score FLOAT NOT NULL DEFAULT 100.0,
                incident_severity VARCHAR(64),
                decision VARCHAR(64) NOT NULL DEFAULT 'require_approval',
                requires_approval BOOLEAN NOT NULL DEFAULT 1,
                FOREIGN KEY(policy_id) REFERENCES guardian_automation_policies(policy_id)
            )
            """
        )
    )
    conn.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS guardian_automation_runs (
                {id_col},
                run_id VARCHAR(128) UNIQUE NOT NULL,
                policy_id VARCHAR(128),
                action_type VARCHAR(64) NOT NULL,
                action_name VARCHAR(128) NOT NULL,
                target {json_type} NOT NULL,
                incident_id INTEGER,
                decision_id VARCHAR(128) NOT NULL,
                risk_score FLOAT NOT NULL,
                incident_severity VARCHAR(64) NOT NULL,
                requested_by VARCHAR(255) NOT NULL,
                rationale TEXT NOT NULL,
                status VARCHAR(64) NOT NULL,
                policy_decision VARCHAR(64) NOT NULL,
                requires_approval BOOLEAN NOT NULL,
                approval_id VARCHAR(128),
                parameters {json_type} NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                error TEXT,
                result {json_type}
            )
            """
        )
    )
    conn.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS guardian_collector_health (
                {id_col},
                agent_id VARCHAR(128) NOT NULL,
                collector_type VARCHAR(128) NOT NULL,
                health_state VARCHAR(64) NOT NULL,
                last_event_at TIMESTAMP,
                events_received INTEGER NOT NULL DEFAULT 0,
                events_dropped INTEGER NOT NULL DEFAULT 0,
                reconnect_count INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMP NOT NULL,
                UNIQUE(agent_id, collector_type)
            )
            """
        )
    )
    conn.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS guardian_kill_switches (
                {id_col},
                scope VARCHAR(64) NOT NULL,
                switch_key VARCHAR(128) NOT NULL,
                active BOOLEAN NOT NULL DEFAULT 0,
                activated_at TIMESTAMP,
                activated_by VARCHAR(255),
                reason TEXT,
                updated_at TIMESTAMP NOT NULL,
                UNIQUE(scope, switch_key)
            )
            """
        )
    )
    # Indexes matching 007 (IF NOT EXISTS keeps reruns safe on both dialects
    # that support it; SQLite and PostgreSQL both accept this syntax).
    for ddl in (
        "CREATE INDEX IF NOT EXISTS ix_guardian_automation_policies_policy_id"
        " ON guardian_automation_policies(policy_id)",
        "CREATE INDEX IF NOT EXISTS ix_guardian_automation_rules_policy_id"
        " ON guardian_automation_rules(policy_id)",
        "CREATE INDEX IF NOT EXISTS ix_guardian_automation_runs_run_id"
        " ON guardian_automation_runs(run_id)",
        "CREATE INDEX IF NOT EXISTS ix_guardian_automation_runs_status"
        " ON guardian_automation_runs(status)",
        "CREATE INDEX IF NOT EXISTS ix_guardian_collector_health_agent_type"
        " ON guardian_collector_health(agent_id, collector_type)",
        "CREATE INDEX IF NOT EXISTS ix_guardian_kill_switches_scope_key"
        " ON guardian_kill_switches(scope, switch_key)",
    ):
        conn.execute(text(ddl))
    _ = engine  # engine used by caller for inspection; kept for signature clarity


def _add_column_if_missing(conn, engine, table, column_ddl, column_name):
    if column_name in _existing_columns(engine, table):
        return
    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column_ddl}"))


def upgrade(engine, base) -> None:
    json_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
    if engine.dialect.name == "postgresql":
        id_col = "id SERIAL PRIMARY KEY"
    else:
        id_col = "id INTEGER PRIMARY KEY AUTOINCREMENT"

    with engine.begin() as conn:
        _ensure_phase4_base_tables(conn, engine, json_type, id_col)

    # ── Extend guardian_automation_policies (lifecycle) ──────────────
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_policies",
            "version INTEGER NOT NULL DEFAULT 1", "version",
        )
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_policies",
            "priority INTEGER NOT NULL DEFAULT 100", "priority",
        )
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_policies",
            "expires_at TIMESTAMP", "expires_at",
        )
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_policies",
            "updated_by VARCHAR(255)", "updated_by",
        )

    # ── Extend guardian_automation_rules (evaluation) ────────────────
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_rules",
            "priority INTEGER NOT NULL DEFAULT 100", "priority",
        )
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_rules",
            f"target_scope {json_type}", "target_scope",
        )
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_rules",
            "approval_mode VARCHAR(32) NOT NULL DEFAULT 'required'", "approval_mode",
        )
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_rules",
            "max_executions_per_hour INTEGER", "max_executions_per_hour",
        )
    with engine.begin() as conn:
        _add_column_if_missing(
            conn, engine, "guardian_automation_rules",
            "cooldown_seconds INTEGER", "cooldown_seconds",
        )

    # ── Simulation / evaluation audit trail ──────────────────────────
    with engine.begin() as conn:
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_policy_evaluations (
                    {id_col},
                    evaluation_id VARCHAR(128) UNIQUE NOT NULL,
                    policy_id VARCHAR(128),
                    policy_version INTEGER,
                    matched_rule_id VARCHAR(128),
                    incident_id INTEGER,
                    event_ids {json_type} NOT NULL DEFAULT '[]',
                    risk_score FLOAT,
                    incident_severity VARCHAR(64),
                    action_type VARCHAR(64) NOT NULL,
                    action_name VARCHAR(128) NOT NULL,
                    target {json_type} NOT NULL DEFAULT '{{}}',
                    decision VARCHAR(64) NOT NULL,
                    reason TEXT,
                    approval_mode VARCHAR(32) NOT NULL DEFAULT 'required',
                    would_execute BOOLEAN NOT NULL DEFAULT 0,
                    blocked_reason TEXT,
                    safety_checks {json_type} NOT NULL DEFAULT '[]',
                    requested_by VARCHAR(255) NOT NULL DEFAULT 'system',
                    correlation_id VARCHAR(128),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        for ddl in (
            "CREATE INDEX IF NOT EXISTS ix_guardian_policy_evaluations_evaluation_id"
            " ON guardian_policy_evaluations(evaluation_id)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_policy_evaluations_policy_id"
            " ON guardian_policy_evaluations(policy_id)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_policy_evaluations_incident_id"
            " ON guardian_policy_evaluations(incident_id)",
            "CREATE INDEX IF NOT EXISTS ix_guardian_policy_evaluations_created_at"
            " ON guardian_policy_evaluations(created_at)",
        ):
            conn.execute(text(ddl))


def downgrade(engine, base) -> None:
    # Audit data is immutable; Slice 1 downgrade is a no-op by design.
    # Added columns/tables are left in place so history is never destroyed.
    pass
