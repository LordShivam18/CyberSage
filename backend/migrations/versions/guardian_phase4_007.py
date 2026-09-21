"""Guardian v2 Phase 4 — Migration 007: Advanced Automation & Safety Controls.

Creates:
    guardian_automation_policies
    guardian_automation_rules
    guardian_automation_runs
    guardian_collector_health
    guardian_kill_switches

This migration is additive and idempotent.
Existing migrations 001–006 are not modified.
"""

from sqlalchemy import inspect, text

revision = "007_guardian_phase4"
depends_on = "006_guardian_phase3"


def upgrade(engine, base) -> None:
    json_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
    if engine.dialect.name == "postgresql":
        id_col = "id SERIAL PRIMARY KEY"
    else:
        id_col = "id INTEGER PRIMARY KEY AUTOINCREMENT"

    with engine.begin() as conn:
        # ── guardian_automation_policies ───────────────────────
        if not inspect(engine).has_table("guardian_automation_policies"):
            conn.execute(
                text(
                    f"""
                    CREATE TABLE guardian_automation_policies (
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
                text("CREATE INDEX ix_guardian_automation_policies_policy_id ON guardian_automation_policies(policy_id)")
            )

        # ── guardian_automation_rules ──────────────────────────
        if not inspect(engine).has_table("guardian_automation_rules"):
            conn.execute(
                text(
                    f"""
                    CREATE TABLE guardian_automation_rules (
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
                text("CREATE INDEX ix_guardian_automation_rules_policy_id ON guardian_automation_rules(policy_id)")
            )

        # ── guardian_automation_runs ───────────────────────────
        if not inspect(engine).has_table("guardian_automation_runs"):
            conn.execute(
                text(
                    f"""
                    CREATE TABLE guardian_automation_runs (
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
                text("CREATE INDEX ix_guardian_automation_runs_run_id ON guardian_automation_runs(run_id)")
            )
            conn.execute(
                text("CREATE INDEX ix_guardian_automation_runs_status ON guardian_automation_runs(status)")
            )

        # ── guardian_collector_health ──────────────────────────
        if not inspect(engine).has_table("guardian_collector_health"):
            conn.execute(
                text(
                    f"""
                    CREATE TABLE guardian_collector_health (
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
                text("CREATE INDEX ix_guardian_collector_health_agent_type ON guardian_collector_health(agent_id, collector_type)")
            )

        # ── guardian_kill_switches ─────────────────────────────
        if not inspect(engine).has_table("guardian_kill_switches"):
            conn.execute(
                text(
                    f"""
                    CREATE TABLE guardian_kill_switches (
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
            conn.execute(
                text("CREATE INDEX ix_guardian_kill_switches_scope_key ON guardian_kill_switches(scope, switch_key)")
            )

def downgrade(engine, base) -> None:
    pass
