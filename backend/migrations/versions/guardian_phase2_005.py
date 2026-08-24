"""Guardian v2 Phase 2 — Migration 005: Detection, incident, risk, and policy tables.

Creates:
    guardian_detections
    guardian_incidents
    guardian_incident_events
    guardian_risk_scores
    guardian_response_decisions

This migration is additive and idempotent.
Existing migrations 001–004 are not modified.
"""

from sqlalchemy import inspect, text

revision = "005_guardian_phase2"
depends_on = "004_guardian_core"


def upgrade(engine, base) -> None:
    json_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
    if engine.dialect.name == "postgresql":
        id_col = "id SERIAL PRIMARY KEY"
    else:
        id_col = "id INTEGER PRIMARY KEY AUTOINCREMENT"

    with engine.begin() as conn:
        # ── guardian_detections ──────────────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_detections (
                    {id_col},
                    detection_id VARCHAR(128) UNIQUE NOT NULL,
                    event_id VARCHAR(128) NOT NULL,
                    detector_id VARCHAR(64) NOT NULL,
                    severity VARCHAR(32) NOT NULL DEFAULT 'low',
                    confidence FLOAT NOT NULL DEFAULT 0.0,
                    title VARCHAR(512) NOT NULL,
                    description TEXT,
                    evidence {json_type} DEFAULT '{{}}',
                    mitre_technique VARCHAR(32),
                    mitre_tactic VARCHAR(64),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_incidents ───────────────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_incidents (
                    {id_col},
                    candidate_id VARCHAR(128) UNIQUE NOT NULL,
                    title VARCHAR(512) NOT NULL,
                    description TEXT,
                    severity VARCHAR(32) NOT NULL DEFAULT 'low',
                    confidence FLOAT NOT NULL DEFAULT 0.0,
                    status VARCHAR(32) NOT NULL DEFAULT 'open',
                    evidence_ids {json_type} DEFAULT '[]',
                    event_ids {json_type} DEFAULT '[]',
                    host_ids {json_type} DEFAULT '[]',
                    mitre_techniques {json_type} DEFAULT '[]',
                    mitre_tactics {json_type} DEFAULT '[]',
                    risk_score_id INTEGER,
                    response_decision_id INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_incident_events ─────────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_incident_events (
                    {id_col},
                    incident_id INTEGER NOT NULL,
                    event_id VARCHAR(128) NOT NULL,
                    event_type VARCHAR(64) NOT NULL,
                    description TEXT,
                    data {json_type} DEFAULT '{{}}',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_risk_scores ─────────────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_risk_scores (
                    {id_col},
                    score FLOAT NOT NULL DEFAULT 0.0,
                    severity VARCHAR(32) NOT NULL DEFAULT 'low',
                    confidence FLOAT NOT NULL DEFAULT 0.0,
                    factors {json_type} DEFAULT '[]',
                    explanation TEXT,
                    detection_ids {json_type} DEFAULT '[]',
                    incident_id INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── guardian_response_decisions ──────────────────────────────
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_response_decisions (
                    {id_col},
                    decision_id VARCHAR(128) UNIQUE NOT NULL,
                    incident_id INTEGER,
                    severity VARCHAR(32) NOT NULL DEFAULT 'low',
                    confidence FLOAT NOT NULL DEFAULT 0.0,
                    recommended_action VARCHAR(64) NOT NULL DEFAULT 'monitor',
                    rationale TEXT,
                    evidence {json_type} DEFAULT '[]',
                    expected_effect TEXT,
                    risk {json_type},
                    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
                    rollback_available BOOLEAN NOT NULL DEFAULT FALSE,
                    verification_plan TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # ── Indexes ─────────────────────────────────────────────────
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_detections_detection_id ON guardian_detections(detection_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_detections_event_id ON guardian_detections(event_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_detections_detector_id ON guardian_detections(detector_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_detections_severity ON guardian_detections(severity)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_detections_created_at ON guardian_detections(created_at)"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_incidents_candidate_id ON guardian_incidents(candidate_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_incidents_severity ON guardian_incidents(severity)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_incidents_status ON guardian_incidents(status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_incidents_created_at ON guardian_incidents(created_at)"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_incident_events_incident_id ON guardian_incident_events(incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_incident_events_event_id ON guardian_incident_events(event_id)"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_risk_scores_incident_id ON guardian_risk_scores(incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_risk_scores_created_at ON guardian_risk_scores(created_at)"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_response_decisions_decision_id ON guardian_response_decisions(decision_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_response_decisions_incident_id ON guardian_response_decisions(incident_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_response_decisions_severity ON guardian_response_decisions(severity)"))


def downgrade(engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS guardian_response_decisions"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_risk_scores"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_incident_events"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_incidents"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_detections"))
        conn.execute(
            text("DELETE FROM schema_migrations WHERE revision = :revision"),
            {"revision": revision},
        )
