"""Guardian v2 Phase 1 — Migration 004: Core Guardian tables.

Creates only the tables required for Phase 1:
    guardian_agents
    guardian_heartbeats
    guardian_events

This migration is additive and idempotent.
Existing migrations 001–003 are not modified.
"""

from sqlalchemy import inspect, text


revision = "004_guardian_core"


def upgrade(engine, base) -> None:
    json_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"

    with engine.begin() as conn:
        # guardian_agents
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_key VARCHAR(128) UNIQUE NOT NULL,
                    hostname VARCHAR(255) NOT NULL,
                    host_id VARCHAR(128),
                    os_name VARCHAR(128),
                    os_version VARCHAR(128),
                    agent_version VARCHAR(64),
                    status VARCHAR(32) NOT NULL DEFAULT 'active',
                    registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_heartbeat_at TIMESTAMP,
                    metadata {json_type} DEFAULT '{{}}',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # guardian_heartbeats
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_heartbeats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id INTEGER NOT NULL,
                    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    agent_version VARCHAR(64),
                    uptime_seconds INTEGER,
                    cpu_usage_pct FLOAT,
                    memory_usage_pct FLOAT,
                    events_queued INTEGER DEFAULT 0,
                    events_processed INTEGER DEFAULT 0,
                    detections_pending INTEGER DEFAULT 0,
                    metadata {json_type} DEFAULT '{{}}'
                )
                """
            )
        )

        # guardian_events
        conn.execute(
            text(
                f"""
                CREATE TABLE IF NOT EXISTS guardian_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id VARCHAR(128) UNIQUE NOT NULL,
                    schema_version VARCHAR(32) NOT NULL DEFAULT 'guardian.event.v1',
                    agent_id INTEGER NOT NULL,
                    event_category VARCHAR(32) NOT NULL DEFAULT 'process',
                    timestamp TIMESTAMP NOT NULL,
                    ingestion_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

                    process_name VARCHAR(255),
                    process_pid INTEGER,
                    process_exe_path TEXT,
                    process_exe_hash_sha256 VARCHAR(128),
                    process_command_line TEXT,
                    parent_process_name VARCHAR(255),
                    parent_process_pid INTEGER,
                    parent_process_exe_path TEXT,

                    user_name VARCHAR(255),
                    user_sid VARCHAR(128),

                    source_ip VARCHAR(64),
                    source_port INTEGER,
                    destination_ip VARCHAR(64),
                    destination_port INTEGER,
                    protocol VARCHAR(32),
                    bytes_sent FLOAT,
                    bytes_received FLOAT,

                    file_path TEXT,
                    file_operation VARCHAR(32),
                    file_hash_sha256 VARCHAR(128),

                    persistence_type VARCHAR(64),
                    persistence_path TEXT,
                    persistence_data {json_type},

                    evidence {json_type} DEFAULT '{{}}',
                    raw_event {json_type} DEFAULT '{{}}',

                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )

        # Indexes
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_agents_agent_key ON guardian_agents(agent_key)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_agents_status ON guardian_agents(status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_agents_hostname ON guardian_agents(hostname)"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_heartbeats_agent_id ON guardian_heartbeats(agent_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_heartbeats_timestamp ON guardian_heartbeats(timestamp)"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_events_event_id ON guardian_events(event_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_events_agent_id ON guardian_events(agent_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_events_timestamp ON guardian_events(timestamp)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_events_event_category ON guardian_events(event_category)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_events_process_exe_path ON guardian_events(process_exe_path)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_events_destination_ip ON guardian_events(destination_ip)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_guardian_events_status ON guardian_events(status)"))


def downgrade(engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS guardian_events"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_heartbeats"))
        conn.execute(text("DROP TABLE IF EXISTS guardian_agents"))
        conn.execute(
            text("DELETE FROM schema_migrations WHERE revision = :revision"),
            {"revision": revision},
        )
