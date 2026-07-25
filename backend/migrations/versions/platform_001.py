from sqlalchemy import inspect, text


revision = "001_platform_schema"


ALERT_COLUMNS = {
    "alert_key": "VARCHAR(128)",
    "detection_id": "INTEGER",
    "status": "VARCHAR(64) DEFAULT 'new'",
    "severity": "VARCHAR(32) DEFAULT 'low'",
    "classification": "VARCHAR(128)",
    "confidence": "FLOAT",
    "detection_source": "VARCHAR(64)",
    "source_ip": "VARCHAR(64)",
    "destination_ip": "VARCHAR(64)",
    "risk_score": "FLOAT",
    "triggered_rules": "JSON",
    "anomaly_score": "FLOAT",
    "model_version": "VARCHAR(255)",
    "mitre_techniques": "JSON",
    "related_event_ids": "JSON",
    "investigation_actions": "JSON",
    "risk_components": "JSON",
    "raw_evidence_reference": "VARCHAR(512)",
    "assignee": "VARCHAR(255)",
    "priority": "VARCHAR(32) DEFAULT 'medium'",
    "analyst_notes": "TEXT",
    "resolution_reason": "TEXT",
    "first_seen": "TIMESTAMP",
    "last_seen": "TIMESTAMP",
    "updated_at": "TIMESTAMP",
}


INDEXES = [
    ("ux_alerts_alert_key", "alerts", "alert_key", True),
    ("ix_alerts_status", "alerts", "status", False),
    ("ix_alerts_severity", "alerts", "severity", False),
    ("ix_alerts_classification", "alerts", "classification", False),
    ("ix_alerts_source_ip", "alerts", "source_ip", False),
    ("ix_alerts_destination_ip", "alerts", "destination_ip", False),
    ("ix_alerts_risk_score", "alerts", "risk_score", False),
]


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _add_missing_alert_columns(engine) -> None:
    inspector = inspect(engine)
    if "alerts" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("alerts")}
    with engine.begin() as connection:
        for name, type_sql in ALERT_COLUMNS.items():
            if name in existing:
                continue
            connection.execute(text(f"ALTER TABLE alerts ADD COLUMN {_quote(name)} {type_sql}"))
        connection.execute(
            text(
                """
                UPDATE alerts
                SET status = COALESCE(status, 'new'),
                    severity = COALESCE(severity, 'high'),
                    classification = COALESCE(classification, prediction),
                    confidence = COALESCE(confidence, probability),
                    detection_source = COALESCE(detection_source, 'legacy_model'),
                    risk_score = COALESCE(risk_score, probability * 100),
                    priority = COALESCE(priority, 'medium'),
                    first_seen = COALESCE(first_seen, timestamp),
                    last_seen = COALESCE(last_seen, timestamp),
                    updated_at = COALESCE(updated_at, timestamp)
                """
            )
        )


def _create_indexes(engine) -> None:
    with engine.begin() as connection:
        for name, table_name, column_name, unique in INDEXES:
            unique_sql = "UNIQUE " if unique else ""
            connection.execute(
                text(
                    f"CREATE {unique_sql}INDEX IF NOT EXISTS {name} "
                    f"ON {table_name} ({column_name})"
                )
            )


def upgrade(engine, base) -> None:
    base.metadata.create_all(bind=engine)
    _add_missing_alert_columns(engine)
    _create_indexes(engine)


def downgrade(engine) -> None:
    tables = [
        "dead_letter_events",
        "audit_events",
        "model_versions",
        "threat_intel_cache",
        "analyst_feedback",
        "incident_alerts",
        "incidents",
        "detections",
        "normalized_events",
        "users",
    ]
    with engine.begin() as connection:
        for table in tables:
            connection.execute(text(f"DROP TABLE IF EXISTS {table}"))
        connection.execute(
            text("DELETE FROM schema_migrations WHERE revision = :revision"),
            {"revision": revision},
        )
