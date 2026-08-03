from sqlalchemy import inspect, text


revision = "002_model_governance"


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _columns(engine):
    json_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
    return {
        "task": "VARCHAR(128) NOT NULL DEFAULT 'network_detection'",
        "status": "VARCHAR(32) NOT NULL DEFAULT 'candidate'",
        "dataset_identifier": "VARCHAR(255)",
        "validation_result": json_type,
        "rejection_reason": "TEXT",
        "updated_at": "TIMESTAMP",
        "activated_at": "TIMESTAMP",
    }


def upgrade(engine, _base) -> None:
    inspector = inspect(engine)
    if "model_versions" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("model_versions")}
    with engine.begin() as connection:
        for name, type_sql in _columns(engine).items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE model_versions ADD COLUMN {_quote(name)} {type_sql}"))
        connection.execute(
            text(
                "UPDATE model_versions SET task = COALESCE(task, 'network_detection'), "
                "status = COALESCE(status, 'archived'), updated_at = COALESCE(updated_at, created_at)"
            )
        )
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_model_versions_task_status ON model_versions (task, status)")
        )


def downgrade(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX IF EXISTS ix_model_versions_task_status"))
        connection.execute(text("DELETE FROM schema_migrations WHERE revision = :revision"), {"revision": revision})
