from typing import Iterable

from sqlalchemy import inspect, text

from ..database import Base, engine
from .. import models  # noqa: F401 - registers SQLAlchemy models
from .versions import platform_001


MIGRATIONS = [platform_001]


def _ensure_migration_table(connection):
    connection.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                revision VARCHAR(128) PRIMARY KEY,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    )


def _applied_revisions(connection) -> Iterable[str]:
    result = connection.execute(text("SELECT revision FROM schema_migrations"))
    return {row[0] for row in result}


def run_migrations(target_engine=None) -> None:
    active_engine = target_engine or engine
    with active_engine.begin() as connection:
        _ensure_migration_table(connection)
        applied = set(_applied_revisions(connection))

    for migration in MIGRATIONS:
        if migration.revision in applied:
            continue
        migration.upgrade(active_engine, Base)
        with active_engine.begin() as connection:
            connection.execute(
                text("INSERT INTO schema_migrations (revision) VALUES (:revision)"),
                {"revision": migration.revision},
            )


def current_revision(target_engine=None):
    active_engine = target_engine or engine
    inspector = inspect(active_engine)
    if "schema_migrations" not in inspector.get_table_names():
        return None
    with active_engine.begin() as connection:
        row = connection.execute(
            text("SELECT revision FROM schema_migrations ORDER BY applied_at DESC LIMIT 1")
        ).first()
    return row[0] if row else None
