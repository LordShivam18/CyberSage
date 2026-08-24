"""PostgreSQL-backed recurrence state.

Replaces in-memory counters with bounded, persistent state.
Tracks event counts per (host_id, entity_key) for recurrence detection.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class RecurrenceState:
    """PostgreSQL-backed recurrence counter.

    Tracks counts per (host_id, entity_key) with automatic expiration.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def ensure_table(self) -> None:
        """Create the recurrence state table if it doesn't exist."""
        self._session.execute(text("""
            CREATE TABLE IF NOT EXISTS guardian_recurrence_state (
                id SERIAL PRIMARY KEY,
                host_id VARCHAR(128) NOT NULL,
                entity_key VARCHAR(256) NOT NULL,
                count INTEGER NOT NULL DEFAULT 1,
                window_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                UNIQUE(host_id, entity_key, window_start)
            )
        """))
        self._session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_guardian_recurrence_lookup "
            "ON guardian_recurrence_state(host_id, entity_key)"
        ))
        self._session.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_guardian_recurrence_expires "
            "ON guardian_recurrence_state(expires_at)"
        ))
        self._session.commit()

    def increment(
        self,
        host_id: str,
        entity_key: str,
        window_seconds: int = 3600,
    ) -> int:
        """Increment and return the count for a (host_id, entity_key) pair.

        Args:
            host_id: The host identifier.
            entity_key: The entity being counted (e.g., process name).
            window_seconds: Time window for the counter.

        Returns:
            Current count after increment.
        """
        now = _now_utc()
        expires_at = datetime.fromtimestamp(
            now.timestamp() + window_seconds, tz=timezone.utc
        ).replace(tzinfo=None)

        # Try to find existing window
        row = self._session.execute(
            text("""
                SELECT id, count FROM guardian_recurrence_state
                WHERE host_id = :host_id AND entity_key = :entity_key
                  AND expires_at > :now
                ORDER BY window_start DESC LIMIT 1
            """),
            {"host_id": host_id, "entity_key": entity_key, "now": now},
        ).mappings().first()

        if row:
            new_count = row["count"] + 1
            self._session.execute(
                text("""
                    UPDATE guardian_recurrence_state
                    SET count = :count, last_seen = :now, expires_at = :expires
                    WHERE id = :id
                """),
                {"count": new_count, "now": now, "expires": expires_at, "id": row["id"]},
            )
            self._session.commit()
            return new_count
        else:
            # New window
            self._session.execute(
                text("""
                    INSERT INTO guardian_recurrence_state
                        (host_id, entity_key, count, window_start, last_seen, expires_at)
                    VALUES (:host_id, :entity_key, 1, :now, :now, :expires)
                """),
                {"host_id": host_id, "entity_key": entity_key, "now": now, "expires": expires_at},
            )
            self._session.commit()
            return 1

    def get_count(self, host_id: str, entity_key: str) -> int:
        """Get the current count for a (host_id, entity_key) pair."""
        now = _now_utc()
        row = self._session.execute(
            text("""
                SELECT count FROM guardian_recurrence_state
                WHERE host_id = :host_id AND entity_key = :entity_key
                  AND expires_at > :now
                ORDER BY window_start DESC LIMIT 1
            """),
            {"host_id": host_id, "entity_key": entity_key, "now": now},
        ).mappings().first()
        return row["count"] if row else 0

    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of deleted rows."""
        now = _now_utc()
        result = self._session.execute(
            text("DELETE FROM guardian_recurrence_state WHERE expires_at <= :now"),
            {"now": now},
        )
        self._session.commit()
        return result.rowcount

    def reset(self) -> None:
        """Reset all state (for testing)."""
        self._session.execute(text("DELETE FROM guardian_recurrence_state"))
        self._session.commit()
