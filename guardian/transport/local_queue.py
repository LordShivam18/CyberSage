"""Local SQLite event queue for Guardian v2.

Durable, bounded, FIFO event buffer that survives agent restarts.
Events are stored as JSON and tracked with state, retry count, and timestamps.

Queue states:
    pending  — ready to send
    sending  — currently being transmitted
    failed   — transmission failed, awaiting retry
    sent     — successfully acknowledged by backend

Design:
* SQLite WAL mode for concurrent read/write safety.
* Bounded capacity with explicit overflow state.
* Deterministic event_id uniqueness enforced by UNIQUE constraint.
* Idempotent insert: duplicate event_ids are silently ignored.
* Events removed from the queue only after server acknowledgement.
* No plaintext credentials stored in the queue.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Queue event states
STATE_PENDING = "pending"
STATE_SENDING = "sending"
STATE_FAILED = "failed"
STATE_SENT = "sent"

DEFAULT_MAX_QUEUE_SIZE = 100_000
DEFAULT_DB_PATH = "guardian_queue.db"
DEFAULT_SYNC_INTERVAL_SECONDS = 10
DEFAULT_BATCH_SIZE = 100
DEFAULT_MAX_RETRIES = 5


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_placeholders(count: int) -> str:
    """Build a SQL IN-clause placeholder string.

    Returns a comma-separated string of '?' characters.
    This is safe for f-string interpolation because the output
    contains ONLY '?' and ',' — no user-controlled values.
    """
    if count < 1:
        raise ValueError("count must be >= 1")
    return ",".join("?" * count)


class QueueOverflow(Exception):
    """Raised when the queue has reached its configured capacity."""


class EventQueue:
    """SQLite-backed bounded event queue.

    Thread-safe: all public methods acquire an internal lock.
    """

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        max_size: int = DEFAULT_MAX_QUEUE_SIZE,
    ) -> None:
        self._db_path = db_path
        self._max_size = max_size
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=30,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS guardian_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_data TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 5,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sent_at TEXT
            );

            CREATE INDEX IF NOT EXISTS ix_guardian_queue_status
                ON guardian_events(status);
            CREATE INDEX IF NOT EXISTS ix_guardian_queue_created_at
                ON guardian_events(created_at);
            CREATE INDEX IF NOT EXISTS ix_guardian_queue_event_id
                ON guardian_events(event_id);
            """
        )
        conn.commit()

    def enqueue(self, event_dict: Dict[str, Any]) -> bool:
        """Add an event to the queue.

        Returns True if the event was inserted (new).
        Returns False if the event_id already exists (idempotent).
        Raises QueueOverflow if the queue is at capacity.

        The event_dict must contain an 'event_id' key.
        """
        event_id = event_dict.get("event_id")
        if not event_id:
            raise ValueError("event_dict must contain an 'event_id' key")

        now = _now_iso()
        with self._lock:
            conn = self._get_conn()

            # Check current queue size
            count = conn.execute(
                "SELECT COUNT(*) FROM guardian_events WHERE status != ?",
                (STATE_SENT,),
            ).fetchone()[0]

            if count >= self._max_size:
                # Allow idempotent inserts even when full
                existing = conn.execute(
                    "SELECT 1 FROM guardian_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing:
                    return False
                raise QueueOverflow(
                    f"Queue at capacity ({self._max_size}). "
                    "Events must be synced before accepting more."
                )

            # Idempotent insert
            try:
                conn.execute(
                    """
                    INSERT INTO guardian_events (event_id, event_data, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        json.dumps(event_dict, default=str),
                        STATE_PENDING,
                        now,
                        now,
                    ),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Duplicate event_id — idempotent, not an error
                return False

    def enqueue_batch(self, event_dicts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Enqueue a batch of events.

        Returns a summary: {inserted: N, duplicate: N, overflow: N}.
        Stops inserting on overflow (remaining events are not inserted).
        """
        inserted = 0
        duplicates = 0
        overflow_count = 0

        with self._lock:
            conn = self._get_conn()
            now = _now_iso()

            for event_dict in event_dicts:
                event_id = event_dict.get("event_id")
                if not event_id:
                    continue

                # Check for duplicate
                existing = conn.execute(
                    "SELECT 1 FROM guardian_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if existing:
                    duplicates += 1
                    continue

                # Check capacity
                count = conn.execute(
                    "SELECT COUNT(*) FROM guardian_events WHERE status != ?",
                    (STATE_SENT,),
                ).fetchone()[0]
                if count >= self._max_size:
                    overflow_count += 1
                    continue

                try:
                    conn.execute(
                        """
                        INSERT INTO guardian_events (event_id, event_data, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            json.dumps(event_dict, default=str),
                            STATE_PENDING,
                            now,
                            now,
                        ),
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    duplicates += 1

            conn.commit()

        return {"inserted": inserted, "duplicate": duplicates, "overflow": overflow_count}

    def dequeue(self, batch_size: int = DEFAULT_BATCH_SIZE) -> List[Dict[str, Any]]:
        """Retrieve a batch of pending events for transmission.

        Marks them as 'sending' to prevent concurrent transmission.
        Returns event dicts in FIFO order.
        """
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(
                """
                SELECT id, event_id, event_data
                FROM guardian_events
                WHERE status = ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (STATE_PENDING, batch_size),
            ).fetchall()

            if not rows:
                return []

            now = _now_iso()
            ids = [row["id"] for row in rows]
            # _build_placeholders returns only '?' and ',' — safe for f-string interpolation
            in_clause = _build_placeholders(len(ids))
            conn.execute(
                f"UPDATE guardian_events SET status = ?, updated_at = ? WHERE id IN ({in_clause})",  # nosec B608
                [STATE_SENDING, now] + ids,
            )
            conn.commit()

        return [json.loads(row["event_data"]) for row in rows]

    def mark_sent(self, event_ids: List[str]) -> int:
        """Mark events as successfully sent.

        Returns the number of events marked.
        """
        if not event_ids:
            return 0

        now = _now_iso()
        with self._lock:
            conn = self._get_conn()
            # _build_placeholders returns only '?' and ',' — safe for f-string interpolation
            in_clause = _build_placeholders(len(event_ids))
            cursor = conn.execute(
                f"UPDATE guardian_events SET status = ?, sent_at = ?, updated_at = ? WHERE event_id IN ({in_clause}) AND status = ?",  # nosec B608
                [STATE_SENT, now, now] + event_ids + [STATE_SENDING],
            )
            conn.commit()
            return cursor.rowcount

    def mark_failed(self, event_ids: List[str], error: str, permanent: bool = False) -> int:
        """Mark events as failed after a transmission attempt.

        If ``permanent`` is True, events are immediately moved to 'failed' state
        (e.g., 401/403/422 errors that will not succeed on retry).

        Otherwise, if the event has exceeded max_retries, it remains in 'failed' state.
        If under max_retries, it transitions back to 'pending' for retry.

        Returns the number of events updated.
        """
        if not event_ids:
            return 0

        now = _now_iso()
        with self._lock:
            conn = self._get_conn()
            updated = 0
            for event_id in event_ids:
                row = conn.execute(
                    "SELECT attempt_count, max_retries FROM guardian_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()

                if not row:
                    continue

                new_count = row["attempt_count"] + 1
                if permanent:
                    new_status = STATE_FAILED
                else:
                    new_status = STATE_FAILED if new_count >= row["max_retries"] else STATE_PENDING

                conn.execute(
                    """
                    UPDATE guardian_events
                    SET status = ?, attempt_count = ?, last_error = ?, updated_at = ?
                    WHERE event_id = ?
                    """,
                    (new_status, new_count, error[:1024], now, event_id),
                )
                updated += 1

            conn.commit()
            return updated

    def purge_sent(self, older_than_hours: int = 24) -> int:
        """Remove successfully sent events older than the specified hours.

        Returns the number of events purged.
        """
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None)
        from datetime import timedelta
        cutoff = cutoff - timedelta(hours=older_than_hours)
        cutoff_iso = cutoff.isoformat()

        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                "DELETE FROM guardian_events WHERE status = ? AND sent_at < ?",
                (STATE_SENT, cutoff_iso),
            )
            conn.commit()
            return cursor.rowcount

    def queue_stats(self) -> Dict[str, Any]:
        """Return current queue statistics."""
        with self._lock:
            conn = self._get_conn()
            counts = {}
            for state in [STATE_PENDING, STATE_SENDING, STATE_FAILED, STATE_SENT]:
                row = conn.execute(
                    "SELECT COUNT(*) FROM guardian_events WHERE status = ?",
                    (state,),
                ).fetchone()
                counts[state] = row[0]

            total_active = counts[STATE_PENDING] + counts[STATE_SENDING] + counts[STATE_FAILED]
            return {
                "pending": counts[STATE_PENDING],
                "sending": counts[STATE_SENDING],
                "failed": counts[STATE_FAILED],
                "sent": counts[STATE_SENT],
                "total_active": total_active,
                "capacity": self._max_size,
                "utilization_pct": round(total_active / max(self._max_size, 1) * 100, 1),
            }

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
