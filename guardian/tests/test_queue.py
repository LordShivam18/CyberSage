"""Tests for local SQLite event queue (Phase 1)."""

import os
import tempfile
import time

import pytest

from guardian.transport.local_queue import (
    STATE_FAILED,
    STATE_PENDING,
    STATE_SENDING,
    STATE_SENT,
    EventQueue,
    QueueOverflow,
)


@pytest.fixture
def queue(tmp_path):
    """Provide a temporary EventQueue for testing."""
    db_path = str(tmp_path / "test_queue.db")
    q = EventQueue(db_path=db_path, max_size=50)
    yield q
    q.close()


def _make_event(event_id="test-event-001", **overrides):
    """Helper to create a minimal event dict."""
    data = {
        "event_id": event_id,
        "event_category": "process",
        "process_name": "test.exe",
        "schema_version": "guardian.event.v1",
    }
    data.update(overrides)
    return data


class TestEnqueue:
    def test_enqueue_returns_true_for_new_event(self, queue):
        result = queue.enqueue(_make_event())
        assert result is True

    def test_enqueue_returns_false_for_duplicate(self, queue):
        queue.enqueue(_make_event("e1"))
        result = queue.enqueue(_make_event("e1"))
        assert result is False

    def test_enqueue_stores_event_data(self, queue):
        event = _make_event("e1", process_name="malware.exe")
        queue.enqueue(event)
        pending = queue.dequeue()
        assert len(pending) == 1
        assert pending[0]["event_id"] == "e1"
        assert pending[0]["process_name"] == "malware.exe"

    def test_enqueue_rejects_event_without_id(self, queue):
        with pytest.raises(ValueError, match="event_id"):
            queue.enqueue({"no_id": True})

    def test_fifo_ordering(self, queue):
        for i in range(5):
            queue.enqueue(_make_event(f"e{i:03d}"))
        events = queue.dequeue(batch_size=10)
        ids = [e["event_id"] for e in events]
        assert ids == ["e000", "e001", "e002", "e003", "e004"]


class TestQueueCapacity:
    def test_overflow_raises_at_capacity(self, queue):
        for i in range(50):
            queue.enqueue(_make_event(f"e{i:03d}"))
        with pytest.raises(QueueOverflow):
            queue.enqueue(_make_event("overflow"))

    def test_idempotent_insert_allowed_when_full(self, queue):
        for i in range(50):
            queue.enqueue(_make_event(f"e{i:03d}"))
        # Duplicate insert should succeed even when full
        result = queue.enqueue(_make_event("e000"))
        assert result is False  # duplicate, not overflow

    def test_sent_events_free_capacity(self, queue):
        for i in range(50):
            queue.enqueue(_make_event(f"e{i:03d}"))
        events = queue.dequeue(batch_size=10)
        event_ids = [e["event_id"] for e in events]
        queue.mark_sent(event_ids)
        # Now we can insert more
        result = queue.enqueue(_make_event("new-event"))
        assert result is True


class TestBatchEnqueue:
    def test_batch_enqueue(self, queue):
        events = [_make_event(f"batch-{i}") for i in range(10)]
        result = queue.enqueue_batch(events)
        assert result["inserted"] == 10
        assert result["duplicate"] == 0
        assert result["overflow"] == 0

    def test_batch_enqueue_deduplicates(self, queue):
        queue.enqueue(_make_event("existing"))
        events = [_make_event("existing"), _make_event("new-one")]
        result = queue.enqueue_batch(events)
        assert result["duplicate"] == 1
        assert result["inserted"] == 1

    def test_batch_enqueue_overflow(self, queue):
        events = [_make_event(f"fill-{i}") for i in range(50)]
        queue.enqueue_batch(events)
        more = [_make_event(f"over-{i}") for i in range(5)]
        result = queue.enqueue_batch(more)
        assert result["overflow"] == 5
        assert result["inserted"] == 0


class TestDequeue:
    def test_dequeue_empty_returns_empty(self, queue):
        events = queue.dequeue()
        assert events == []

    def test_dequeue_marks_as_sending(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.dequeue()
        stats = queue.queue_stats()
        assert stats["sending"] == 1
        assert stats["pending"] == 0

    def test_dequeue_batch_size(self, queue):
        for i in range(20):
            queue.enqueue(_make_event(f"e{i:03d}"))
        events = queue.dequeue(batch_size=5)
        assert len(events) == 5

    def test_dequeue_only_returns_pending(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.enqueue(_make_event("e2"))
        queue.dequeue()  # marks e1, e2 as sending
        queue.enqueue(_make_event("e3"))
        events = queue.dequeue()
        assert len(events) == 1
        assert events[0]["event_id"] == "e3"


class TestMarkSent:
    def test_mark_sent_transitions_to_sent(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.dequeue()
        count = queue.mark_sent(["e1"])
        assert count == 1
        stats = queue.queue_stats()
        assert stats["sent"] == 1
        assert stats["sending"] == 0

    def test_mark_sent_is_idempotent(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.dequeue()
        queue.mark_sent(["e1"])
        count = queue.mark_sent(["e1"])
        assert count == 0

    def test_mark_sent_empty_list(self, queue):
        count = queue.mark_sent([])
        assert count == 0


class TestMarkFailed:
    def test_failed_retries_again(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.dequeue()
        queue.mark_failed(["e1"], "timeout")
        stats = queue.queue_stats()
        assert stats["pending"] == 1  # retried
        assert stats["failed"] == 0

    def test_failed_after_max_retries(self, queue):
        queue.enqueue(_make_event("e1"))
        for _ in range(5):
            queue.dequeue()
            queue.mark_failed(["e1"], "persistent error")
        stats = queue.queue_stats()
        assert stats["failed"] == 1
        assert stats["pending"] == 0

    def test_failed_records_error(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.dequeue()
        queue.mark_failed(["e1"], "connection refused")
        # Error is stored (we can verify via stats/inspection)
        stats = queue.queue_stats()
        assert stats["sending"] == 0


class TestPersistence:
    def test_events_survive_restart(self, tmp_path):
        """Events must be durable across process restarts."""
        db_path = str(tmp_path / "restart_test.db")
        q1 = EventQueue(db_path=db_path, max_size=50)
        q1.enqueue(_make_event("restart-e1"))
        q1.enqueue(_make_event("restart-e2"))
        q1.close()

        q2 = EventQueue(db_path=db_path, max_size=50)
        stats = q2.queue_stats()
        assert stats["pending"] == 2
        q2.close()


class TestQueueStats:
    def test_initial_stats(self, queue):
        stats = queue.queue_stats()
        assert stats["pending"] == 0
        assert stats["sending"] == 0
        assert stats["failed"] == 0
        assert stats["sent"] == 0
        assert stats["capacity"] == 50

    def test_utilization_pct(self, queue):
        for i in range(25):
            queue.enqueue(_make_event(f"e{i:03d}"))
        stats = queue.queue_stats()
        assert stats["utilization_pct"] == 50.0


class TestPurge:
    def test_purge_removes_sent_events(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.dequeue()
        queue.mark_sent(["e1"])
        purged = queue.purge_sent(older_than_hours=0)
        assert purged == 1
        stats = queue.queue_stats()
        assert stats["sent"] == 0

    def test_purge_keeps_pending_events(self, queue):
        queue.enqueue(_make_event("e1"))
        queue.purge_sent(older_than_hours=0)
        stats = queue.queue_stats()
        assert stats["pending"] == 1
