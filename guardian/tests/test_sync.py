"""Tests for backend synchronization (Phase 1)."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from guardian.transport.local_queue import EventQueue
from guardian.transport.sync import (
    DEFAULT_MAX_BACKOFF,
    TransientSyncError,
    PermanentSyncError,
    SyncWorker,
)


@pytest.fixture
def queue(tmp_path):
    db_path = str(tmp_path / "sync_test.db")
    q = EventQueue(db_path=db_path, max_size=100)
    yield q
    q.close()


def _make_event(event_id="sync-e1"):
    return {
        "event_id": event_id,
        "event_category": "process",
        "process_name": "test.exe",
    }


# Shared mutable state for mock server
class _MockState:
    def __init__(self):
        self.last_request = None
        self.last_request_body = None
        self.response_code = 200
        self.response_body = '{"status":"ok"}'

_mock_state = _MockState()


class MockBackendHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for testing sync."""

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        _mock_state.last_request_body = self.rfile.read(content_length) if content_length else b""
        _mock_state.last_request = {
            "path": self.path,
            "method": self.command,
            "headers": dict(self.headers),
        }
        self.send_response(_mock_state.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(_mock_state.response_body.encode())

    def log_message(self, format, *args):
        pass  # Suppress logs during tests


@pytest.fixture
def mock_server():
    """Start a mock HTTP server for sync tests."""
    _mock_state.last_request = None
    _mock_state.last_request_body = None
    _mock_state.response_code = 200
    _mock_state.response_body = '{"status":"ok"}'
    server = HTTPServer(("127.0.0.1", 0), MockBackendHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, port
    server.shutdown()


class TestSyncWorkerUpload:
    def test_successful_upload(self, queue, mock_server):
        server, port = mock_server
        queue.enqueue(_make_event("upload-e1"))

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
            sync_interval=100,
            batch_size=10,
        )

        worker._sync_once()

        stats = queue.queue_stats()
        assert stats["sent"] == 1
        assert stats["pending"] == 0

    def test_batch_upload(self, queue, mock_server):
        server, port = mock_server
        for i in range(5):
            queue.enqueue(_make_event(f"batch-{i}"))

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
            batch_size=10,
        )
        worker._sync_once()

        stats = queue.queue_stats()
        assert stats["sent"] == 5

    def test_empty_queue_no_request(self, queue, mock_server):
        server, port = mock_server
        _mock_state.last_request = None

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
        )
        count = worker._sync_once()

        assert count == 0
        assert _mock_state.last_request is None

    def test_auth_token_sent(self, queue, mock_server):
        server, port = mock_server
        queue.enqueue(_make_event("auth-e1"))

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="my-secret-token",
        )
        worker._sync_once()

        assert _mock_state.last_request is not None
        headers = _mock_state.last_request["headers"]
        # urllib lowercases header names
        auth_header = headers.get("authorization") or headers.get("Authorization")
        assert auth_header == "Bearer my-secret-token"

    def test_events_in_request_body(self, queue, mock_server):
        server, port = mock_server
        queue.enqueue(_make_event("body-e1"))

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
        )
        worker._sync_once()

        assert _mock_state.last_request_body is not None
        body = json.loads(_mock_state.last_request_body)
        assert "events" in body
        assert len(body["events"]) == 1
        assert body["events"][0]["event_id"] == "body-e1"


class TestSyncWorkerRetry:
    def test_server_error_retries(self, queue, mock_server):
        server, port = mock_server
        _mock_state.response_code = 500
        queue.enqueue(_make_event("retry-e1"))

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
        )
        worker._sync_once()

        stats = queue.queue_stats()
        assert stats["pending"] == 1  # retried
        assert worker.consecutive_failures == 1

    def test_auth_error_does_not_retry(self, queue, mock_server):
        server, port = mock_server
        _mock_state.response_code = 401
        queue.enqueue(_make_event("auth-fail-e1"))

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="bad-token",
        )
        worker._sync_once()

        stats = queue.queue_stats()
        assert stats["failed"] == 1, f"Expected 1 failed, got stats: {stats}"
        assert stats["pending"] == 0
        assert worker.consecutive_failures == 1

    def test_schema_error_does_not_retry(self, queue, mock_server):
        server, port = mock_server
        _mock_state.response_code = 422
        queue.enqueue(_make_event("schema-e1"))

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
        )
        worker._sync_once()

        stats = queue.queue_stats()
        assert stats["failed"] == 1  # permanent failure


class TestSyncWorkerStartStop:
    def test_start_stop_lifecycle(self, queue, mock_server):
        server, port = mock_server
        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
            sync_interval=100,
        )
        worker.start()
        assert worker.is_running is True
        worker.stop()
        assert worker.is_running is False

    def test_start_idempotent(self, queue, mock_server):
        server, port = mock_server
        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
        )
        worker.start()
        worker.start()  # Should not create a second thread
        worker.stop()

    def test_stop_idempotent(self, queue, mock_server):
        server, port = mock_server
        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
        )
        worker.stop()  # Not started, should not raise

    def test_sync_complete_callback(self, queue, mock_server):
        server, port = mock_server
        queue.enqueue(_make_event("cb-e1"))
        synced_count = []

        def on_complete(count):
            synced_count.append(count)

        worker = SyncWorker(
            queue=queue,
            backend_url=f"http://127.0.0.1:{port}",
            auth_token="test-token",
            on_sync_complete=on_complete,
        )
        worker._sync_once()
        assert synced_count == [1]
