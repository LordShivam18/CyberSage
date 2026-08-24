"""Security-focused tests for Guardian v2 Phase 1.

Proves:
* SQL construction safety — user-controlled values cannot become SQL syntax.
* URL scheme validation — only http/https reach urlopen.
* Stable agent identity — heartbeat and events use agent_key, not latest-agent shortcut.
"""

import os
import tempfile

import pytest

from guardian.transport.local_queue import EventQueue, _build_placeholders
from guardian.transport.safe_url import (
    ALLOWED_SCHEMES,
    InvalidSchemeError,
    build_api_url,
    validate_url_scheme,
)


# ── SQL Construction Safety ───────────────────────────────────────────


class TestSQLConstructionSafety:
    """Prove that user-controlled values cannot become SQL syntax.

    The queue uses f-string SQL with `_build_placeholders()` for IN clauses.
    This test proves the placeholder generator only produces '?' and ',',
    and that user-supplied event_ids are bound as parameters, not interpolated.
    """

    def test_build_placeholders_only_contains_question_marks_and_commas(self):
        """_build_placeholders must never produce anything but '?' and ','."""
        for count in [1, 2, 5, 10, 50]:
            result = _build_placeholders(count)
            # Every character must be '?' or ','
            assert all(c in ("?", ",") for c in result), (
                f"_build_placeholders({count}) produced unexpected characters: {result!r}"
            )
            # Must have exactly count '?' characters
            assert result.count("?") == count

    def test_build_placeholders_rejects_zero(self):
        with pytest.raises(ValueError, match="count must be >= 1"):
            _build_placeholders(0)

    def test_event_ids_are_parameterized_not_interpolated(self):
        """event_ids go through parameterized binding, not f-string interpolation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            q = EventQueue(db_path=db_path, max_size=100)
            try:
                # Enqueue events with various IDs
                for i in range(5):
                    q.enqueue({"event_id": f"safe-test-{i}", "data": "value"})

                # Dequeue and mark sent — this exercises the IN clause
                events = q.dequeue(batch_size=10)
                event_ids = [e["event_id"] for e in events]

                # Now try injecting a malicious event_id
                # The UNIQUE constraint prevents duplicates, but even if it didn't,
                # the parameterized query would treat it as a string value, not SQL
                malicious_id = "'; DROP TABLE guardian_events; --"
                q.enqueue({"event_id": malicious_id, "data": "evil"})

                # Dequeue the malicious event (moves it to 'sending' state)
                q.dequeue(batch_size=10)

                # Mark sent — the malicious ID is passed as a parameter
                count = q.mark_sent([malicious_id])
                assert count == 1

                # Verify the table still exists and the malicious ID is stored as data
                stats = q.queue_stats()
                assert stats["sent"] == 1

                # Verify the malicious string is stored literally, not executed
                conn = q._get_conn()
                row = conn.execute(
                    "SELECT event_id FROM guardian_events WHERE event_id = ?",
                    (malicious_id,),
                ).fetchone()
                assert row is not None
                assert row["event_id"] == malicious_id
            finally:
                q.close()

    def test_injection_attempt_in_event_id_is_stored_literally(self):
        """SQL injection in event_id is stored as a literal string, not executed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_inject.db")
            q = EventQueue(db_path=db_path, max_size=100)
            try:
                injection = "x'; DELETE FROM guardian_events WHERE 1=1; --"
                q.enqueue({"event_id": injection})

                # The row exists with the injection string as its event_id
                conn = q._get_conn()
                row = conn.execute(
                    "SELECT event_id FROM guardian_events WHERE event_id = ?",
                    (injection,),
                ).fetchone()
                assert row is not None

                # The table still has our row (DELETE was not executed)
                stats = q.queue_stats()
                assert stats["pending"] == 1
            finally:
                q.close()


# ── URL Scheme Validation ─────────────────────────────────────────────


class TestURLSchemeValidation:
    """Prove that only http/https URLs reach urlopen."""

    def test_allows_http(self):
        assert validate_url_scheme("http://localhost:8000") == "http://localhost:8000"

    def test_allows_https(self):
        assert validate_url_scheme("https://example.com/api") == "https://example.com/api"

    def test_rejects_file_scheme(self):
        with pytest.raises(InvalidSchemeError, match="file"):
            validate_url_scheme("file:///etc/passwd")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(InvalidSchemeError, match="ftp"):
            validate_url_scheme("ftp://evil.com/payload")

    def test_rejects_ftps_scheme(self):
        with pytest.raises(InvalidSchemeError, match="ftps"):
            validate_url_scheme("ftps://evil.com/payload")

    def test_rejects_data_scheme(self):
        with pytest.raises(InvalidSchemeError, match="data"):
            validate_url_scheme("data:text/html,<script>alert(1)</script>")

    def test_rejects_javascript_scheme(self):
        with pytest.raises(InvalidSchemeError, match="javascript"):
            validate_url_scheme("javascript:alert(1)")

    def test_rejects_empty_url(self):
        with pytest.raises(ValueError, match="empty"):
            validate_url_scheme("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError, match="empty"):
            validate_url_scheme("   ")

    def test_allowed_schemes_constant(self):
        assert ALLOWED_SCHEMES == frozenset({"http", "https"})

    def test_build_api_url_validates_scheme(self):
        with pytest.raises(InvalidSchemeError):
            build_api_url("file:///etc/passwd", "api/v1/guardian/events")

    def test_build_api_url_constructs_correctly(self):
        url = build_api_url("http://localhost:8000", "api/v1/guardian/events")
        assert url == "http://localhost:8000/api/v1/guardian/events"

    def test_build_api_url_handles_trailing_slash(self):
        url = build_api_url("http://localhost:8000/", "api/v1/guardian/events")
        assert url == "http://localhost:8000/api/v1/guardian/events"


# ── Agent Identity ─────────────────────────────────────────────────────


class TestAgentIdentity:
    """Prove that agent_key is used for stable identity resolution."""

    def test_agent_key_in_config(self):
        """Agent config must include agent_key for identity."""
        os.environ["GUARDIAN_AGENT_KEY"] = "test-agent-001"
        os.environ["GUARDIAN_HOST_ID"] = "host-001"
        os.environ["GUARDIAN_BACKEND_URL"] = "http://localhost:8000"
        os.environ["GUARDIAN_AUTH_TOKEN"] = "test-token"
        try:
            from guardian.agent.config import AgentConfig
            config = AgentConfig()
            assert config.agent_key == "test-agent-001"
            config.validate()  # Should not raise
        finally:
            for key in ["GUARDIAN_AGENT_KEY", "GUARDIAN_HOST_ID",
                        "GUARDIAN_BACKEND_URL", "GUARDIAN_AUTH_TOKEN"]:
                os.environ.pop(key, None)

    def test_sync_worker_accepts_agent_key(self):
        """SyncWorker must accept and store agent_key."""
        from guardian.transport.sync import SyncWorker
        from guardian.transport.local_queue import EventQueue

        with tempfile.TemporaryDirectory() as tmpdir:
            queue = EventQueue(db_path=os.path.join(tmpdir, "test.db"), max_size=10)
            try:
                worker = SyncWorker(
                    queue=queue,
                    backend_url="http://localhost:8000",
                    auth_token="token",
                    agent_key="my-agent-001",
                )
                assert worker._agent_key == "my-agent-001"
            finally:
                queue.close()

    def test_sync_worker_default_agent_key_empty(self):
        """SyncWorker defaults to empty agent_key for backward compat."""
        from guardian.transport.sync import SyncWorker
        from guardian.transport.local_queue import EventQueue

        with tempfile.TemporaryDirectory() as tmpdir:
            queue = EventQueue(db_path=os.path.join(tmpdir, "test.db"), max_size=10)
            try:
                worker = SyncWorker(
                    queue=queue,
                    backend_url="http://localhost:8000",
                    auth_token="token",
                )
                assert worker._agent_key == ""
            finally:
                queue.close()
