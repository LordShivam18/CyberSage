"""Integration tests for Guardian v2 Phase 1 API endpoints.

Tests the backend API endpoints with a real database using FastAPI's TestClient.
Skips automatically when backend dependencies (pandas, etc.) are not installed.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest

try:
    from fastapi.testclient import TestClient
    from backend.main import app
    from backend.database import Base, engine, SessionLocal
    from backend.auth import create_user, create_access_token
    from backend.models import User
except ImportError as exc:
    pytest.skip(
        f"Backend dependencies not available: {exc}",
        allow_module_level=True,
    )


@pytest.fixture(autouse=True)
def setup_database():
    """Create all tables before each test, drop after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def admin_user():
    """Create an admin user and return (user, token)."""
    db = SessionLocal()
    try:
        user = create_user(db, "guardian-admin", "Admin123456!", "administrator")
        db.commit()
        token = create_access_token(user)
        return user, token
    finally:
        db.close()


@pytest.fixture
def analyst_user():
    """Create an analyst user and return (user, token)."""
    db = SessionLocal()
    try:
        user = create_user(db, "guardian-analyst", "Analyst123456!", "security_analyst")
        db.commit()
        token = create_access_token(user)
        return user, token
    finally:
        db.close()


@pytest.fixture
def auditor_user():
    """Create an auditor user and return (user, token)."""
    db = SessionLocal()
    try:
        user = create_user(db, "guardian-auditor", "Auditor123456!", "read_only_auditor")
        db.commit()
        token = create_access_token(user)
        return user, token
    finally:
        db.close()


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestAgentRegistration:
    def test_register_agent(self, client, admin_user):
        _, token = admin_user
        response = client.post(
            "/api/v1/guardian/agents/register",
            json={
                "agent_key": "agent-001",
                "hostname": "DESKTOP-01",
                "host_id": "host-001",
                "os_name": "Windows",
                "os_version": "10.0.19045",
                "agent_version": "2.0.0",
            },
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "registered"
        assert data["agent"]["agent_key"] == "agent-001"
        assert data["agent"]["hostname"] == "DESKTOP-01"

    def test_register_agent_idempotent(self, client, admin_user):
        _, token = admin_user
        payload = {
            "agent_key": "agent-001",
            "hostname": "DESKTOP-01",
            "os_name": "Windows",
        }
        r1 = client.post(
            "/api/v1/guardian/agents/register",
            json=payload,
            headers=_auth_header(token),
        )
        r2 = client.post(
            "/api/v1/guardian/agents/register",
            json={**payload, "hostname": "DESKTOP-02"},
            headers=_auth_header(token),
        )
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["agent"]["id"] == r2.json()["agent"]["id"]

    def test_register_requires_auth(self, client):
        response = client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "a", "hostname": "h"},
        )
        assert response.status_code in (401, 403)

    def test_register_requires_role(self, client, auditor_user):
        _, token = auditor_user
        response = client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "a", "hostname": "h"},
            headers=_auth_header(token),
        )
        assert response.status_code == 403

    def test_list_agents(self, client, admin_user):
        _, token = admin_user
        # Register an agent first
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        response = client.get(
            "/api/v1/guardian/agents",
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1

    def test_get_agent_detail(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        agent_id = r.json()["agent"]["id"]
        response = client.get(
            f"/api/v1/guardian/agents/{agent_id}",
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        assert response.json()["agent_key"] == "agent-001"


class TestHeartbeat:
    def test_heartbeat(self, client, admin_user):
        _, token = admin_user
        # Register agent first
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        response = client.post(
            "/api/v1/guardian/heartbeat",
            json={
                "agent_version": "2.0.0",
                "uptime_seconds": 3600,
                "events_queued": 10,
                "events_processed": 5,
            },
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_heartbeat_without_agent(self, client, admin_user):
        _, token = admin_user
        response = client.post(
            "/api/v1/guardian/heartbeat",
            json={"uptime_seconds": 100},
            headers=_auth_header(token),
        )
        assert response.status_code == 404

    def test_heartbeat_requires_auth(self, client):
        response = client.post(
            "/api/v1/guardian/heartbeat",
            json={"uptime_seconds": 100},
        )
        assert response.status_code in (401, 403)


class TestEventIngestion:
    def test_ingest_single_event(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        response = client.post(
            "/api/v1/guardian/events",
            json={
                "events": [
                    {
                        "event_id": "guardian-test-001",
                        "event_category": "process",
                        "process_name": "cmd.exe",
                        "process_pid": 1234,
                    }
                ]
            },
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["created"] == 1
        assert data["duplicate"] == 0

    def test_ingest_batch(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        events = [
            {"event_id": f"guardian-batch-{i}", "event_category": "process"}
            for i in range(5)
        ]
        response = client.post(
            "/api/v1/guardian/events",
            json={"events": events},
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 5
        assert data["created"] == 5

    def test_idempotent_event_ingestion(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        payload = {
            "events": [{"event_id": "guardian-dup-001", "event_category": "process"}]
        }
        r1 = client.post(
            "/api/v1/guardian/events",
            json=payload,
            headers=_auth_header(token),
        )
        r2 = client.post(
            "/api/v1/guardian/events",
            json=payload,
            headers=_auth_header(token),
        )
        assert r1.status_code == 200
        assert r1.json()["created"] == 1
        assert r2.status_code == 200
        assert r2.json()["duplicate"] == 1

    def test_empty_events_rejected(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        response = client.post(
            "/api/v1/guardian/events",
            json={"events": []},
            headers=_auth_header(token),
        )
        assert response.status_code == 422

    def test_events_require_auth(self, client):
        response = client.post(
            "/api/v1/guardian/events",
            json={"events": [{"event_id": "e1"}]},
        )
        assert response.status_code in (401, 403)

    def test_mixed_category_batch_succeeds(self, client, admin_user):
        """Regression: batch with process + file events must not return 500.

        The process event triggers RecurrenceState.increment() which requires
        the guardian_recurrence_state table. The file event's db.query() must
        not fail on a broken session after the first dispatch.
        """
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        # This exact payload mirrors the runtime release gate CI validation
        import uuid
        event_id_1 = f"runtime-guardian-event-{uuid.uuid4().hex[:12]}"
        event_id_2 = f"runtime-guardian-event-{uuid.uuid4().hex[:12]}"
        response = client.post(
            "/api/v1/guardian/events",
            json={
                "agent_key": "agent-001",
                "events": [
                    {"event_id": event_id_1, "event_category": "process", "process_name": "ci-test"},
                    {"event_id": event_id_2, "event_category": "file", "file_path": "/tmp/test"},
                ],
            },
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["created"] == 2
        assert data["duplicate"] == 0

    def test_recurrence_state_table_created_automatically(self, client, admin_user):
        """Regression: RecurrenceState must create its table on first use."""
        from sqlalchemy import text
        from backend.database import SessionLocal
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        client.post(
            "/api/v1/guardian/events",
            json={
                "events": [
                    {"event_id": "recurrence-test-001", "event_category": "process", "process_name": "test.exe"}
                ]
            },
            headers=_auth_header(token),
        )
        db = SessionLocal()
        try:
            # Use dialect-agnostic check (works on both PostgreSQL and SQLite)
            result = db.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='guardian_recurrence_state'")
            ).fetchone()
            if result is None:
                # Fallback for PostgreSQL
                result = db.execute(
                    text("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'guardian_recurrence_state')")
                ).scalar()
                assert result is True, "guardian_recurrence_state table was not created automatically"
            else:
                assert result[0] == "guardian_recurrence_state"
        finally:
            db.close()


class TestEventQuery:
    def test_list_events(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        # Ingest some events
        client.post(
            "/api/v1/guardian/events",
            json={
                "events": [
                    {"event_id": f"guardian-q-{i}", "event_category": "process"}
                    for i in range(3)
                ]
            },
            headers=_auth_header(token),
        )
        response = client.get(
            "/api/v1/guardian/events",
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert len(data["items"]) == 3

    def test_list_events_with_category_filter(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        client.post(
            "/api/v1/guardian/events",
            json={
                "events": [
                    {"event_id": "guardian-f1", "event_category": "process"},
                    {"event_id": "guardian-f2", "event_category": "file"},
                ]
            },
            headers=_auth_header(token),
        )
        response = client.get(
            "/api/v1/guardian/events?event_category=process",
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        assert response.json()["total"] == 1

    def test_list_events_pagination(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        client.post(
            "/api/v1/guardian/events",
            json={
                "events": [
                    {"event_id": f"guardian-p-{i}", "event_category": "process"}
                    for i in range(10)
                ]
            },
            headers=_auth_header(token),
        )
        response = client.get(
            "/api/v1/guardian/events?limit=3&offset=0",
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 10
        assert len(data["items"]) == 3
        assert data["limit"] == 3
        assert data["offset"] == 0


class TestGuardianStats:
    def test_stats(self, client, admin_user):
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "agent-001", "hostname": "DESKTOP-01"},
            headers=_auth_header(token),
        )
        client.post(
            "/api/v1/guardian/events",
            json={
                "events": [
                    {"event_id": "guardian-s1", "event_category": "process"},
                    {"event_id": "guardian-s2", "event_category": "file"},
                ]
            },
            headers=_auth_header(token),
        )
        response = client.get(
            "/api/v1/guardian/stats",
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agents"]["total"] >= 1
        assert data["events"]["total"] == 2
        assert "process" in data["events"]["by_category"]


class TestReadExistingV1Compat:
    """Verify v1.1 endpoints are unaffected by Guardian additions."""

    def test_v1_health(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_v1_ready(self, client):
        response = client.get("/api/v1/ready")
        assert response.status_code == 200

    def test_v1_login(self, client, admin_user):
        _, token = admin_user
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "guardian-admin", "password": "Admin123456!"},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

    def test_v1_alerts(self, client, admin_user):
        _, token = admin_user
        response = client.get(
            "/api/v1/alerts",
            headers=_auth_header(token),
        )
        assert response.status_code == 200

    def test_v1_incidents(self, client, admin_user):
        _, token = admin_user
        response = client.get(
            "/api/v1/incidents",
            headers=_auth_header(token),
        )
        assert response.status_code == 200

    def test_v1_metrics(self, client, admin_user):
        _, token = admin_user
        response = client.get(
            "/api/v1/metrics",
            headers=_auth_header(token),
        )
        assert response.status_code == 200


class TestAgentIdentity:
    """Verify stable agent identity: heartbeat and events use agent_key."""

    def test_heartbeat_with_agent_key(self, client, admin_user):
        """Heartbeat with agent_key resolves the correct agent."""
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "identity-agent-001", "hostname": "host-a"},
            headers=_auth_header(token),
        )
        assert r.status_code == 200
        agent_id = r.json()["agent"]["id"]

        # Heartbeat with agent_key
        r_hb = client.post(
            "/api/v1/guardian/heartbeat",
            json={"agent_key": "identity-agent-001", "uptime_seconds": 10},
            headers=_auth_header(token),
        )
        assert r_hb.status_code == 200
        assert r_hb.json()["agent_id"] == agent_id

    def test_events_with_agent_key(self, client, admin_user):
        """Events with agent_key are associated with the correct agent."""
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "identity-agent-002", "hostname": "host-b"},
            headers=_auth_header(token),
        )
        agent_id = r.json()["agent"]["id"]

        # Ingest events with agent_key
        r_ev = client.post(
            "/api/v1/guardian/events",
            json={
                "agent_key": "identity-agent-002",
                "events": [{"event_id": "id-test-001", "event_category": "process"}],
            },
            headers=_auth_header(token),
        )
        assert r_ev.status_code == 200
        assert r_ev.json()["created"] == 1

        # Verify the event is associated with the correct agent
        r_list = client.get(
            f"/api/v1/guardian/events?agent_id={agent_id}",
            headers=_auth_header(token),
        )
        assert r_list.status_code == 200
        assert r_list.json()["total"] == 1
        assert r_list.json()["items"][0]["event_id"] == "id-test-001"

    def test_heartbeat_without_agent_key_falls_back(self, client, admin_user):
        """Heartbeat without agent_key falls back to most recent agent."""
        _, token = admin_user
        client.post(
            "/api/v1/guardian/agents/register",
            json={"agent_key": "fallback-agent", "hostname": "host-c"},
            headers=_auth_header(token),
        )
        r_hb = client.post(
            "/api/v1/guardian/heartbeat",
            json={"uptime_seconds": 5},
            headers=_auth_header(token),
        )
        assert r_hb.status_code == 200
        assert r_hb.json()["status"] == "ok"
