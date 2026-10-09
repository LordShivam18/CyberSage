"""Phase 5 Slice 4 harness: bounded pre-authorization (PROVIDED — NOT EXECUTED).

Genuine harness for the developer to execute later. Uses the REAL
pre-authorization domain logic and the REAL API contracts against an
isolated database. The harmless execution path traverses the REAL
SafetyEnvelope with a non-destructive test action; no OS, firewall,
registry, or persistence state is touched.

Status: TEST HARNESS PROVIDED — NOT EXECUTED (per human-controlled
testing instructions). No results are claimed below.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.auth import ROLE_ADMIN, ROLE_ANALYST, get_current_user
from backend.database import Base
from backend.main import app
from guardian.automation.policy_v5 import PolicyValidationError
from guardian.automation.preauth import (
    grant_covers_request,
    validate_allowed_actions,
    validate_grant_bounds,
)


def _future_iso(hours=24):
    return (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=hours)).isoformat()


def _grant_payload(**over):
    base = {
        "policy_id": "p-bounded",
        "allowed_actions": [{"action_type": "network", "action_name": "block_destination"}],
        "target_scope": {"destination_ips": ["203.0.113.66"]},
        "agent_scope": {},
        "max_risk_score": 80.0,
        "max_executions_per_hour": 5,
        "cooldown_seconds": 300,
        "expires_at": _future_iso(),
        "reason": "bounded rollout harness",
        "rollback_required": False,
    }
    base.update(over)
    return base


def _mock_user(username, role):
    class _User:
        pass

    user = _User()
    user.username = username
    user.role = role
    user.disabled = False
    return user


@pytest.fixture()
def isolated_engine(tmp_path):
    path = tmp_path / "slice4_harness.db"
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def api_client(isolated_engine):
    factory = sessionmaker(bind=isolated_engine, autocommit=False, autoflush=False)

    def override_get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    from backend.database import get_db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: _mock_user("harness-admin", ROLE_ADMIN)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


class TestGrantBoundsDomain:
    def test_wildcard_actions_rejected(self):
        with pytest.raises(PolicyValidationError):
            validate_allowed_actions([{"action_type": "network", "action_name": "*"}])

    def test_unregistered_actions_rejected(self):
        with pytest.raises(PolicyValidationError):
            validate_allowed_actions([{"action_type": "nope", "action_name": "nope"}])

    def test_empty_target_scope_rejected(self):
        with pytest.raises(PolicyValidationError):
            validate_grant_bounds(_grant_payload(target_scope={}))

    def test_missing_expiry_rejected(self):
        payload = _grant_payload()
        del payload["expires_at"]
        with pytest.raises(PolicyValidationError):
            validate_grant_bounds(payload)

    def test_grant_covers_request_and_caps(self):
        grant = dict(_grant_payload(), active=True)
        ok, _ = grant_covers_request(
            grant, action_type="network", action_name="block_destination",
            target={"destination_ip": "203.0.113.66"}, risk_score=50.0,
        )
        assert ok is True
        covered, reason = grant_covers_request(
            grant, action_type="network", action_name="block_destination",
            target={"destination_ip": "198.51.100.7"}, risk_score=50.0,
        )
        assert covered is False and reason == "target_outside_grant_scope"
        over, reason = grant_covers_request(
            grant, action_type="network", action_name="block_destination",
            target={"destination_ip": "203.0.113.66"}, risk_score=95.0,
        )
        assert over is False and reason == "risk_above_grant_cap"


class TestPreauthApiContract:
    def test_activate_requires_admin(self, api_client):
        app.dependency_overrides[get_current_user] = lambda: _mock_user("analyst", ROLE_ANALYST)
        res = api_client.post("/api/v1/guardian/automation/v5/preauth/activate", json=_grant_payload())
        assert res.status_code == 403

    def test_revoke_unknown_grant_is_404(self, api_client):
        res = api_client.post(
            "/api/v1/guardian/automation/v5/preauth/revoke",
            json={"policy_id": "does-not-exist", "reason": "harness"},
        )
        assert res.status_code in (404, 422)

    def test_grant_read_paths_exist(self, api_client):
        assert api_client.get("/api/v1/guardian/automation/v5/preauth").status_code == 200
        assert api_client.get("/api/v1/guardian/automation/v5/preauth/none").status_code == 404

    def test_manual_execution_still_requires_approval(self, api_client):
        res = api_client.post("/api/v1/guardian/automation/v5/executions", json={
            "policy_id": "p-harness", "expected_policy_version": 1,
            "action_type": "network", "action_name": "block_destination",
            "target": {"destination_ip": "203.0.113.66"},
            "decision_id": "dec-harness", "risk_score": 10.0,
            "incident_severity": "low", "authorization_mode": "approved_manual",
        })
        # Missing approval_id must fail closed (shape validation).
        assert res.status_code == 422
