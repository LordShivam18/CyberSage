"""Phase 4 tests: Automation, Safety, UI API."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth import create_access_token, ROLE_ADMIN, ROLE_ANALYST
from guardian.automation.policy import (
    AutomationMode, AutomationPolicy, AutomationRule, PolicyDecision, PolicyEngine, DEFAULT_POLICY
)
from guardian.automation.runner import AutomationRunner, AutomationRunRequest, AutomationRunStatus
from guardian.safety.kill_switch import KillSwitch, KillSwitchScope
from guardian.safety.circuit_breaker import CircuitBreaker
from guardian.safety.rate_limiter import ActionRateLimiter
from guardian.ai_boundary import AiAdvisory, AiBoundaryValidator, AiBoundaryViolation

from backend.auth import get_current_user, ROLE_ADMIN, ROLE_ANALYST

# ── API Tests ────────────────────────────────────────────────────────

@pytest.fixture
def admin_user():
    class MockUser:
        username = "admin"
        role = ROLE_ADMIN
        disabled = False
    return MockUser()

@pytest.fixture
def client(admin_user):
    app.dependency_overrides[get_current_user] = lambda: admin_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def test_dashboard_api(client):
    res = client.get("/api/v1/guardian/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "collectors" in data

def test_automation_policies_api(client):
    res = client.get("/api/v1/guardian/automation/policies")
    assert res.status_code == 200
    assert "policies" in res.json()

def test_kill_switch_api(client):
    res = client.get("/api/v1/guardian/safety/kill_switch")
    assert res.status_code == 200
    assert "kill_switches" in res.json()

# ── Safety Tests ──────────────────────────────────────────────────────

def test_kill_switch_global():
    ks = KillSwitch()
    assert not ks.is_blocked(KillSwitchScope.ACTION, "process")[0]
    ks.activate(KillSwitchScope.GLOBAL, "global", "test_admin", "Test")
    assert ks.is_blocked(KillSwitchScope.ACTION, "process")[0]

def test_circuit_breaker():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=60)
    assert cb.allow_action()
    cb.record_failure()
    cb.record_failure()
    assert cb.allow_action()
    cb.record_failure()
    assert not cb.allow_action()  # Tripped

def test_rate_limiter():
    limiter = ActionRateLimiter(max_per_minute=2)
    assert limiter.check_and_record("test_action")[0]
    assert limiter.check_and_record("test_action")[0]
    assert not limiter.check_and_record("test_action")[0]  # Exceeded

# ── Automation Policy Tests ──────────────────────────────────────────

def test_policy_engine_approval_required_default():
    engine = PolicyEngine()
    decision, reason = engine.evaluate(
        DEFAULT_POLICY,
        action_type="process",
        action_name="terminate_process",
        risk_score=50.0,
        incident_severity="high",
    )
    assert decision == PolicyDecision.REQUIRE_APPROVAL

def test_policy_engine_match_rule():
    policy = AutomationPolicy(
        policy_id="test-1", name="Test", description="Test",
        rules=[
            AutomationRule(
                rule_id="r1", description="Allow process terminate",
                action_type="process", action_name="terminate_process",
                decision=PolicyDecision.ALLOW,
                requires_approval=True  # Safety check
            )
        ]
    )
    engine = PolicyEngine()
    decision, _ = engine.evaluate(
        policy,
        action_type="process",
        action_name="terminate_process",
        risk_score=90.0,
        incident_severity="high",
    )
    assert decision == PolicyDecision.REQUIRE_APPROVAL # Forced to REQUIRE_APPROVAL by requires_approval=True

def test_automation_runner_forces_approval():
    policy = AutomationPolicy(
        policy_id="test-1", name="Test", description="Test",
        mode=AutomationMode.APPROVAL_REQUIRED,
        rules=[
            AutomationRule(
                rule_id="r1", description="Allow",
                action_type="process", action_name="terminate_process",
                decision=PolicyDecision.ALLOW,
                requires_approval=False  # Try to bypass
            )
        ]
    )
    runner = AutomationRunner(policy)
    req = AutomationRunRequest(
        action_type="process", action_name="terminate_process",
        target={"pid": 123}, incident_id=1, decision_id="dec-1",
        risk_score=90.0, incident_severity="critical",
        requested_by="ai", rationale="Test"
    )
    run = runner.submit(req)
    assert run.requires_approval is True
    assert run.status == AutomationRunStatus.AWAITING_APPROVAL

# ── AI Boundary Tests ────────────────────────────────────────────────

def test_ai_boundary_blocks_subprocess():
    validator = AiBoundaryValidator()
    # Safe text
    assert validator.validate_suggestion("I suggest blocking IP 1.2.3.4")[0]
    # Unsafe code
    assert not validator.validate_suggestion("import subprocess; subprocess.call('rm -rf /', shell=True)")[0]

def test_ai_advisory():
    adv = AiAdvisory(
        summary="Threat detected",
        suggested_action={"action_type": "network", "action_name": "block_destination", "target": {"ip": "1.1.1.1"}}
    )
    assert adv.to_dict()["_boundary"] == "AI advisory only — requires operator approval before any action"
