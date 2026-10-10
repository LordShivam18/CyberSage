"""Phase 5 Slice 2 tests: safety-envelope executor.

Covers the 28-area Slice 2 matrix: safety-order, kill switch (memory +
persisted), breaker blocking/transitions, rate-limit blocking, cooldown,
target validation, policy authorization, stale policy/approval, approved
execution, independent verification, rollback (+failure), idempotency,
concurrency, audit completeness, dry-run non-mutation, RBAC, AI boundary,
replay, state transitions, Phase 1-4 + Slice 1 compatibility, migrations.

All action behavior is mocked/sandboxed: the registered
network:block_destination singleton is monkeypatched so no test touches
iptables, the network, or the runner host.
"""

import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect as sa_inspect
from sqlalchemy.orm import sessionmaker

from backend.auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_RESPONDER,
    get_current_user,
)
from backend.database import Base
from backend.main import app
from backend.migrations import runner as mig_runner

from guardian.actions.base import ExecutionResult, VerificationResult
from guardian.actions.registry import get_action
from guardian.ai_boundary import constrain_ai_advisory
from guardian.approval.manager import ApprovalManager
from guardian.automation import store as policy_store
from guardian.automation.envelope import (
    EnvelopeRequest,
    EnvelopeTransitionError,
    SafetyEnvelope,
    compute_execution_id,
    pre_execution_safety,
    transition_envelope_status,
)
from guardian.automation.policy_v5 import PolicyValidationError, simulate
from guardian.safety import kill_switch_store as kss
from guardian.safety.circuit_breaker import CircuitBreaker
from guardian.safety.kill_switch import KillSwitch, KillSwitchScope, get_default_kill_switch
from guardian.safety.rate_limiter import ActionRateLimiter
from guardian.safety.registry import (
    get_breaker,
    get_execution_limiter,
    reset_safety_state,
)


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture()
def test_engine(tmp_path):
    path = tmp_path / "phase5_slice2.db"
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def session_factory(test_engine):
    return sessionmaker(bind=test_engine, autocommit=False, autoflush=False)


@pytest.fixture()
def db_session(session_factory):
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def clean_safety_state():
    """Isolate process-global safety singletons between tests."""
    reset_safety_state()
    ks = get_default_kill_switch()
    for scope, key in (
        (KillSwitchScope.GLOBAL, "global"),
        (KillSwitchScope.AGENT, "agent-1"),
        (KillSwitchScope.ACTION, "network"),
        (KillSwitchScope.ACTION, "process"),
        (KillSwitchScope.ACTION, "persistence"),
    ):
        try:
            ks.deactivate(scope, key, by="test-cleanup")
        except Exception:  # noqa: BLE001
            pass
    yield
    reset_safety_state()
    for scope, key in (
        (KillSwitchScope.GLOBAL, "global"),
        (KillSwitchScope.AGENT, "agent-1"),
        (KillSwitchScope.ACTION, "network"),
        (KillSwitchScope.ACTION, "process"),
        (KillSwitchScope.ACTION, "persistence"),
    ):
        try:
            ks.deactivate(scope, key, by="test-cleanup")
        except Exception:  # noqa: BLE001
            pass


def _mock_user(username, role):
    class _User:
        pass

    user = _User()
    user.username = username
    user.role = role
    user.disabled = False
    return user


@pytest.fixture()
def api(test_engine):
    factory = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)

    def override_get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    from backend.database import get_db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: _mock_user("slice2-admin", ROLE_ADMIN)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture()
def mock_net_action(monkeypatch):
    """Sandbox the registered network action. Counts real invocations."""
    action = get_action("network", "block_destination")
    calls = {"execute": 0, "verify": 0, "rollback": 0}
    outcomes = {"execute_ok": True, "verify_ok": True, "rollback_ok": True}

    def fake_execute(target, parameters=None, snapshot=None):
        calls["execute"] += 1
        if outcomes["execute_ok"]:
            return ExecutionResult(success=True, output={"mocked": True})
        return ExecutionResult(success=False, error="mocked execution failure")

    def fake_verify(target, execution_result):
        calls["verify"] += 1
        if outcomes["verify_ok"]:
            return VerificationResult(passed=True, checks=[{"check": "mocked", "passed": True}])
        return VerificationResult(passed=False, checks=[{"check": "mocked", "passed": False}],
                                  failure_reason="mocked verification failure")

    def fake_rollback(target, snapshot):
        from guardian.actions.base import RollbackResult

        calls["rollback"] += 1
        if outcomes["rollback_ok"]:
            return RollbackResult(success=True, output={"mocked": True})
        return RollbackResult(success=False, error="mocked rollback failure")

    monkeypatch.setattr(action, "execute", fake_execute)
    monkeypatch.setattr(action, "verify", fake_verify)
    monkeypatch.setattr(action, "rollback", fake_rollback)
    return calls, outcomes


# ── Builders ──────────────────────────────────────────────────────────

TARGET = {"destination_ip": "203.0.113.66", "destination_port": 443}


def _rule(**over):
    base = {
        "rule_id": "r-exec",
        "description": "exec rule",
        "action_type": "network",
        "action_name": "block_destination",
        "min_risk_score": 60.0,
        "max_risk_score": 100.0,
        "incident_severity": "high",
        "decision": "allow",
        "requires_approval": True,
        "priority": 100,
        "target_scope": {"destination_ips": ["203.0.113.66"]},
        "approval_mode": "required",
    }
    base.update(over)
    return base


def _policy(policy_id="p-exec", **over):
    base = {
        "policy_id": policy_id,
        "name": "Exec policy",
        "description": "d",
        "mode": "approval_required",
        "priority": 100,
        "enabled": True,
        "rules": [_rule()],
    }
    base.update(over)
    return base


def make_approved(db, *, decision_id="dec-exec-1", target=None, incident_id=7,
                  approver="responder-1", requester="analyst-1",
                  action_type="network", requested_action="block_destination"):
    """Create + approve an approval. Returns (approval_id, decision_id)."""
    mgr = ApprovalManager()
    target = dict(target or TARGET)
    created = mgr.create_approval_request(
        db, incident_id=incident_id, decision_id=decision_id,
        requested_action=requested_action, action_type=action_type,
        target=target, rationale="slice2 test", requested_by=requester,
    )
    approval_id = created["approval_id"]
    mgr.approve_request(db, approval_id=approval_id, approver=approver)
    db.commit()
    return approval_id, decision_id


def make_evaluation(db, *, policy_id="p-exec", correlation_id="corr-exec-1",
                    incident_id=7, risk=75.0):
    """Run a simulation and persist its audit record. Returns evaluation_id."""
    from guardian.automation.policy_v5 import EvaluationRequest as _ER

    policies = policy_store.list_policies(db, include_disabled=False)
    request = _ER(action_type="network", action_name="block_destination",
                  target=dict(TARGET), risk_score=risk, incident_severity="high",
                  incident_id=incident_id, event_ids=["evt-1"],
                  requested_by="analyst-1", correlation_id=correlation_id)
    result = simulate(policies, request)
    evaluation_id, _ = policy_store.record_evaluation(db, request, result)
    db.commit()
    return evaluation_id


def make_request(db, *, policy_id="p-exec", version=1, decision_id="dec-exec-1",
                 approval_id, evaluation_id=None, incident_id=7, risk=75.0,
                 target=None, correlation_id="corr-run-1", agent_key=None):
    return EnvelopeRequest(
        policy_id=policy_id, expected_policy_version=version,
        action_type="network", action_name="block_destination",
        target=dict(target or TARGET), decision_id=decision_id,
        approval_id=approval_id, risk_score=risk, incident_severity="high",
        incident_id=incident_id, event_ids=["evt-1"], evaluation_id=evaluation_id,
        agent_key=agent_key, correlation_id=correlation_id, requested_by="analyst-1",
    )


def full_setup(db, *, policy_id="p-exec", decision_id="dec-exec-1", correlation_id="corr-exec-1"):
    """Policy + evaluation + approval. Returns (EnvelopeRequest, approval_id, evaluation_id)."""
    policy_store.create_policy(db, _policy(policy_id), created_by="admin-1")
    db.commit()
    evaluation_id = make_evaluation(db, policy_id=policy_id, correlation_id=correlation_id)
    approval_id, _ = make_approved(db, decision_id=decision_id)
    request = make_request(db, policy_id=policy_id, decision_id=decision_id,
                           approval_id=approval_id, evaluation_id=evaluation_id,
                           correlation_id=correlation_id)
    return request, approval_id, evaluation_id


# ══════════════════════════════════════════════════════════════════════
# 1. Safety-order enforcement + gate reporting
# ══════════════════════════════════════════════════════════════════════

def test_gate_order_is_mandated(db_session):
    from guardian.automation.envelope import GATE_ORDER

    assert GATE_ORDER == [
        "policy_active", "policy_version", "identity",
        "kill_switch_global", "kill_switch_scoped",
        "circuit_breaker", "rate_limit", "cooldown",
        "target_validation", "policy_authorization",
        "preauth_authorization", "approval",
    ]
    assert GATE_ORDER.index("kill_switch_global") < GATE_ORDER.index("circuit_breaker")
    assert GATE_ORDER.index("circuit_breaker") < GATE_ORDER.index("rate_limit")
    assert GATE_ORDER.index("rate_limit") < GATE_ORDER.index("target_validation")
    assert GATE_ORDER.index("target_validation") < GATE_ORDER.index("approval")
    # Slice 4: bounded-grant authorization is gated after policy
    # authorization and before approval; kill-switch precedence is unchanged.
    assert GATE_ORDER.index("policy_authorization") < GATE_ORDER.index("preauth_authorization")
    assert GATE_ORDER.index("preauth_authorization") < GATE_ORDER.index("approval")


def test_all_gates_reported_in_order_on_success(db_session, mock_net_action):
    request, _, _ = full_setup(db_session)
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "succeeded", result.error
    assert [g["gate"] for g in result.gates] == [
        "policy_active", "policy_version", "identity",
        "kill_switch_global", "kill_switch_scoped",
        "circuit_breaker", "rate_limit", "cooldown",
        "target_validation", "policy_authorization",
        "preauth_authorization", "approval",
    ]
    assert all(g["passed"] for g in result.gates)
    # Manual path records the bounded-grant gate as not applicable without
    # consuming any grant; approval still carries the authorization.
    preauth_gate = next(g for g in result.gates if g["gate"] == "preauth_authorization")
    assert preauth_gate["passed"] is True
    assert preauth_gate["reason"] == "manual_path_preauth_not_applicable"


# ══════════════════════════════════════════════════════════════════════
# 2-3. Kill switch (memory + persisted)
# ══════════════════════════════════════════════════════════════════════

def test_memory_global_kill_blocks(db_session, mock_net_action):
    calls, _ = mock_net_action
    request, _, _ = full_setup(db_session)
    get_default_kill_switch().activate(KillSwitchScope.GLOBAL, "global", by="t", reason="test")
    try:
        result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    finally:
        get_default_kill_switch().deactivate(KillSwitchScope.GLOBAL, "global", by="t")
    assert result.status == "blocked"
    assert any(g["gate"] == "kill_switch_global" and not g["passed"] for g in result.gates)
    assert calls["execute"] == 0


def test_persisted_global_kill_blocks_with_clean_memory(db_session, mock_net_action):
    from backend.models import GuardianKillSwitch

    calls, _ = mock_net_action
    request, _, _ = full_setup(db_session)
    db_session.add(GuardianKillSwitch(scope="global", switch_key="global", active=True,
                                      activated_by="t", reason="test"))
    db_session.commit()
    try:
        result = SafetyEnvelope().run(db_session, request, actor="responder-1")
        assert result.status == "blocked"
        assert calls["execute"] == 0
    finally:
        db_session.query(GuardianKillSwitch).delete()
        db_session.commit()


def test_memory_and_persisted_disagreement_still_blocks(db_session):
    # OR semantics: either source active blocks. Memory active + persisted row
    # inactive must block (and vice versa).
    from backend.models import GuardianKillSwitch

    request, _, _ = full_setup(db_session)
    get_default_kill_switch().activate(KillSwitchScope.GLOBAL, "global", by="t", reason="t")
    db_session.add(GuardianKillSwitch(scope="global", switch_key="global", active=False))
    db_session.commit()
    try:
        result = SafetyEnvelope().run(db_session, request, actor="responder-1")
        assert result.status == "blocked"
    finally:
        get_default_kill_switch().deactivate(KillSwitchScope.GLOBAL, "global", by="t")
        db_session.query(GuardianKillSwitch).delete()
        db_session.commit()


def test_action_scoped_kill_blocks_only_matching_action(db_session, mock_net_action):
    calls, _ = mock_net_action
    request, _, _ = full_setup(db_session)
    ks = get_default_kill_switch()
    ks.activate(KillSwitchScope.ACTION, "network", by="t", reason="test")
    try:
        blocked = SafetyEnvelope().run(db_session, request, actor="responder-1")
        assert blocked.status == "blocked"
        assert calls["execute"] == 0
    finally:
        ks.deactivate(KillSwitchScope.ACTION, "network", by="t")


def test_agent_scoped_kill_blocks_only_matching_agent(db_session, mock_net_action):
    calls, _ = mock_net_action
    request, _, _ = full_setup(db_session, decision_id="dec-agent")
    request.agent_key = "agent-1"
    ks = get_default_kill_switch()
    ks.activate(KillSwitchScope.AGENT, "agent-1", by="t", reason="test")
    try:
        blocked = SafetyEnvelope().run(db_session, request, actor="responder-1")
        assert blocked.status == "blocked"
        assert calls["execute"] == 0
    finally:
        ks.deactivate(KillSwitchScope.AGENT, "agent-1", by="t")
    # Different agent passes the scoped gate.
    request.agent_key = "agent-2"
    request.correlation_id = "corr-agent-2"
    ok_result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert ok_result.status == "succeeded", ok_result.error


def test_kill_switch_write_through_and_restart(db_session):
    ks = get_default_kill_switch()
    kss.activate_persisted(db_session, ks, "global", "global", by="admin-1", reason="stop")
    db_session.commit()
    assert ks.is_blocked(KillSwitchScope.GLOBAL, "global")[0] is True
    # Fresh singleton (simulated restart) reloads the persisted stop.
    fresh = KillSwitch()
    assert fresh.is_blocked(KillSwitchScope.GLOBAL, "global")[0] is False
    assert kss.sync_to_memory(fresh, db_session) >= 1
    assert fresh.is_blocked(KillSwitchScope.GLOBAL, "global")[0] is True
    # Combined check sees it too.
    blocked, _ = kss.is_blocked_combined(db_session, KillSwitch(), KillSwitchScope.GLOBAL, "global")
    assert blocked is True
    kss.deactivate_persisted(db_session, ks, "global", "global", by="admin-1")
    db_session.commit()
    assert ks.is_blocked(KillSwitchScope.GLOBAL, "global")[0] is False
    assert kss.is_persisted_active(db_session, "global", "global") is False


def test_kill_switch_invalid_scope_rejected(db_session):
    with pytest.raises(ValueError):
        kss.activate_persisted(db_session, get_default_kill_switch(),
                               "nonsense", "global", by="a", reason="r")


# ══════════════════════════════════════════════════════════════════════
# 4-5. Circuit breaker blocking + transitions
# ══════════════════════════════════════════════════════════════════════

def test_breaker_open_blocks_execution(db_session, mock_net_action):
    calls, outcomes = mock_net_action
    outcomes["execute_ok"] = False  # fail twice to trip the default-threshold... use custom
    env = SafetyEnvelope(breaker_fn=lambda at: get_breaker(at, failure_threshold=2,
                                                            recovery_timeout_seconds=600))
    r1, _, _ = full_setup(db_session, decision_id="dec-b1", correlation_id="c-b1")
    assert env.run(db_session, r1, actor="responder-1").status == "execution_failed"
    db_session.expire_all()
    r2, _, _ = full_setup(db_session, decision_id="dec-b2", correlation_id="c-b2")
    # New approval/decision => new execution identity => second attempt trips breaker.
    assert env.run(db_session, r2, actor="responder-1").status == "execution_failed"
    assert get_breaker("network").is_open() is True
    r3, _, _ = full_setup(db_session, decision_id="dec-b3", correlation_id="c-b3")
    blocked = env.run(db_session, r3, actor="responder-1")
    assert blocked.status == "blocked"
    assert any(g["gate"] == "circuit_breaker" and not g["passed"] for g in blocked.gates)
    assert calls["execute"] == 2  # third never reached the action


def test_breaker_half_open_probe_and_recovery():
    tripped = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=600,
                             action_type="probe-tripped")
    assert tripped.allow_action() is True
    tripped.record_failure("x")
    assert tripped.is_open() is True
    assert tripped.allow_action() is False  # blocked while OPEN

    maturing = CircuitBreaker(failure_threshold=1, recovery_timeout_seconds=0,
                              action_type="probe-maturing")
    maturing.record_failure("x")
    # Zero timeout matures OPEN -> HALF_OPEN on next read: one probe allowed.
    assert maturing.allow_action() is True
    maturing.record_success("probe")
    assert maturing.is_open() is False
    assert maturing.allow_action() is True


def test_verified_success_closes_breaker(db_session, mock_net_action):
    env = SafetyEnvelope(breaker_fn=lambda at: get_breaker(at, failure_threshold=5,
                                                            recovery_timeout_seconds=600))
    breaker = get_breaker("network")
    breaker.record_failure("x")
    assert breaker.get_stats()["consecutive_failures"] == 1
    request, _, _ = full_setup(db_session)
    assert env.run(db_session, request, actor="responder-1").status == "succeeded"
    assert breaker.get_stats()["consecutive_failures"] == 0


# ══════════════════════════════════════════════════════════════════════
# 6-7. Rate limiting + cooldown
# ══════════════════════════════════════════════════════════════════════

def test_rate_limit_blocks_execution(db_session, mock_net_action):
    calls, _ = mock_net_action
    limiter = ActionRateLimiter(max_per_minute=1, max_per_hour=10)
    env = SafetyEnvelope(limiter=limiter)
    r1, _, _ = full_setup(db_session, decision_id="dec-r1", correlation_id="c-r1")
    assert env.run(db_session, r1, actor="responder-1").status == "succeeded"
    r2, _, _ = full_setup(db_session, decision_id="dec-r2", correlation_id="c-r2")
    blocked = env.run(db_session, r2, actor="responder-1")
    assert blocked.status == "blocked"
    assert any(g["gate"] == "rate_limit" and not g["passed"] for g in blocked.gates)
    assert calls["execute"] == 1


def test_cooldown_blocks_repeat_target(db_session, mock_net_action):
    calls, _ = mock_net_action
    payload = _policy("p-cool", rules=[_rule(rule_id="r-cool", cooldown_seconds=3600)])
    policy_store.create_policy(db_session, payload, created_by="admin-1")
    db_session.commit()
    evaluation_id = make_evaluation(db_session, policy_id="p-cool", correlation_id="c-cool-1")
    approval_id, _ = make_approved(db_session, decision_id="dec-cool-1")
    req1 = make_request(db_session, policy_id="p-cool", decision_id="dec-cool-1",
                        approval_id=approval_id, evaluation_id=evaluation_id,
                        correlation_id="c-cool-run-1")
    assert SafetyEnvelope().run(db_session, req1, actor="responder-1").status == "succeeded"
    approval_id2, _ = make_approved(db_session, decision_id="dec-cool-2")
    evaluation_id2 = make_evaluation(db_session, policy_id="p-cool", correlation_id="c-cool-2")
    req2 = make_request(db_session, policy_id="p-cool", decision_id="dec-cool-2",
                        approval_id=approval_id2, evaluation_id=evaluation_id2,
                        correlation_id="c-cool-run-2")
    blocked = SafetyEnvelope().run(db_session, req2, actor="responder-1")
    assert blocked.status == "blocked"
    assert any(g["gate"] == "cooldown" and not g["passed"] for g in blocked.gates)
    assert calls["execute"] == 1


def test_max_frequency_cap(db_session, mock_net_action):
    payload = _policy("p-freq", rules=[_rule(rule_id="r-freq", max_executions_per_hour=1)])
    policy_store.create_policy(db_session, payload, created_by="admin-1")
    db_session.commit()
    evaluation_id = make_evaluation(db_session, policy_id="p-freq", correlation_id="c-f1")
    approval_id, _ = make_approved(db_session, decision_id="dec-f1")
    req1 = make_request(db_session, policy_id="p-freq", decision_id="dec-f1",
                        approval_id=approval_id, evaluation_id=evaluation_id,
                        correlation_id="c-f-run-1")
    assert SafetyEnvelope().run(db_session, req1, actor="responder-1").status == "succeeded"
    approval_id2, _ = make_approved(db_session, decision_id="dec-f2")
    evaluation_id2 = make_evaluation(db_session, policy_id="p-freq", correlation_id="c-f2")
    req2 = make_request(db_session, policy_id="p-freq", decision_id="dec-f2",
                        approval_id=approval_id2, evaluation_id=evaluation_id2,
                        correlation_id="c-f-run-2")
    blocked = SafetyEnvelope().run(db_session, req2, actor="responder-1")
    assert blocked.status == "blocked"
    assert any(g["gate"] == "cooldown" and not g["passed"] for g in blocked.gates)


def test_rate_limiter_concurrent_no_overconsume():
    limiter = ActionRateLimiter(max_per_minute=3, max_per_hour=100)
    results = []
    lock = threading.Lock()

    def worker():
        ok, _ = limiter.check_and_record("network")
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for r in results if r) == 3
    assert len(results) == 10


# ══════════════════════════════════════════════════════════════════════
# 8. Target validation
# ══════════════════════════════════════════════════════════════════════

def test_protected_target_blocked(db_session, mock_net_action):
    calls, _ = mock_net_action

    payload = {
        "policy_id": "p-proc",
        "name": "proc",
        "description": "d",
        "mode": "approval_required",
        "priority": 100,
        "enabled": True,
        "rules": [{
            "rule_id": "r-proc", "description": "d", "action_type": "process",
            "action_name": "terminate_process", "min_risk_score": 0.0,
            "max_risk_score": 100.0, "decision": "allow", "requires_approval": True,
        }],
    }
    policy_store.create_policy(db_session, payload, created_by="admin-1")
    db_session.commit()
    bad_target = {"pid": 1, "process_name": "init"}  # protected PID
    approval_id, _ = make_approved(db_session, decision_id="dec-proc", target=bad_target)
    request = EnvelopeRequest(
        policy_id="p-proc", expected_policy_version=1, action_type="process",
        action_name="terminate_process", target=bad_target, decision_id="dec-proc",
        approval_id=approval_id, risk_score=90.0, incident_severity="critical",
        incident_id=7, requested_by="analyst-1",
    )
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert any(g["gate"] == "target_validation" and not g["passed"] for g in result.gates)
    assert calls["execute"] == 0


def test_shell_injection_target_blocked(db_session, mock_net_action):
    calls, _ = mock_net_action
    request, _, _ = full_setup(db_session, decision_id="dec-inj")
    request.target = {"destination_ip": "1.2.3.4; rm -rf /", "destination_port": 443}
    # Tampered target fails the evaluation-identity binding (fail closed).
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert calls["execute"] == 0


def test_unregistered_action_rejected_at_validation(db_session):
    request, _, _ = full_setup(db_session)
    request.action_name = "pwn_everything"
    with pytest.raises(PolicyValidationError):
        SafetyEnvelope().run(db_session, request, actor="responder-1")


def test_wildcard_action_forbidden_for_execution(db_session):
    request, _, _ = full_setup(db_session)
    request.action_name = "*"
    with pytest.raises(PolicyValidationError):
        SafetyEnvelope().run(db_session, request, actor="responder-1")


# ══════════════════════════════════════════════════════════════════════
# 9-11. Policy authorization, stale policy, stale approval
# ══════════════════════════════════════════════════════════════════════

def test_deny_rule_overrides_valid_approval(db_session, mock_net_action):
    calls, _ = mock_net_action
    payload = _policy("p-deny", rules=[_rule(rule_id="r-deny", decision="deny", requires_approval=False)])
    policy_store.create_policy(db_session, payload, created_by="admin-1")
    db_session.commit()
    approval_id, _ = make_approved(db_session, decision_id="dec-deny")
    request = make_request(db_session, policy_id="p-deny", decision_id="dec-deny",
                           approval_id=approval_id, correlation_id="c-deny")
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert any(g["gate"] == "policy_authorization" and not g["passed"] for g in result.gates)
    assert calls["execute"] == 0


def test_stale_policy_version_blocked(db_session, mock_net_action):
    calls, _ = mock_net_action
    request, _, evaluation_id = full_setup(db_session, policy_id="p-stale")
    policy_store.update_policy(db_session, "p-stale", {"description": "v2"}, updated_by="admin-1")
    db_session.commit()
    stale = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert stale.status == "blocked"
    assert any(g["gate"] == "policy_version" and not g["passed"] for g in stale.gates)
    assert calls["execute"] == 0
    # Fresh version proceeds (new approval/decision => new execution identity).
    approval_id2, _ = make_approved(db_session, decision_id="dec-stale-2")
    evaluation_id2 = make_evaluation(db_session, policy_id="p-stale", correlation_id="c-stale-2")
    req2 = make_request(db_session, policy_id="p-stale", version=2, decision_id="dec-stale-2",
                        approval_id=approval_id2, evaluation_id=evaluation_id2,
                        correlation_id="c-stale-run-2")
    assert SafetyEnvelope().run(db_session, req2, actor="responder-1").status == "succeeded"


def test_disabled_policy_blocked(db_session, mock_net_action):
    request, _, _ = full_setup(db_session, policy_id="p-dis2")
    policy_store.set_policy_enabled(db_session, "p-dis2", False, updated_by="admin-1")
    db_session.commit()
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert any(g["gate"] == "policy_active" and not g["passed"] for g in result.gates)


def test_missing_policy_blocked(db_session):
    approval_id, _ = make_approved(db_session, decision_id="dec-miss")
    request = make_request(db_session, policy_id="p-ghost", decision_id="dec-miss",
                           approval_id=approval_id)
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert any(g["gate"] == "policy_active" and not g["passed"] for g in result.gates)


def test_decision_mismatch_blocked(db_session, mock_net_action):
    calls, _ = mock_net_action
    policy_store.create_policy(db_session, _policy("p-exec"), created_by="admin-1")
    db_session.commit()
    approval_id, _ = make_approved(db_session, decision_id="dec-A")
    request = make_request(db_session, decision_id="dec-B", approval_id=approval_id)
    # New decision => new approval expected; reusing approval fails binding.
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert calls["execute"] == 0


def test_rejected_approval_blocked(db_session, mock_net_action):
    mgr = ApprovalManager()
    created = mgr.create_approval_request(
        db_session, incident_id=7, decision_id="dec-rej",
        requested_action="block_destination", action_type="network",
        target=dict(TARGET), rationale="t", requested_by="analyst-1",
    )
    mgr.reject_request(db_session, approval_id=created["approval_id"], approver="responder-1")
    db_session.commit()
    policy_store.create_policy(db_session, _policy("p-rej"), created_by="admin-1")
    db_session.commit()
    request = make_request(db_session, policy_id="p-rej", decision_id="dec-rej",
                           approval_id=created["approval_id"], correlation_id="c-rej")
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert any(g["gate"] == "approval" and not g["passed"] for g in result.gates)


def test_expired_approval_blocked(db_session, mock_net_action):
    mgr = ApprovalManager()
    created = mgr.create_approval_request(
        db_session, incident_id=7, decision_id="dec-exp",
        requested_action="block_destination", action_type="network",
        target=dict(TARGET), rationale="t", requested_by="analyst-1", ttl_minutes=30,
    )
    mgr.approve_request(db_session, approval_id=created["approval_id"], approver="responder-1")
    from backend.models import GuardianApprovalRequest

    row = db_session.query(GuardianApprovalRequest).filter_by(
        approval_id=created["approval_id"]).one()
    from datetime import datetime, timedelta, timezone
    row.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
    db_session.commit()
    policy_store.create_policy(db_session, _policy("p-exp"), created_by="admin-1")
    db_session.commit()
    request = make_request(db_session, policy_id="p-exp", decision_id="dec-exp",
                           approval_id=created["approval_id"], correlation_id="c-exp")
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert any(g["gate"] == "approval" and not g["passed"] for g in result.gates)


def test_pre_authorized_rule_still_requires_approval(db_session, mock_net_action):
    payload = _policy("p-pre", rules=[_rule(rule_id="r-pre", decision="allow", requires_approval=False,
                                            approval_mode="pre_authorized")])
    policy_store.create_policy(db_session, payload, created_by="admin-1")
    db_session.commit()
    approval_id, _ = make_approved(db_session, decision_id="dec-pre")
    request = make_request(db_session, policy_id="p-pre", decision_id="dec-pre",
                           approval_id=approval_id, correlation_id="c-pre")
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    # Manual path executes only with approval; the gate must note the deferral.
    # Slice 4 intentionally changed this wording; the approval requirement itself
    # is preserved below, and the bounded-grant path is gated separately.
    assert result.status == "succeeded", result.error
    auth_gate = next(g for g in result.gates if g["gate"] == "policy_authorization")
    assert "Slice 4" in (auth_gate.get("detail") or "")
    # A manual request must not be confused with a bounded grant: without an
    # active grant the preauth gate passes as not-applicable and approval decides.
    preauth_gate = next(g for g in result.gates if g["gate"] == "preauth_authorization")
    assert preauth_gate["passed"] is True
    assert preauth_gate["reason"] == "manual_path_preauth_not_applicable"
    # And without any approval the request is invalid (approval_id required).
    bad = make_request(db_session, policy_id="p-pre", decision_id="dec-pre",
                       approval_id="", correlation_id="c-pre-2")
    with pytest.raises(PolicyValidationError):
        SafetyEnvelope().run(db_session, bad, actor="responder-1")


# ══════════════════════════════════════════════════════════════════════
# 12-15. Execution, verification, rollback, audit
# ══════════════════════════════════════════════════════════════════════

def test_approved_execution_succeeds_with_mock(db_session, mock_net_action):
    calls, _ = mock_net_action
    request, _, _ = full_setup(db_session)
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "succeeded"
    assert result.existing is False
    assert calls["execute"] == 1
    assert calls["verify"] == 1
    assert result.verification is not None


def test_execution_failure_recorded_and_breaker_updated(db_session, mock_net_action):
    calls, outcomes = mock_net_action
    outcomes["execute_ok"] = False
    request, _, _ = full_setup(db_session)
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "execution_failed"
    assert result.error == "mocked execution failure"
    assert get_breaker("network").get_stats()["consecutive_failures"] == 1


def test_verification_failure_offers_rollback(db_session, mock_net_action):
    calls, outcomes = mock_net_action
    outcomes["verify_ok"] = False
    request, _, _ = full_setup(db_session)
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    # network:block_destination supports rollback + snapshot exists.
    assert result.status == "rollback_available", result.error
    assert result.rollback is not None
    assert result.rollback["status"] == "available"
    from backend.models import GuardianActionAttempt, GuardianActionRollback

    attempt = db_session.query(GuardianActionAttempt).filter_by(
        action_id=result.action_id).one()
    assert attempt.snapshot_id is not None
    rb = db_session.query(GuardianActionRollback).filter_by(
        rollback_id=result.rollback["rollback_id"]).one()
    assert rb.status == "available"


def test_rollback_failure_terminal(db_session, mock_net_action):
    calls, outcomes = mock_net_action
    outcomes["verify_ok"] = False
    outcomes["rollback_ok"] = False
    request, _, _ = full_setup(db_session)
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "rollback_available"
    # Explicit rollback via the existing Phase 3 endpoint fails terminally.
    client = _authed_client(db_session, "admin-rb", ROLE_ADMIN)
    try:
        rb = client.post(f"/api/v1/guardian/actions/{result.action_id}/rollback", json={})
        assert rb.status_code == 200, rb.text
        assert rb.json()["status"] == "rollback_failed"
    finally:
        client.close()


def test_no_rollback_invented_for_process_termination(db_session, monkeypatch):
    from guardian.actions.base import ExecutionResult as _ER
    from guardian.actions.base import VerificationResult as _VR

    action = get_action("process", "terminate_process")
    monkeypatch.setattr(action, "execute",
                        lambda t, p=None, s=None: _ER(success=True, output={"mocked": True}))
    monkeypatch.setattr(action, "verify",
                        lambda t, e: _VR(passed=False, failure_reason="mocked still running"))
    payload = {
        "policy_id": "p-term", "name": "t", "description": "d", "mode": "approval_required",
        "priority": 100, "enabled": True,
        "rules": [{"rule_id": "r-term", "description": "d", "action_type": "process",
                   "action_name": "terminate_process", "min_risk_score": 0.0,
                   "max_risk_score": 100.0, "decision": "allow", "requires_approval": True}],
    }
    policy_store.create_policy(db_session, payload, created_by="admin-1")
    db_session.commit()
    target = {"pid": 4242, "process_name": "evil.exe"}
    approval_id, _ = make_approved(db_session, decision_id="dec-term", target=target,
                                   action_type="process",
                                   requested_action="terminate_process")
    request = EnvelopeRequest(
        policy_id="p-term", expected_policy_version=1, action_type="process",
        action_name="terminate_process", target=target, decision_id="dec-term",
        approval_id=approval_id, risk_score=90.0, incident_severity="critical",
        incident_id=7, requested_by="analyst-1",
    )
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "verification_failed", result.error
    assert result.rollback is None  # terminate_process: rollback_supported == False


def test_audit_row_complete(db_session, mock_net_action):
    from backend.models import GuardianActionAudit, GuardianEnvelopeRun

    request, approval_id, evaluation_id = full_setup(
        db_session, decision_id="dec-audit", correlation_id="corr-audit")
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "succeeded"
    row = db_session.query(GuardianEnvelopeRun).filter_by(
        execution_id=result.execution_id).one()
    assert row.policy_id == "p-exec" and row.policy_version == 1
    assert row.rule_id == "r-exec" and row.evaluation_id == evaluation_id
    assert row.approval_id == approval_id and row.actor == "responder-1"
    assert row.action_type == "network" and row.target["destination_ip"] == "203.0.113.66"
    assert len(row.gate_results) == 12
    assert row.execution_result is not None and row.verification is not None
    assert row.incident_id == 7 and row.event_ids == ["evt-1"]
    assert row.correlation_id == "corr-audit" and row.created_at is not None
    assert row.error is None
    audit = db_session.query(GuardianActionAudit).filter_by(action_id=row.action_id).one()
    assert audit.actor == "responder-1" and audit.verification_passed is True


# ══════════════════════════════════════════════════════════════════════
# 15-17. State machine, idempotency, concurrency, replay
# ══════════════════════════════════════════════════════════════════════

def test_envelope_transitions_valid_and_invalid():
    assert transition_envelope_status("safety_check", "executing") == "executing"
    assert transition_envelope_status("executing", "verifying") == "verifying"
    assert transition_envelope_status("verifying", "succeeded") == "succeeded"
    assert transition_envelope_status("verification_failed", "rollback_available") == "rollback_available"
    for bad in [("succeeded", "executing"), ("safety_check", "succeeded"),
                ("blocked", "executing"), ("executing", "succeeded"),
                ("rollback_available", "succeeded"), ("safety_check", "verifying")]:
        with pytest.raises(EnvelopeTransitionError):
            transition_envelope_status(*bad)


def test_execution_id_deterministic():
    approval_id = "apr-x"
    r1 = EnvelopeRequest(policy_id="p", expected_policy_version=1, action_type="network",
                         action_name="block_destination", target=dict(TARGET),
                         decision_id="d", approval_id=approval_id)
    r2 = EnvelopeRequest(policy_id="p", expected_policy_version=1, action_type="network",
                         action_name="block_destination", target=dict(TARGET),
                         decision_id="d", approval_id=approval_id)
    assert compute_execution_id(r1) == compute_execution_id(r2)
    r3 = EnvelopeRequest(policy_id="p", expected_policy_version=1, action_type="network",
                         action_name="block_destination", target=dict(TARGET),
                         decision_id="d", approval_id="apr-other")
    assert compute_execution_id(r1) != compute_execution_id(r3)


def test_replay_returns_original_without_reexecution(db_session, mock_net_action):
    calls, _ = mock_net_action
    request, _, _ = full_setup(db_session)
    first = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert first.status == "succeeded" and first.existing is False
    second = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert second.status == "succeeded" and second.existing is True
    assert second.execution_id == first.execution_id
    assert calls["execute"] == 1
    from backend.models import GuardianEnvelopeRun
    assert db_session.query(GuardianEnvelopeRun).filter_by(
        execution_id=first.execution_id).count() == 1


def test_concurrent_submissions_single_execution(session_factory, mock_net_action):
    import time as _time

    from backend.models import GuardianEnvelopeRun

    setup_session = session_factory()
    try:
        request, _, _ = full_setup(setup_session, decision_id="dec-conc",
                                   correlation_id="corr-conc")
    finally:
        setup_session.close()
    calls, _ = mock_net_action
    barrier = threading.Barrier(8)
    outcomes, lock = [], threading.Lock()

    def worker():
        session = session_factory()
        try:
            barrier.wait(timeout=30)
            # Stagger slightly to widen the race window.
            _time.sleep(0.01)
            result = SafetyEnvelope().run(session, request, actor="responder-1")
            with lock:
                outcomes.append((result.execution_id, result.status, result.existing))
        finally:
            session.close()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert len(outcomes) == 8
    assert len({o[0] for o in outcomes}) == 1
    assert all(o[1] == "succeeded" for o in outcomes)
    assert sum(1 for o in outcomes if o[2]) == 7  # one winner, seven replays
    check = session_factory()
    try:
        assert check.query(GuardianEnvelopeRun).filter_by(
            execution_id=outcomes[0][0]).count() == 1
    finally:
        check.close()
    assert calls["execute"] == 1


# ══════════════════════════════════════════════════════════════════════
# 18. Dry-run guarantee
# ══════════════════════════════════════════════════════════════════════

def test_simulation_mutates_nothing(db_session, mock_net_action):
    calls, _ = mock_net_action
    from backend.models import (GuardianActionAttempt, GuardianActionAudit,
                                GuardianApprovalRequest, GuardianEnvelopeRun,
                                GuardianPolicyEvaluation)

    policy_store.create_policy(db_session, _policy("p-dry"), created_by="admin-1")
    db_session.commit()
    before = {
        "attempts": db_session.query(GuardianActionAttempt).count(),
        "approvals": db_session.query(GuardianApprovalRequest).count(),
        "audit": db_session.query(GuardianActionAudit).count(),
        "envelope": db_session.query(GuardianEnvelopeRun).count(),
        "limiter": dict(get_execution_limiter().get_stats()),
        "breakers": dict(get_breaker("network").get_stats()),
    }
    from guardian.automation.policy_v5 import EvaluationRequest as _ER

    policies = policy_store.list_policies(db_session, include_disabled=False)
    for i in range(3):
        req = _ER(action_type="network", action_name="block_destination",
                  target=dict(TARGET), risk_score=75.0, incident_severity="high",
                  incident_id=7, requested_by="analyst-1", correlation_id=f"c-dry-{i}")
        result = simulate(policies, req)
        assert result.would_execute is False
        policy_store.record_evaluation(db_session, req, result)
    db_session.commit()
    db_session.expire_all()
    assert db_session.query(GuardianActionAttempt).count() == before["attempts"]
    assert db_session.query(GuardianApprovalRequest).count() == before["approvals"]
    assert db_session.query(GuardianActionAudit).count() == before["audit"]
    assert db_session.query(GuardianEnvelopeRun).count() == before["envelope"]
    assert db_session.query(GuardianPolicyEvaluation).count() == 3  # only the audit artifact
    assert get_execution_limiter().get_stats() == before["limiter"]
    assert get_breaker("network").get_stats() == before["breakers"]
    assert calls["execute"] == 0


# ══════════════════════════════════════════════════════════════════════
# 19. AI boundary (executor has no AI dependency)
# ══════════════════════════════════════════════════════════════════════

def test_executor_source_has_no_ai_dependency():
    from pathlib import Path

    for name in ("guardian/automation/envelope.py", "backend/api_guardian_phase5.py",
                 "guardian/safety/kill_switch_store.py"):
        text = Path(name).read_text(encoding="utf-8").lower()
        assert "ai_boundary" not in text and "aiadvisory" not in text, name
        assert "advisory" not in text, name


def test_ai_advisory_cannot_authorize_execution(api):
    advisory = constrain_ai_advisory({
        "summary": "Block this host now",
        "suggested_action": {"action_type": "network", "action_name": "block_destination",
                             "target": dict(TARGET)},
        "confidence": 0.99,
    })
    # An advisory is not an execution request: missing approval/policy/version.
    res = api.post("/api/v1/guardian/automation/v5/executions", json={
        "policy_id": "p-exec", "expected_policy_version": 1,
        "action_type": advisory["suggested_action"]["action_type"],
        "action_name": advisory["suggested_action"]["action_name"],
        "target": advisory["suggested_action"]["target"],
        "decision_id": "dec-ai", "approval_id": "apr-fake",
        "risk_score": 90.0, "incident_severity": "critical",
    })
    assert res.status_code in (403, 404, 422)  # never an execution


def test_forged_evaluation_id_blocked(db_session):
    request, _, _ = full_setup(db_session, decision_id="dec-forge")
    request.evaluation_id = "evl-forged"
    result = SafetyEnvelope().run(db_session, request, actor="responder-1")
    assert result.status == "blocked"
    assert any(g["gate"] == "identity" and not g["passed"] for g in result.gates)


def test_kill_switch_extra_field_ignored(api, db_session):
    policy_store.create_policy(db_session, _policy("p-xfield"), created_by="admin-1")
    db_session.commit()
    res = api.post("/api/v1/guardian/automation/v5/executions", json={
        "policy_id": "p-xfield", "expected_policy_version": 1,
        "action_type": "network", "action_name": "block_destination",
        "target": dict(TARGET), "decision_id": "d", "approval_id": "a",
        "risk_score": 75.0, "incident_severity": "high",
        "kill_switch": "disable",  # hostile extra field: must be ignored
    })
    # Fails on approval/policy grounds, never touches the kill switch.
    assert res.status_code in (422, 404)
    assert get_default_kill_switch().is_blocked(
        KillSwitchScope.GLOBAL, "global")[0] is False


# ══════════════════════════════════════════════════════════════════════
# 20. API + RBAC
# ══════════════════════════════════════════════════════════════════════

def _authed_client(db_session, username, role):
    """TestClient bound to the SAME database as db_session (shared engine)."""
    engine = db_session.bind
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def override_get_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    from backend.database import get_db

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: _mock_user(username, role)
    return TestClient(app)


def _api_full_flow(client, *, policy_id="p-api", decision_id="dec-api", corr="corr-api"):
    p = client.post("/api/v1/guardian/automation/v5/policies", json=_policy(policy_id))
    assert p.status_code == 200, p.text
    a = client.post("/api/v1/guardian/approvals", json={
        "decision_id": decision_id, "requested_action": "block_destination",
        "action_type": "network", "target": dict(TARGET), "rationale": "t"})
    assert a.status_code == 200, a.text
    approval_id = a.json()["approval_id"]
    ap = client.post(f"/api/v1/guardian/approvals/{approval_id}/approve", json={})
    assert ap.status_code == 200, ap.text
    s = client.post("/api/v1/guardian/automation/v5/simulate", json={
        "action_type": "network", "action_name": "block_destination",
        "target": dict(TARGET), "risk_score": 75.0, "incident_severity": "high",
        "incident_id": 7, "event_ids": ["evt-1"], "correlation_id": corr})
    assert s.status_code == 200, s.text
    return approval_id, s.json()["evaluation_id"]


def test_api_execution_success_and_replay(api, db_session, mock_net_action, monkeypatch):
    calls, _ = mock_net_action
    approval_id, evaluation_id = _api_full_flow(api)
    body = {"policy_id": "p-api", "expected_policy_version": 1,
            "action_type": "network", "action_name": "block_destination",
            "target": dict(TARGET), "decision_id": "dec-api",
            "approval_id": approval_id, "risk_score": 75.0,
            "incident_severity": "high", "incident_id": 7,
            "event_ids": ["evt-1"], "evaluation_id": evaluation_id,
            "correlation_id": "corr-api-run"}
    r1 = api.post("/api/v1/guardian/automation/v5/executions", json=body)
    assert r1.status_code == 200, r1.text
    assert r1.json()["status"] == "succeeded"
    assert r1.json()["existing"] is False
    execution_id = r1.json()["execution_id"]
    r2 = api.post("/api/v1/guardian/automation/v5/executions", json=body)
    assert r2.json()["existing"] is True
    assert r2.json()["execution_id"] == execution_id
    assert calls["execute"] == 1
    detail = api.get(f"/api/v1/guardian/automation/v5/executions/{execution_id}")
    assert detail.status_code == 200
    assert detail.json()["actor"] == "slice2-admin"
    listing = api.get("/api/v1/guardian/automation/v5/executions", params={"policy_id": "p-api"})
    assert listing.json()["total"] >= 1


def test_api_kill_switch_blocks_with_503(api, db_session, mock_net_action):
    approval_id, evaluation_id = _api_full_flow(
        api, policy_id="p-kill", decision_id="dec-kill", corr="corr-kill")
    ks = api.post("/api/v1/guardian/automation/v5/safety/kill-switch", json={
        "scope": "global", "switch_key": "global", "reason": "slice2 test"})
    assert ks.status_code == 200, ks.text
    try:
        res = api.post("/api/v1/guardian/automation/v5/executions", json={
            "policy_id": "p-kill", "expected_policy_version": 1,
            "action_type": "network", "action_name": "block_destination",
            "target": dict(TARGET), "decision_id": "dec-kill",
            "approval_id": approval_id, "risk_score": 75.0,
            "incident_severity": "high", "incident_id": 7,
            "event_ids": ["evt-1"], "evaluation_id": evaluation_id})
        assert res.status_code == 503, res.text
    finally:
        off = api.delete("/api/v1/guardian/automation/v5/safety/kill-switch",
                         params={"scope": "global", "switch_key": "global"})
        assert off.status_code == 200, off.text


def test_api_analyst_cannot_execute(db_session):
    client = _authed_client(db_session, "analyst-x", ROLE_ANALYST)
    res = client.post("/api/v1/guardian/automation/v5/executions", json={
        "policy_id": "p", "expected_policy_version": 1, "action_type": "network",
        "action_name": "block_destination", "target": dict(TARGET),
        "decision_id": "d", "approval_id": "a", "risk_score": 1.0,
        "incident_severity": "low"})
    assert res.status_code == 403
    client.close()


def test_api_auditor_cannot_execute_but_can_read(db_session):
    policy_store.create_policy(db_session, _policy("p-aud"), created_by="admin-1")
    db_session.commit()
    client = _authed_client(db_session, "auditor-x", ROLE_AUDITOR)
    try:
        assert client.post("/api/v1/guardian/automation/v5/executions", json={
            "policy_id": "p-aud", "expected_policy_version": 1, "action_type": "network",
            "action_name": "block_destination", "target": dict(TARGET),
            "decision_id": "d", "approval_id": "a", "risk_score": 1.0,
            "incident_severity": "low"}).status_code == 403
        assert client.get("/api/v1/guardian/automation/v5/executions").status_code == 200
        assert client.get("/api/v1/guardian/automation/v5/safety/status").status_code == 200
    finally:
        client.close()


def test_api_responder_can_execute(db_session, mock_net_action):
    admin = _authed_client(db_session, "admin-r", ROLE_ADMIN)
    try:
        approval_id, evaluation_id = _api_full_flow(
            admin, policy_id="p-resp", decision_id="dec-resp", corr="corr-resp")
    finally:
        admin.close()
    responder = _authed_client(db_session, "responder-x", ROLE_RESPONDER)
    try:
        res = responder.post("/api/v1/guardian/automation/v5/executions", json={
            "policy_id": "p-resp", "expected_policy_version": 1,
            "action_type": "network", "action_name": "block_destination",
            "target": dict(TARGET), "decision_id": "dec-resp",
            "approval_id": approval_id, "risk_score": 75.0,
            "incident_severity": "high", "incident_id": 7,
            "evaluation_id": evaluation_id})
        assert res.status_code == 200, res.text
        assert res.json()["status"] == "succeeded"
    finally:
        responder.close()


def test_api_kill_switch_requires_admin(db_session):
    analyst = _authed_client(db_session, "analyst-k", ROLE_ANALYST)
    try:
        assert analyst.post("/api/v1/guardian/automation/v5/safety/kill-switch", json={
            "scope": "global", "switch_key": "global"}).status_code == 403
    finally:
        analyst.close()


def test_api_execution_validates_input(api):
    res = api.post("/api/v1/guardian/automation/v5/executions", json={
        "policy_id": "p", "expected_policy_version": 0, "action_type": "network",
        "action_name": "block_destination", "target": {}, "decision_id": "d",
        "approval_id": "a", "risk_score": 1.0, "incident_severity": "low"})
    assert res.status_code == 422


def test_api_safety_status_shape(api):
    res = api.get("/api/v1/guardian/automation/v5/safety/status")
    assert res.status_code == 200, res.text
    body = res.json()
    assert "kill_switches" in body and "circuit_breakers" in body
    assert "rate_limiter" in body and "execution_modes" in body
    assert "approved_manual_execution" in body["execution_modes"]
    assert "pre_authorized" not in str(body["execution_modes"])


def test_legacy_phase3_execute_gated_by_kill_switch(api, db_session, mock_net_action):
    """The pre-existing Phase 3 path now composes kill/breaker/limiter."""
    from backend.models import GuardianActionAttempt
    from guardian.actions.base import compute_action_id

    mgr = ApprovalManager()
    created = mgr.create_approval_request(
        db_session, incident_id=7, decision_id="dec-legacy",
        requested_action="block_destination", action_type="network",
        target=dict(TARGET), rationale="legacy gate test", requested_by="admin-1")
    mgr.approve_request(db_session, approval_id=created["approval_id"], approver="admin-1")
    action_id = compute_action_id("network", TARGET, "dec-legacy")
    db_session.add(GuardianActionAttempt(
        action_id=action_id, approval_id=created["approval_id"], incident_id=7,
        decision_id="dec-legacy", action_type="network", action_name="block_destination",
        target=dict(TARGET), parameters={}, status="approved"))
    db_session.commit()
    ks = get_default_kill_switch()
    ks.activate(KillSwitchScope.GLOBAL, "global", by="t", reason="test")
    try:
        blocked = api.post(f"/api/v1/guardian/actions/{action_id}/execute", json={})
        assert blocked.status_code == 503, blocked.text
        db_session.expire_all()
        row = db_session.query(GuardianActionAttempt).filter_by(action_id=action_id).one()
        assert row.status == "approved"  # refused before any mutation
    finally:
        ks.deactivate(KillSwitchScope.GLOBAL, "global", by="t")


def test_phase4_kill_switch_post_persists(api, db_session):
    res = api.post("/api/v1/guardian/safety/kill_switch",
                   params={"scope": "global", "switch_key": "global", "reason": "stub fix test"})
    assert res.status_code == 200, res.text
    assert res.json()["status"] == "activated"
    assert get_default_kill_switch().is_blocked(
        KillSwitchScope.GLOBAL, "global")[0] is True
    assert kss.is_persisted_active(db_session, "global", "global") is True
    kss.deactivate_persisted(db_session, get_default_kill_switch(), "global", "global", by="t")
    db_session.commit()


# ══════════════════════════════════════════════════════════════════════
# 21-28. Migrations + compat
# ══════════════════════════════════════════════════════════════════════

def test_migration_runner_includes_009():
    revisions = [m.revision for m in mig_runner.MIGRATIONS]
    for expected in ("007_guardian_phase4", "008_guardian_phase5_slice1",
                     "009_guardian_phase5_slice2"):
        assert expected in revisions, revisions
    assert revisions.index("008_guardian_phase5_slice1") < revisions.index("009_guardian_phase5_slice2")


def test_migration_009_idempotent(tmp_path):
    from backend.migrations.versions import guardian_phase5_slice2_009 as mig09

    path = tmp_path / "mig09.db"
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    mig09.upgrade(engine, Base)
    mig09.upgrade(engine, Base)
    names = set(sa_inspect(engine).get_table_names())
    assert "guardian_envelope_runs" in names
    cols = {c["name"] for c in sa_inspect(engine).get_columns("guardian_envelope_runs")}
    for required in ("execution_id", "policy_id", "policy_version", "rule_id",
                     "evaluation_id", "approval_id", "action_id", "actor",
                     "target_hash", "status", "gate_results", "correlation_id"):
        assert required in cols, required
    engine.dispose()


def test_full_runner_applies_007_008_009(tmp_path):
    path = tmp_path / "runner9.db"
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    mig_runner.run_migrations(engine)
    mig_runner.run_migrations(engine)
    from sqlalchemy import text as _text

    with engine.begin() as conn:
        revisions = {row[0] for row in conn.execute(_text("SELECT revision FROM schema_migrations"))}
    assert {"007_guardian_phase4", "008_guardian_phase5_slice1",
            "009_guardian_phase5_slice2"} <= revisions
    names = set(sa_inspect(engine).get_table_names())
    assert {"guardian_envelope_runs", "guardian_policy_evaluations",
            "guardian_automation_runs", "guardian_kill_switches"} <= names
    engine.dispose()


def test_slice1_simulate_still_never_executes(db_session):
    policy_store.create_policy(db_session, _policy("p-s1c"), created_by="admin-1")
    db_session.commit()
    from guardian.automation.policy_v5 import EvaluationRequest as _ER

    policies = policy_store.list_policies(db_session, include_disabled=False)
    result = simulate(policies, _ER(action_type="network", action_name="block_destination",
                                    target=dict(TARGET), risk_score=75.0,
                                    incident_severity="high"))
    assert result.would_execute is False
    assert result.blocked_reason is not None
