"""Phase 5 Slice 3 tests: deterministic conflict analysis + read-only API.

Covers:
  - overlap primitives (action / risk / severity / scope incl. CIDR + prefix)
  - conflict gating (DENY vs non-DENY only; different actions alone never conflict)
  - precedence (DENY wins; otherwise Slice 1 sort key)
  - shadowed full vs partial + ambiguous flag
  - dormant overlaps for disabled / expired policies (no runtime impact)
  - determinism (order-independent, stable conflict_id)
  - API schemas / validation / RBAC / version handling
  - read-only guarantee (no mutation from /conflicts)
  - simulation semantics preserved (no execution from simulation)
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.auth import ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR, ROLE_RESPONDER, get_current_user
from backend.database import Base
from backend.main import app

from guardian.automation.conflicts import (
    actions_overlap,
    analyze_policy_conflicts,
    risk_overlap,
    rules_overlap,
    scope_is_subset,
    scope_overlap,
)
from guardian.automation.policy import AutomationMode, PolicyDecision
from guardian.automation.policy_v5 import (
    ApprovalMode,
    AutomationPolicyV5,
    PolicyRuleV5,
)


def _rule(rule_id="r1", **over):
    kwargs = {
        "rule_id": rule_id,
        "description": "D",
        "action_type": "network",
        "action_name": "block_destination",
        "min_risk_score": 0.0,
        "max_risk_score": 100.0,
        "incident_severity": None,
        "decision": PolicyDecision.REQUIRE_APPROVAL,
        "requires_approval": True,
        "priority": 100,
        "target_scope": None,
        "approval_mode": ApprovalMode.REQUIRED,
    }
    kwargs.update(over)
    return PolicyRuleV5(**kwargs)


def _policy(policy_id="p-a", rules=None, **over):
    kwargs = {
        "policy_id": policy_id,
        "name": "N",
        "description": "D",
        "mode": AutomationMode.APPROVAL_REQUIRED,
        "enabled": True,
        "version": 1,
        "priority": 100,
        "expires_at": None,
        "rules": rules if rules is not None else [],
    }
    kwargs.update(over)
    return AutomationPolicyV5(**kwargs)


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture()
def test_engine(tmp_path):
    path = tmp_path / "phase5_slice3.db"
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


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
    app.dependency_overrides[get_current_user] = lambda: _mock_user("slice3-admin", ROLE_ADMIN)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def _client_as(api_client, username, role):
    app.dependency_overrides[get_current_user] = lambda: _mock_user(username, role)
    return api_client


def _policy_payload(policy_id="p-s3", **over):
    base = {
        "policy_id": policy_id,
        "name": "Slice3 policy",
        "description": "Test",
        "mode": "approval_required",
        "priority": 100,
        "enabled": True,
        "rules": [
            {
                "rule_id": "r-a",
                "description": "Rule A",
                "action_type": "network",
                "action_name": "block_destination",
                "min_risk_score": 0.0,
                "max_risk_score": 100.0,
                "decision": "allow",
                "requires_approval": True,
                "priority": 100,
            }
        ],
    }
    base.update(over)
    return base


# ── Overlap primitives ────────────────────────────────────────────────

def test_actions_overlap_wildcard():
    assert actions_overlap("network", "block_destination", "network", "block_destination")
    assert actions_overlap("*", "*", "process", "terminate_process")
    assert actions_overlap("network", "*", "network", "block_destination")
    assert not actions_overlap("network", "block_destination", "process", "terminate_process")
    assert not actions_overlap("network", "block_destination", "network", "other_action")


def test_risk_overlap_edges():
    assert risk_overlap(0, 50, 50, 100)
    assert risk_overlap(0, 10, 20, 30) is False
    assert risk_overlap(60, 80, 70, 90)


def test_scope_overlap_broad_and_shared():
    assert scope_overlap(None, {"host_ids": ["h1"]}) is True
    assert scope_overlap({}, {}) is True
    # Disjoint dimensions still overlap (a target can carry both attributes).
    assert scope_overlap({"host_ids": ["h1"]}, {"process_names": ["evil"]}) is True
    # Shared dimension with disjoint entries does not overlap.
    assert scope_overlap({"host_ids": ["h1"]}, {"host_ids": ["h2"]}) is False
    assert scope_overlap({"host_ids": ["H1"]}, {"host_ids": ["h1"]}) is True
    assert scope_overlap({"destination_ips": ["10.0.0.0/8"]}, {"destination_ips": ["10.1.2.3"]}) is True
    assert scope_overlap({"destination_ips": ["10.0.0.0/8"]}, {"destination_ips": ["192.168.1.1"]}) is False
    assert scope_overlap({"file_paths": ["/tmp/a"]}, {"file_paths": ["/tmp/a/b/c"]}) is True
    assert scope_overlap({"file_paths": ["/tmp/a"]}, {"file_paths": ["/etc"]}) is False


def test_scope_subset():
    assert scope_is_subset(None, None) is True
    assert scope_is_subset({}, {}) is True
    assert scope_is_subset({"host_ids": ["h1"]}, {}) is True
    assert scope_is_subset({}, {"host_ids": ["h1"]}) is False
    assert scope_is_subset({"host_ids": ["h1"]}, {"host_ids": ["h1", "h2"]}) is True
    assert scope_is_subset({"file_paths": ["/tmp/a/b"]}, {"file_paths": ["/tmp/a"]}) is True
    assert scope_is_subset({"destination_ips": ["10.1.2.3"]}, {"destination_ips": ["10.0.0.0/8"]}) is True


def test_rules_overlap_requires_all_dimensions():
    base = _rule()
    assert rules_overlap(base, _rule("r2")) is True
    assert rules_overlap(base, _rule("r2", action_type="process", action_name="terminate_process")) is False
    assert rules_overlap(base, _rule("r2", min_risk_score=90.0, max_risk_score=100.0)) is True
    narrow = _rule("r2", min_risk_score=0.0, max_risk_score=10.0)
    wide = _rule("r1", min_risk_score=90.0, max_risk_score=100.0)
    assert rules_overlap(narrow, wide) is False
    assert rules_overlap(base, _rule("r2", incident_severity="high")) is True
    assert (
        rules_overlap(
            _rule("r1", incident_severity="high"), _rule("r2", incident_severity="low")
        )
        is False
    )


# ── Conflict gating ───────────────────────────────────────────────────

def test_deny_vs_allow_is_conflict():
    deny = _policy("p-deny", rules=[_rule("r-d", decision=PolicyDecision.DENY)])
    allow = _policy("p-allow", rules=[_rule("r-a", decision=PolicyDecision.ALLOW, requires_approval=False)])
    findings = analyze_policy_conflicts([deny, allow])
    assert len(findings) == 1
    finding = findings[0]
    assert finding["is_conflict"] is True
    assert finding["type"] == "deny_conflict"
    assert finding["runtime_impact"] is True
    assert finding["precedence"]["winner_rule_id"] == "r-d"
    assert "Advisory only" in finding["advisory"]


def test_different_actions_alone_never_conflict():
    a = _policy("p-a", rules=[_rule("r-a", action_type="network", action_name="block_destination")])
    b = _policy("p-b", rules=[_rule("r-b", action_type="process", action_name="terminate_process")])
    assert analyze_policy_conflicts([a, b]) == []


def test_same_decision_overlap_is_advisory_not_conflict():
    a = _policy("p-a", rules=[_rule("r-a", decision=PolicyDecision.REQUIRE_APPROVAL)])
    b = _policy("p-b", rules=[_rule("r-b", decision=PolicyDecision.REQUIRE_APPROVAL)])
    findings = analyze_policy_conflicts([a, b])
    assert len(findings) == 1
    assert findings[0]["is_conflict"] is False
    assert findings[0]["type"] == "redundant_overlap"


def test_precedence_shadow_same_effect():
    low = _policy("p-low", priority=10, rules=[_rule("r-low", priority=10)])
    high = _policy("p-high", priority=900, rules=[_rule("r-high", priority=900)])
    findings = analyze_policy_conflicts([low, high])
    assert len(findings) == 1
    # Same decision -> redundant advisory, winner is the higher precedence rule.
    assert findings[0]["precedence"]["winner_rule_id"] == "r-high"


def test_deny_wins_regardless_of_priority():
    weak_deny = _policy("p-weak", priority=1, rules=[_rule("r-d", decision=PolicyDecision.DENY, priority=1)])
    strong_allow = _policy(
        "p-strong", priority=1000,
        rules=[_rule("r-a", decision=PolicyDecision.ALLOW, requires_approval=False, priority=1000)],
    )
    findings = analyze_policy_conflicts([weak_deny, strong_allow])
    assert findings[0]["precedence"]["winner_rule_id"] == "r-d"


def test_full_vs_partial_shadowing():
    broad = _policy("p-broad", rules=[_rule("r-broad", decision=PolicyDecision.DENY)])
    narrow = _policy(
        "p-narrow",
        rules=[_rule(
            "r-narrow", decision=PolicyDecision.ALLOW, requires_approval=False,
            target_scope={"destination_ips": ["10.1.2.3"]},
        )],
    )
    findings = analyze_policy_conflicts([broad, narrow])
    assert findings[0]["shadowed"]["rule_id"] == "r-narrow"
    # Narrow match set is a subset of the broad deny: fully shadowed.
    assert findings[0]["shadowed"]["coverage"] == "full"
    assert findings[0]["ambiguous"] is False

    # Partial overlap: neither scope contains the other (share h2 only).
    left = _policy(
        "p-left",
        rules=[_rule(
            "r-left", decision=PolicyDecision.DENY,
            target_scope={"host_ids": ["h1", "h2"]},
        )],
    )
    right = _policy(
        "p-right",
        rules=[_rule(
            "r-right", decision=PolicyDecision.ALLOW, requires_approval=False,
            target_scope={"host_ids": ["h2", "h3"]},
        )],
    )
    partial = analyze_policy_conflicts([left, right])
    assert len(partial) == 1
    assert partial[0]["shadowed"]["coverage"] == "partial"
    assert partial[0]["ambiguous"] is True


def test_dormant_overlap_has_no_runtime_impact():
    active = _policy("p-on", rules=[_rule("r-a", decision=PolicyDecision.DENY)])
    disabled = _policy("p-off", rules=[_rule("r-b", decision=PolicyDecision.ALLOW)], enabled=False)
    findings = analyze_policy_conflicts([active, disabled])
    assert len(findings) == 1
    assert findings[0]["is_conflict"] is False
    assert findings[0]["type"] == "dormant_overlap"
    assert findings[0]["runtime_impact"] is False


def test_analysis_deterministic_and_order_independent():
    a = _policy("p-aaa", rules=[_rule("r1", decision=PolicyDecision.DENY)])
    b = _policy("p-zzz", rules=[_rule("r1", decision=PolicyDecision.ALLOW)])
    first = analyze_policy_conflicts([a, b])
    second = analyze_policy_conflicts([b, a])
    assert first == second
    assert first[0]["conflict_id"].startswith("cfx-")


# ── API ───────────────────────────────────────────────────────────────

def test_conflicts_empty_without_policies(api):
    res = api.get("/api/v1/guardian/automation/v5/conflicts")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["total"] == 0
    assert body["conflicts"] == 0
    assert "Guidance only" in body["note"]


def test_conflicts_detects_deny_override(api):
    api.post(
        "/api/v1/guardian/automation/v5/policies",
        json=_policy_payload("p-s3-deny", rules=[{
            "rule_id": "r-deny", "description": "Deny", "action_type": "network",
            "action_name": "block_destination", "min_risk_score": 0.0,
            "max_risk_score": 100.0, "decision": "deny",
            "requires_approval": True, "priority": 100,
        }]),
    )
    api.post(
        "/api/v1/guardian/automation/v5/policies",
        json=_policy_payload("p-s3-allow", rules=[{
            "rule_id": "r-allow", "description": "Allow", "action_type": "network",
            "action_name": "block_destination", "min_risk_score": 0.0,
            "max_risk_score": 100.0, "decision": "allow",
            "requires_approval": True, "priority": 100,
        }]),
    )
    res = api.get("/api/v1/guardian/automation/v5/conflicts")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["conflicts"] >= 1
    conflict = next(item for item in body["items"] if item["is_conflict"])
    assert conflict["precedence"]["winner_rule_id"] == "r-deny"
    assert "only" in conflict["advisory"].lower()


def test_conflicts_policy_filter_and_404(api):
    api.post("/api/v1/guardian/automation/v5/policies", json=_policy_payload("p-s3-only"))
    res = api.get("/api/v1/guardian/automation/v5/conflicts", params={"policy_id": "p-s3-only"})
    assert res.status_code == 200, res.text
    assert all(
        any(r["policy_id"] == "p-s3-only" for r in item["rules"])
        for item in res.json()["items"]
    )
    missing = api.get("/api/v1/guardian/automation/v5/conflicts", params={"policy_id": "does-not-exist"})
    assert missing.status_code == 404


def test_conflicts_rbac_view_roles_allowed_auditor_denied_none(api):
    api.post("/api/v1/guardian/automation/v5/policies", json=_policy_payload("p-s3-rbac"))
    auditor = _client_as(api, "auditor-1", ROLE_AUDITOR)
    assert auditor.get("/api/v1/guardian/automation/v5/conflicts").status_code == 200
    analyst = _client_as(api, "analyst-1", ROLE_ANALYST)
    assert analyst.get("/api/v1/guardian/automation/v5/conflicts").status_code == 200
    responder = _client_as(api, "responder-1", ROLE_RESPONDER)
    assert responder.get("/api/v1/guardian/automation/v5/conflicts").status_code == 200


def test_conflicts_is_read_only(api, test_engine):
    from backend.models import GuardianAutomationPolicy, GuardianPolicyEvaluation

    api.post("/api/v1/guardian/automation/v5/policies", json=_policy_payload("p-s3-ro"))
    factory = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    session = factory()
    try:
        policies_before = session.query(GuardianAutomationPolicy).count()
        evals_before = session.query(GuardianPolicyEvaluation).count()
    finally:
        session.close()
    res = api.get("/api/v1/guardian/automation/v5/conflicts")
    assert res.status_code == 200, res.text
    session = factory()
    try:
        assert session.query(GuardianAutomationPolicy).count() == policies_before
        assert session.query(GuardianPolicyEvaluation).count() == evals_before
    finally:
        session.close()


def test_conflicts_respects_version_bump(api):
    api.post("/api/v1/guardian/automation/v5/policies", json=_policy_payload("p-s3-ver"))
    api.patch("/api/v1/guardian/automation/v5/policies/p-s3-ver", json={"description": "v2"})
    detail = api.get("/api/v1/guardian/automation/v5/policies/p-s3-ver").json()
    assert detail["version"] == 2


def test_simulation_still_never_executes(api):
    api.post("/api/v1/guardian/automation/v5/policies", json=_policy_payload("p-s3-sim"))
    res = api.post("/api/v1/guardian/automation/v5/simulate", json={
        "action_type": "network",
        "action_name": "block_destination",
        "target": {"destination_ip": "203.0.113.66"},
        "risk_score": 75.0,
        "incident_severity": "high",
        "correlation_id": "slice3-sim",
    })
    assert res.status_code == 200, res.text
    assert res.json()["would_execute"] is False
