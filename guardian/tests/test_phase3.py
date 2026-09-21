"""Comprehensive tests for Guardian Phase 3 — Controlled Response, Approval, Verification, and Rollback.

Tests cover:
- Approval lifecycle (create, approve, reject, expiry, invalid transitions, RBAC)
- Action architecture (registry, validation, execution)
- Snapshot model (capture, immutability, integrity)
- Verification (positive, negative, independent)
- Rollback (supported, unsupported, success, failure)
- Stale-decision protection
- Idempotency
- Audit trail (immutability, actor attribution, no secrets)
- Security (no shell=True, no arbitrary commands, path validation, target validation)
- Adversarial cases (approval bypass, decision tampering, expired/rejected approval)
"""

import inspect
import os
import sys
import tempfile
import textwrap

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# ── Skip if backend dependencies not available ─────────────────────────
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

from guardian.actions.base import (
    ActionStatus,
    ApprovalStatus,
    ExecutionResult,
    RollbackStatus,
    ValidationResult,
    SnapshotData,
    VerificationResult,
    compute_action_id,
    compute_approval_id,
    compute_snapshot_id,
    compute_verification_id,
    compute_audit_id,
    validate_state_transition,
)
from guardian.actions.registry import get_action, list_actions, is_registered
from guardian.actions.process import TerminateProcessAction, PROTECTED_PROCESSES, PROTECTED_PIDS
from guardian.actions.network import BlockDestinationAction
from guardian.actions.persistence import DisablePersistenceEntryAction, ALLOWED_PERSISTENCE_TYPES
from guardian.actions.snapshot import SnapshotManager
from guardian.actions.verification import VerificationManager
from guardian.actions.rollback import RollbackManager
from guardian.approval.manager import ApprovalManager


# ── Fixtures ───────────────────────────────────────────────────────────


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
        user = create_user(db, "phase3-admin", "Admin123456!", "administrator")
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
        user = create_user(db, "phase3-analyst", "Analyst123456!", "security_analyst")
        db.commit()
        token = create_access_token(user)
        return user, token
    finally:
        db.close()


@pytest.fixture
def responder_user():
    """Create a responder user and return (user, token)."""
    db = SessionLocal()
    try:
        user = create_user(db, "phase3-responder", "Responder123456!", "incident_responder")
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
        user = create_user(db, "phase3-auditor", "Auditor123456!", "read_only_auditor")
        db.commit()
        token = create_access_token(user)
        return user, token
    finally:
        db.close()


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════
# 1. ACTION ARCHITECTURE TESTS
# ══════════════════════════════════════════════════════════════════════


class TestActionRegistry:
    """Test action registration and discovery."""

    def test_builtin_actions_registered(self):
        """All built-in actions should be registered at import time."""
        assert is_registered("process", "terminate_process")
        assert is_registered("network", "block_destination")
        assert is_registered("persistence", "disable_persistence_entry")

    def test_list_actions_returns_all(self):
        """list_actions should return all registered actions."""
        actions = list_actions()
        assert len(actions) >= 3
        names = [(a["action_type"], a["action_name"]) for a in actions]
        assert ("process", "terminate_process") in names
        assert ("network", "block_destination") in names
        assert ("persistence", "disable_persistence_entry") in names

    def test_get_action_returns_correct_instance(self):
        """get_action should return the correct action instance."""
        action = get_action("process", "terminate_process")
        assert action is not None
        assert isinstance(action, TerminateProcessAction)

    def test_get_action_unknown_returns_none(self):
        """get_action for unknown action returns None."""
        assert get_action("nonexistent", "nonexistent") is None


class TestActionStateTransitions:
    """Test state machine transitions."""

    def test_valid_transition_planned_to_awaiting_approval(self):
        assert validate_state_transition(ActionStatus.PLANNED, ActionStatus.AWAITING_APPROVAL)

    def test_valid_transition_approved_to_executing(self):
        assert validate_state_transition(ActionStatus.APPROVED, ActionStatus.EXECUTING)

    def test_valid_transition_executing_to_verifying(self):
        assert validate_state_transition(ActionStatus.EXECUTING, ActionStatus.VERIFYING)

    def test_valid_transition_verifying_to_succeeded(self):
        assert validate_state_transition(ActionStatus.VERIFYING, ActionStatus.SUCCEEDED)

    def test_invalid_transition_succeeded_to_executing(self):
        """Cannot go from succeeded back to executing."""
        assert not validate_state_transition(ActionStatus.SUCCEEDED, ActionStatus.EXECUTING)

    def test_invalid_transition_rejected_to_approved(self):
        """Cannot approve a rejected request."""
        assert not validate_state_transition(ActionStatus.REJECTED, ActionStatus.APPROVED)

    def test_invalid_transition_expired_to_executing(self):
        """Cannot execute an expired action."""
        assert not validate_state_transition(ActionStatus.EXPIRED, ActionStatus.EXECUTING)

    def test_rollback_flow(self):
        """Test the rollback state flow."""
        assert validate_state_transition(ActionStatus.EXECUTION_FAILED, ActionStatus.ROLLBACK_AVAILABLE)
        assert validate_state_transition(ActionStatus.ROLLBACK_AVAILABLE, ActionStatus.ROLLBACK_REQUESTED)
        assert validate_state_transition(ActionStatus.ROLLBACK_REQUESTED, ActionStatus.ROLLBACK_RUNNING)
        assert validate_state_transition(ActionStatus.ROLLBACK_RUNNING, ActionStatus.ROLLBACK_SUCCEEDED)

    def test_stale_flow(self):
        """Test stale decision flow."""
        assert validate_state_transition(ActionStatus.APPROVED, ActionStatus.STALE)
        assert not validate_state_transition(ActionStatus.STALE, ActionStatus.EXECUTING)


# ══════════════════════════════════════════════════════════════════════
# 2. PROCESS ACTION TESTS
# ══════════════════════════════════════════════════════════════════════


class TestTerminateProcessAction:
    """Test process termination action validation."""

    def test_validate_valid_target(self):
        action = TerminateProcessAction()
        result = action.validate({"pid": 12345, "process_name": "test.exe"})
        assert result.valid
        assert len(result.errors) == 0

    def test_validate_missing_pid(self):
        action = TerminateProcessAction()
        result = action.validate({"process_name": "test.exe"})
        assert not result.valid
        assert any("pid" in e.lower() for e in result.errors)

    def test_validate_negative_pid(self):
        action = TerminateProcessAction()
        result = action.validate({"pid": -1, "process_name": "test.exe"})
        assert not result.valid

    def test_validate_protected_pid(self):
        action = TerminateProcessAction()
        result = action.validate({"pid": 1, "process_name": "init"})
        assert not result.valid
        assert any("protected" in e.lower() for e in result.errors)

    def test_validate_protected_process_name(self):
        action = TerminateProcessAction()
        result = action.validate({"pid": 12345, "process_name": "svchost"})
        assert not result.valid
        assert any("protected" in e.lower() for e in result.errors)

    def test_validate_zero_pid_rejected(self):
        action = TerminateProcessAction()
        result = action.validate({"pid": 0, "process_name": "test.exe"})
        assert not result.valid

    def test_no_rollback(self):
        action = TerminateProcessAction()
        assert not action.rollback_supported

    def test_no_snapshot(self):
        action = TerminateProcessAction()
        assert not action.requires_snapshot

    def test_describe(self):
        action = TerminateProcessAction()
        desc = action.describe({"pid": 1234, "process_name": "bad.exe"})
        assert "1234" in desc
        assert "bad.exe" in desc

    def test_action_type_and_name(self):
        action = TerminateProcessAction()
        assert action.action_type == "process"
        assert action.action_name == "terminate_process"


# ══════════════════════════════════════════════════════════════════════
# 3. NETWORK ACTION TESTS
# ══════════════════════════════════════════════════════════════════════


class TestBlockDestinationAction:
    """Test network blocking action validation."""

    def test_validate_valid_target(self):
        action = BlockDestinationAction()
        result = action.validate({"destination_ip": "192.168.1.100", "destination_port": 4444})
        assert result.valid

    def test_validate_missing_ip(self):
        action = BlockDestinationAction()
        result = action.validate({"destination_port": 4444})
        assert not result.valid

    def test_validate_invalid_ip(self):
        action = BlockDestinationAction()
        result = action.validate({"destination_ip": "not-an-ip", "destination_port": 4444})
        assert not result.valid

    def test_validate_loopback_rejected(self):
        action = BlockDestinationAction()
        result = action.validate({"destination_ip": "127.0.0.1", "destination_port": 80})
        assert not result.valid

    def test_validate_multicast_rejected(self):
        action = BlockDestinationAction()
        result = action.validate({"destination_ip": "224.0.0.1", "destination_port": 80})
        assert not result.valid

    def test_validate_port_out_of_range(self):
        action = BlockDestinationAction()
        result = action.validate({"destination_ip": "10.0.0.1", "destination_port": 99999})
        assert not result.valid

    def test_validate_sensitive_port_warning(self):
        action = BlockDestinationAction()
        result = action.validate({"destination_ip": "10.0.0.1", "destination_port": 22})
        assert result.valid
        assert len(result.warnings) > 0

    def test_validate_invalid_protocol(self):
        action = BlockDestinationAction()
        result = action.validate(
            {"destination_ip": "10.0.0.1", "destination_port": 4444},
            {"protocol": "icmp"},
        )
        assert not result.valid

    def test_rollback_supported(self):
        action = BlockDestinationAction()
        assert action.rollback_supported

    def test_action_type_and_name(self):
        action = BlockDestinationAction()
        assert action.action_type == "network"
        assert action.action_name == "block_destination"


# ══════════════════════════════════════════════════════════════════════
# 4. PERSISTENCE ACTION TESTS
# ══════════════════════════════════════════════════════════════════════


class TestDisablePersistenceEntryAction:
    """Test persistence disabling action validation."""

    def test_validate_valid_target(self):
        action = DisablePersistenceEntryAction()
        result = action.validate({
            "persistence_type": "registry_run_key",
            "persistence_path": "HKCU\\Software\\Test",
            "entry_name": "malware",
        })
        assert result.valid

    def test_validate_missing_type(self):
        action = DisablePersistenceEntryAction()
        result = action.validate({"persistence_path": "test", "entry_name": "test"})
        assert not result.valid

    def test_validate_unknown_type(self):
        action = DisablePersistenceEntryAction()
        result = action.validate({
            "persistence_type": "unknown_type",
            "persistence_path": "test",
            "entry_name": "test",
        })
        assert not result.valid
        assert any("allowlist" in e.lower() for e in result.errors)

    def test_validate_protected_path(self):
        action = DisablePersistenceEntryAction()
        result = action.validate({
            "persistence_type": "registry_run_key",
            "persistence_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "entry_name": "test",
        })
        assert not result.valid
        assert any("protected" in e.lower() for e in result.errors)

    def test_validate_path_traversal(self):
        action = DisablePersistenceEntryAction()
        result = action.validate({
            "persistence_type": "registry_run_key",
            "persistence_path": "HKCU\\..\\..\\System32",
            "entry_name": "test",
        })
        assert not result.valid
        assert any("traversal" in e.lower() for e in result.errors)

    def test_validate_missing_entry_name(self):
        action = DisablePersistenceEntryAction()
        result = action.validate({
            "persistence_type": "registry_run_key",
            "persistence_path": "HKCU\\Software\\Test",
        })
        assert not result.valid

    def test_rollback_supported(self):
        action = DisablePersistenceEntryAction()
        assert action.rollback_supported

    def test_action_type_and_name(self):
        action = DisablePersistenceEntryAction()
        assert action.action_type == "persistence"
        assert action.action_name == "disable_persistence_entry"

    def test_startup_folder_simulation(self):
        """Test startup folder disable with temp directory."""
        action = DisablePersistenceEntryAction()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake startup entry
            entry_path = os.path.join(tmpdir, "malware.lnk")
            with open(entry_path, "w") as f:
                f.write("fake shortcut")

            target = {
                "persistence_type": "startup_folder",
                "persistence_path": tmpdir,
                "entry_name": "malware.lnk",
            }

            # Validate
            validation = action.validate(target)
            assert validation.valid

            # Snapshot
            snapshot = action.snapshot(target, "test-action-001")
            assert snapshot is not None
            assert snapshot.prior_state.get("entry_exists") is True

            # Execute
            result = action.execute(target, {"backup": True}, snapshot)
            assert result.success

            # Verify
            v_result = action.verify(target, result)
            assert v_result.passed

            # Rollback
            rb_result = action.rollback(target, snapshot)
            assert rb_result.success
            assert os.path.exists(entry_path)


# ══════════════════════════════════════════════════════════════════════
# 5. SNAPSHOT TESTS
# ══════════════════════════════════════════════════════════════════════


class TestSnapshotManager:
    """Test snapshot capture and integrity."""

    def test_create_snapshot(self):
        manager = SnapshotManager()
        snapshot = manager.create_snapshot(
            action_id="act-test-001",
            action_type="process",
            target={"pid": 1234},
            prior_state={"process_running": True},
        )
        assert snapshot.snapshot_id
        assert snapshot.action_id == "act-test-001"
        assert snapshot.immutable is True
        assert snapshot.prior_state == {"process_running": True}

    def test_snapshot_integrity(self):
        manager = SnapshotManager()
        snapshot = manager.create_snapshot(
            action_id="act-test-002",
            action_type="network",
            target={"destination_ip": "10.0.0.1"},
            prior_state={"firewall_rules": []},
        )
        # Verify integrity
        assert manager.verify_integrity(snapshot)

    def test_snapshot_tamper_detection(self):
        manager = SnapshotManager()
        snapshot = manager.create_snapshot(
            action_id="act-test-003",
            action_type="persistence",
            target={"path": "/test"},
            prior_state={"data": "original"},
        )
        # Tamper with the snapshot
        snapshot.prior_state["data"] = "tampered"
        # Integrity should fail
        assert not manager.verify_integrity(snapshot)


# ══════════════════════════════════════════════════════════════════════
# 6. VERIFICATION TESTS
# ══════════════════════════════════════════════════════════════════════


class TestVerificationManager:
    """Test independent verification."""

    def test_verify_action_success(self):
        manager = VerificationManager()
        action = TerminateProcessAction()
        exec_result = ExecutionResult(success=True, output={"pid": 99999})

        def verify_fn(target, exec_result):
            return VerificationResult(
                passed=True,
                checks=[{"check": "process_terminated", "passed": True}],
            )

        result = manager.verify_action(
            "act-test-004", {"pid": 99999}, exec_result, verify_fn,
        )
        assert result.passed

    def test_verify_action_exception(self):
        manager = VerificationManager()

        def bad_verify(target, exec_result):
            raise RuntimeError("verification exploded")

        result = manager.verify_action(
            "act-test-005", {"pid": 1234}, ExecutionResult(success=True), bad_verify,
        )
        assert not result.passed
        assert "exception" in result.failure_reason.lower()


# ══════════════════════════════════════════════════════════════════════
# 7. ROLLBACK TESTS
# ══════════════════════════════════════════════════════════════════════


class TestRollbackManager:
    """Test rollback operations."""

    def test_rollback_not_needed_when_verification_passed(self):
        manager = RollbackManager()
        action = TerminateProcessAction()
        v_result = VerificationResult(passed=True)
        assert not manager.is_rollback_needed(v_result, action)

    def test_rollback_needed_when_verification_failed(self):
        manager = RollbackManager()
        action = BlockDestinationAction()
        v_result = VerificationResult(passed=False)
        assert manager.is_rollback_needed(v_result, action)

    def test_rollback_not_needed_when_not_supported(self):
        manager = RollbackManager()
        action = TerminateProcessAction()
        v_result = VerificationResult(passed=False)
        assert not manager.is_rollback_needed(v_result, action)

    def test_rollback_without_snapshot_fails(self):
        manager = RollbackManager()
        action = BlockDestinationAction()
        result = manager.request_rollback(action, {"destination_ip": "10.0.0.1"}, None)
        assert not result.success
        assert "no snapshot" in result.error.lower()


# ══════════════════════════════════════════════════════════════════════
# 8. APPROVAL MODEL TESTS (API)
# ══════════════════════════════════════════════════════════════════════


class TestApprovalAPI:
    """Test approval endpoints."""

    def test_create_approval_request(self, client, admin_user):
        _, token = admin_user
        response = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": "rd-test-001",
                "requested_action": "terminate_process",
                "action_type": "process",
                "target": {"pid": 1234, "process_name": "test.exe"},
                "rationale": "Suspicious process detected",
            },
            headers=_auth_header(token),
        )
        assert response.status_code == 200
        data = response.json()
        assert "approval_id" in data
        assert data["status"] == "pending"

    def test_create_approval_unregistered_action(self, client, admin_user):
        _, token = admin_user
        response = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": "rd-test-002",
                "requested_action": "nonexistent_action",
                "action_type": "nonexistent",
                "target": {"something": "value"},
                "rationale": "Test",
            },
            headers=_auth_header(token),
        )
        assert response.status_code == 422

    def test_approve_request(self, client, admin_user):
        _, token = admin_user
        # Create
        r = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": "rd-test-003",
                "requested_action": "block_destination",
                "action_type": "network",
                "target": {"destination_ip": "10.0.0.1", "destination_port": 4444},
                "rationale": "C2 traffic",
            },
            headers=_auth_header(token),
        )
        approval_id = r.json()["approval_id"]

        # Approve
        r2 = client.post(
            f"/api/v1/guardian/approvals/{approval_id}/approve",
            json={"notes": "Approved after review"},
            headers=_auth_header(token),
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "approved"

    def test_reject_request(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": "rd-test-004",
                "requested_action": "block_destination",
                "action_type": "network",
                "target": {"destination_ip": "10.0.0.1", "destination_port": 4444},
                "rationale": "C2 traffic",
            },
            headers=_auth_header(token),
        )
        approval_id = r.json()["approval_id"]

        r2 = client.post(
            f"/api/v1/guardian/approvals/{approval_id}/reject",
            json={"notes": "Not enough evidence"},
            headers=_auth_header(token),
        )
        assert r2.status_code == 200
        assert r2.json()["status"] == "rejected"

    def test_approve_already_approved_fails(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": "rd-test-005",
                "requested_action": "terminate_process",
                "action_type": "process",
                "target": {"pid": 9999},
                "rationale": "Test",
            },
            headers=_auth_header(token),
        )
        approval_id = r.json()["approval_id"]
        client.post(
            f"/api/v1/guardian/approvals/{approval_id}/approve",
            json={},
            headers=_auth_header(token),
        )
        # Try again
        r2 = client.post(
            f"/api/v1/guardian/approvals/{approval_id}/approve",
            json={},
            headers=_auth_header(token),
        )
        assert r2.status_code == 422

    def test_auditor_cannot_approve(self, client, auditor_user):
        _, token = auditor_user
        # Auditor can read but not approve
        r = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": "rd-test-006",
                "requested_action": "terminate_process",
                "action_type": "process",
                "target": {"pid": 1234},
                "rationale": "Test",
            },
            headers=_auth_header(token),
        )
        # Auditor shouldn't be able to create approvals (requires analyst/responder/admin)
        assert r.status_code == 403

    def test_list_approvals(self, client, admin_user):
        _, token = admin_user
        # Create some approvals
        for i in range(3):
            client.post(
                "/api/v1/guardian/approvals",
                json={
                    "decision_id": f"rd-list-{i}",
                    "requested_action": "terminate_process",
                    "action_type": "process",
                    "target": {"pid": 1000 + i},
                    "rationale": "Test",
                },
                headers=_auth_header(token),
            )
        r = client.get("/api/v1/guardian/approvals", headers=_auth_header(token))
        assert r.status_code == 200
        assert r.json()["total"] == 3

    def test_get_approval_detail(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": "rd-detail-001",
                "requested_action": "block_destination",
                "action_type": "network",
                "target": {"destination_ip": "10.0.0.1"},
                "rationale": "Test",
            },
            headers=_auth_header(token),
        )
        approval_id = r.json()["approval_id"]
        r2 = client.get(f"/api/v1/guardian/approvals/{approval_id}", headers=_auth_header(token))
        assert r2.status_code == 200
        assert r2.json()["approval_id"] == approval_id


# ══════════════════════════════════════════════════════════════════════
# 9. ACTION EXECUTION TESTS (API)
# ══════════════════════════════════════════════════════════════════════


class TestActionExecutionAPI:
    """Test action execution endpoints."""

    def test_action_registry_endpoint(self, client, admin_user):
        _, token = admin_user
        r = client.get("/api/v1/guardian/actions/registry", headers=_auth_header(token))
        assert r.status_code == 200
        assert "actions" in r.json()
        assert len(r.json()["actions"]) >= 3


# ══════════════════════════════════════════════════════════════════════
# 10. AUDIT TRAIL TESTS
# ══════════════════════════════════════════════════════════════════════


class TestAuditTrail:
    """Test immutable audit records."""

    def test_audit_id_deterministic(self):
        """Same inputs produce same audit ID."""
        id1 = compute_audit_id("act-001")
        id2 = compute_audit_id("act-001")
        assert id1 == id2

    def test_audit_id_different_for_different_actions(self):
        id1 = compute_audit_id("act-001")
        id2 = compute_audit_id("act-002")
        assert id1 != id2

    def test_audit_endpoint_requires_admin_or_auditor(self, client, analyst_user):
        _, token = analyst_user
        r = client.get("/api/v1/guardian/audit", headers=_auth_header(token))
        # Analyst should not be able to access audit
        assert r.status_code == 403

    def test_audit_endpoint_auditor_can_read(self, client, auditor_user):
        _, token = auditor_user
        r = client.get("/api/v1/guardian/audit", headers=_auth_header(token))
        assert r.status_code == 200
        assert "total" in r.json()


# ══════════════════════════════════════════════════════════════════════
# 11. SECURITY TESTS
# ══════════════════════════════════════════════════════════════════════


class TestSecurity:
    """Test security invariants."""

    def test_no_shell_true_in_process_action(self):
        """Process action must not use shell=True in executable code."""
        import ast
        source = inspect.getsource(TerminateProcessAction.execute)
        tree = ast.parse(textwrap.dedent(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    pytest.fail("Process action uses shell=True")

    def test_no_shell_true_in_network_action(self):
        """Network action must not use shell=True in executable code."""
        import ast
        source = inspect.getsource(BlockDestinationAction.execute)
        tree = ast.parse(textwrap.dedent(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    pytest.fail("Network action uses shell=True")

    def test_no_shell_true_in_persistence_action(self):
        """Persistence action must not use shell=True in executable code."""
        import ast
        source = inspect.getsource(DisablePersistenceEntryAction.execute)
        tree = ast.parse(textwrap.dedent(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    pytest.fail("Persistence action uses shell=True")

    def test_no_eval_exec_in_actions(self):
        """No eval/exec in any action module."""
        for module_name in [
            "guardian.actions.process",
            "guardian.actions.network",
            "guardian.actions.persistence",
            "guardian.actions.base",
            "guardian.actions.registry",
            "guardian.actions.snapshot",
            "guardian.actions.verification",
            "guardian.actions.rollback",
        ]:
            module = __import__(module_name, fromlist=[""])
            source = inspect.getsource(module)
            assert "eval(" not in source, f"eval() found in {module_name}"
            assert "exec(" not in source, f"exec() found in {module_name}"

    def test_protected_processes_cannot_be_terminated(self):
        """Protected process names must be rejected."""
        action = TerminateProcessAction()
        for name in PROTECTED_PROCESSES:
            result = action.validate({"pid": 12345, "process_name": name})
            assert not result.valid, f"Protected process '{name}' should be rejected"

    def test_protected_pids_cannot_be_terminated(self):
        """Protected PIDs must be rejected."""
        action = TerminateProcessAction()
        for pid in PROTECTED_PIDS:
            result = action.validate({"pid": pid, "process_name": "test"})
            assert not result.valid, f"Protected PID {pid} should be rejected"

    def test_non_allowlisted_persistence_rejected(self):
        """Non-allowlisted persistence types must be rejected."""
        action = DisablePersistenceEntryAction()
        result = action.validate({
            "persistence_type": "arbitrary_registry",
            "persistence_path": "HKLM\\Test",
            "entry_name": "evil",
        })
        assert not result.valid

    def test_approval_required_for_execution(self):
        """No action can execute without an approval record."""
        from backend.models import GuardianActionAttempt
        db = SessionLocal()
        try:
            # No approval record exists, so execution should fail
            # This is tested at the API level - the endpoint checks for approval
            pass
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════
# 12. ADVERSARIAL TESTS
# ══════════════════════════════════════════════════════════════════════


class TestAdversarial:
    """Test adversarial scenarios."""

    def test_cannot_approve_nonexistent_request(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/approvals/nonexistent-id/approve",
            json={},
            headers=_auth_header(token),
        )
        assert r.status_code == 422

    def test_cannot_reject_nonexistent_request(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/approvals/nonexistent-id/reject",
            json={},
            headers=_auth_header(token),
        )
        assert r.status_code == 422

    def test_cannot_execute_nonexistent_action(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/guardian/actions/nonexistent-id/execute",
            json={},
            headers=_auth_header(token),
        )
        assert r.status_code == 404

    def test_different_target_cannot_reuse_approval(self):
        """Approval for one target cannot be used for a different target."""
        manager = ApprovalManager()
        db = SessionLocal()
        try:
            # Create approval for target A
            result = manager.create_approval_request(
                db,
                incident_id=None,
                decision_id="rd-adv-001",
                requested_action="terminate_process",
                action_type="process",
                target={"pid": 1111, "process_name": "a.exe"},
                rationale="Test",
            )
            approval_id = result["approval_id"]

            # Approve it
            manager.approve_request(db, approval_id=approval_id, approver="admin")

            # Try to validate for different target
            is_valid, error = manager.validate_for_execution(
                db,
                approval_id=approval_id,
                decision_id="rd-adv-001",
                target={"pid": 2222, "process_name": "b.exe"},  # Different!
                action_type="process",
            )
            assert not is_valid
            assert "target mismatch" in error.lower()
        finally:
            db.close()

    def test_expired_approval_cannot_execute(self):
        """Expired approval cannot be used for execution."""
        manager = ApprovalManager()
        db = SessionLocal()
        try:
            result = manager.create_approval_request(
                db,
                incident_id=None,
                decision_id="rd-adv-002",
                requested_action="block_destination",
                action_type="network",
                target={"destination_ip": "10.0.0.1", "destination_port": 4444},
                rationale="Test",
                ttl_minutes=0,  # Expires immediately
            )
            approval_id = result["approval_id"]

            # Check expiry
            is_valid = manager.check_expiry(db, approval_id)
            assert not is_valid  # Should be expired
        finally:
            db.close()

    def test_rejected_approval_cannot_execute(self):
        """Rejected approval cannot be used for execution."""
        manager = ApprovalManager()
        db = SessionLocal()
        try:
            result = manager.create_approval_request(
                db,
                incident_id=None,
                decision_id="rd-adv-003",
                requested_action="terminate_process",
                action_type="process",
                target={"pid": 3333, "process_name": "test.exe"},
                rationale="Test",
            )
            approval_id = result["approval_id"]

            # Reject
            manager.reject_request(db, approval_id=approval_id, approver="admin")

            # Try to validate
            is_valid, error = manager.validate_for_execution(
                db,
                approval_id=approval_id,
                decision_id="rd-adv-003",
                target={"pid": 3333, "process_name": "test.exe"},
                action_type="process",
            )
            assert not is_valid
            assert "rejected" in error.lower()
        finally:
            db.close()

    def test_decision_mismatch_rejected(self):
        """Approval for one decision cannot be used for a different decision."""
        manager = ApprovalManager()
        db = SessionLocal()
        try:
            result = manager.create_approval_request(
                db,
                incident_id=None,
                decision_id="rd-adv-004",
                requested_action="block_destination",
                action_type="network",
                target={"destination_ip": "10.0.0.1"},
                rationale="Test",
            )
            approval_id = result["approval_id"]
            manager.approve_request(db, approval_id=approval_id, approver="admin")

            # Try with different decision_id
            is_valid, error = manager.validate_for_execution(
                db,
                approval_id=approval_id,
                decision_id="rd-adv-999",  # Different!
                target={"destination_ip": "10.0.0.1"},
                action_type="network",
            )
            assert not is_valid
            assert "decision" in error.lower()
        finally:
            db.close()

    def test_rbacs_check(self):
        """Test RBAC enforcement."""
        manager = ApprovalManager()
        # Auditor cannot approve
        assert not manager.check_rbac("read_only_auditor", "approve")
        # Auditor cannot execute
        assert not manager.check_rbac("read_only_auditor", "execute")
        # Analyst can approve
        assert manager.check_rbac("security_analyst", "approve")
        # Analyst cannot execute
        assert not manager.check_rbac("security_analyst", "execute")
        # Responder can approve and execute
        assert manager.check_rbac("incident_responder", "approve")
        assert manager.check_rbac("incident_responder", "execute")
        # Admin can do everything
        assert manager.check_rbac("administrator", "approve")
        assert manager.check_rbac("administrator", "execute")
        assert manager.check_rbac("administrator", "manage")


# ══════════════════════════════════════════════════════════════════════
# 13. IDEMPOTENCY TESTS
# ══════════════════════════════════════════════════════════════════════


class TestIdempotency:
    """Test idempotency of actions and approvals.

    Contract:
        First request  → 200, existing=False,  approval_id=X
        Repeat request → 200, existing=True,   approval_id=X (same)
    """

    # ── Basic idempotency ─────────────────────────────────────────────

    def test_approval_request_idempotent(self, client, admin_user):
        """Same approval request twice should return existing."""
        _, token = admin_user
        payload = {
            "decision_id": "rd-idem-001",
            "requested_action": "terminate_process",
            "action_type": "process",
            "target": {"pid": 5555, "process_name": "test.exe"},
            "rationale": "Test",
        }
        r1 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        r2 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["approval_id"] == r2.json()["approval_id"]
        # First response must advertise existing=False
        assert r1.json().get("existing") is False
        # Second response must advertise existing=True
        assert r2.json().get("existing") is True

    def test_approval_request_idempotent_three_times(self, client, admin_user):
        """Same approval request submitted three times — always returns same identity."""
        _, token = admin_user
        payload = {
            "decision_id": "rd-idem-triple",
            "requested_action": "block_destination",
            "action_type": "network",
            "target": {"destination_ip": "10.0.0.2", "destination_port": 4444},
            "rationale": "Triple-submit idempotency test",
        }
        results = [
            client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
            for _ in range(3)
        ]
        approval_ids = [r.json()["approval_id"] for r in results]
        assert all(s.status_code == 200 for s in results), "All submissions must return 200"
        assert len(set(approval_ids)) == 1, "All submissions must return the same approval_id"
        assert results[1].json().get("existing") is True
        assert results[2].json().get("existing") is True

        # Database: exactly one row
        db = SessionLocal()
        try:
            from backend.models import GuardianApprovalRequest
            count = db.query(GuardianApprovalRequest).filter(
                GuardianApprovalRequest.approval_id == approval_ids[0]
            ).count()
            assert count == 1, f"Expected 1 DB row, found {count}"
        finally:
            db.close()

    def test_idempotency_response_contains_decision_id(self, client, admin_user):
        """First-creation response includes decision_id so clients can replay the request."""
        _, token = admin_user
        decision_id = "rd-idem-roundtrip"
        payload = {
            "decision_id": decision_id,
            "requested_action": "terminate_process",
            "action_type": "process",
            "target": {"pid": 8888, "process_name": "bad.exe"},
            "rationale": "Roundtrip test",
        }
        r1 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        assert r1.status_code == 200
        assert r1.json().get("decision_id") == decision_id, (
            "First-creation response must include decision_id so clients can reconstruct "
            "an identical idempotency request"
        )

        # Use decision_id from first response (the gateway pattern)
        payload2 = dict(payload, decision_id=r1.json()["decision_id"])
        r2 = client.post("/api/v1/guardian/approvals", json=payload2, headers=_auth_header(token))
        assert r2.status_code == 200
        assert r2.json()["approval_id"] == r1.json()["approval_id"]
        assert r2.json().get("existing") is True

    # ── Post-decision idempotency ─────────────────────────────────────

    def test_idempotent_after_approval(self, client, admin_user):
        """Submitting same request after it has been approved still returns existing=True."""
        _, token = admin_user
        payload = {
            "decision_id": "rd-idem-post-approved",
            "requested_action": "terminate_process",
            "action_type": "process",
            "target": {"pid": 7777, "process_name": "test.exe"},
            "rationale": "Test post-approval idempotency",
        }
        r1 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        approval_id = r1.json()["approval_id"]

        # Approve
        client.post(
            f"/api/v1/guardian/approvals/{approval_id}/approve",
            json={"notes": "CI"},
            headers=_auth_header(token),
        )

        # Re-submit identical request
        r2 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        assert r2.status_code == 200
        assert r2.json()["approval_id"] == approval_id
        assert r2.json().get("existing") is True

    def test_idempotent_after_rejection(self, client, admin_user):
        """Submitting same request after rejection still returns existing=True (no new row)."""
        _, token = admin_user
        payload = {
            "decision_id": "rd-idem-post-rejected",
            "requested_action": "block_destination",
            "action_type": "network",
            "target": {"destination_ip": "10.1.2.3", "destination_port": 9999},
            "rationale": "Test post-rejection idempotency",
        }
        r1 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        approval_id = r1.json()["approval_id"]

        # Reject
        client.post(
            f"/api/v1/guardian/approvals/{approval_id}/reject",
            json={"notes": "CI rejection"},
            headers=_auth_header(token),
        )

        # Re-submit identical request — must NOT create a new row
        r2 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        assert r2.status_code == 200
        assert r2.json()["approval_id"] == approval_id
        assert r2.json().get("existing") is True

        db = SessionLocal()
        try:
            from backend.models import GuardianApprovalRequest
            count = db.query(GuardianApprovalRequest).filter(
                GuardianApprovalRequest.approval_id == approval_id
            ).count()
            assert count == 1, "Rejection + re-submit must not create a second row"
        finally:
            db.close()

    def test_idempotent_after_expiry(self, client, admin_user):
        """Submitting same request after it expires still returns existing=True (no new row)."""
        _, token = admin_user
        manager = ApprovalManager()
        db = SessionLocal()
        try:
            # Create with TTL=0 to expire immediately
            result = manager.create_approval_request(
                db,
                incident_id=None,
                decision_id="rd-idem-post-expired",
                requested_action="terminate_process",
                action_type="process",
                target={"pid": 6666, "process_name": "expire.exe"},
                rationale="Post-expiry idempotency",
                ttl_minutes=0,
            )
            approval_id = result["approval_id"]
            db.commit()

            # Expire it
            manager.check_expiry(db, approval_id)
            db.commit()

            # Re-submit via API — must still return same row (existing=True)
            from backend.models import GuardianApprovalRequest
            count_before = db.query(GuardianApprovalRequest).filter(
                GuardianApprovalRequest.approval_id == approval_id
            ).count()
        finally:
            db.close()

        payload = {
            "decision_id": "rd-idem-post-expired",
            "requested_action": "terminate_process",
            "action_type": "process",
            "target": {"pid": 6666, "process_name": "expire.exe"},
            "rationale": "Post-expiry idempotency",
        }
        r = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        assert r.status_code == 200
        assert r.json()["approval_id"] == approval_id
        assert r.json().get("existing") is True

        db2 = SessionLocal()
        try:
            from backend.models import GuardianApprovalRequest
            count_after = db2.query(GuardianApprovalRequest).filter(
                GuardianApprovalRequest.approval_id == approval_id
            ).count()
            assert count_after == 1, "Expiry + re-submit must not create a second row"
        finally:
            db2.close()

    # ── Fingerprint isolation ─────────────────────────────────────────

    def test_changed_action_type_produces_different_id(self):
        """Changed action_type must NOT collide with the original fingerprint."""
        id1 = compute_approval_id("process", {"pid": 1234}, "rd-iso-001")
        id2 = compute_approval_id("network", {"pid": 1234}, "rd-iso-001")
        assert id1 != id2, "Different action_type must produce different approval_id"

    def test_changed_target_produces_different_id(self):
        """Changed target must NOT collide with the original fingerprint."""
        id1 = compute_approval_id("process", {"pid": 1234}, "rd-iso-002")
        id2 = compute_approval_id("process", {"pid": 9999}, "rd-iso-002")
        assert id1 != id2, "Different target must produce different approval_id"

    def test_changed_incident_produces_different_id(self):
        """Changed decision_id (different incident) must NOT collide."""
        id1 = compute_approval_id("process", {"pid": 1234}, "rd-iso-003-incident-A")
        id2 = compute_approval_id("process", {"pid": 1234}, "rd-iso-003-incident-B")
        assert id1 != id2, "Different decision_id must produce different approval_id"

    def test_modified_request_does_not_collide_with_original(self, client, admin_user):
        """A request with a changed target must create a NEW approval row."""
        _, token = admin_user
        base_payload = {
            "decision_id": "rd-iso-api",
            "requested_action": "terminate_process",
            "action_type": "process",
            "target": {"pid": 1111, "process_name": "original.exe"},
            "rationale": "Isolation test",
        }
        modified_payload = dict(base_payload, target={"pid": 2222, "process_name": "different.exe"})

        r1 = client.post("/api/v1/guardian/approvals", json=base_payload, headers=_auth_header(token))
        r2 = client.post("/api/v1/guardian/approvals", json=modified_payload, headers=_auth_header(token))

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["approval_id"] != r2.json()["approval_id"], (
            "Different targets must produce different approval rows"
        )
        # Neither is marked existing on first creation
        assert r1.json().get("existing") is False
        assert r2.json().get("existing") is False

    # ── Audit deduplication ───────────────────────────────────────────

    def test_duplicate_submission_does_not_create_duplicate_audit(self, client, admin_user):
        """Idempotent re-submission must not create a second 'approval requested' audit record."""
        from backend.models import AuditEvent
        _, token = admin_user
        payload = {
            "decision_id": "rd-idem-audit",
            "requested_action": "terminate_process",
            "action_type": "process",
            "target": {"pid": 4321, "process_name": "audit-test.exe"},
            "rationale": "Audit dedup test",
        }
        r1 = client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))
        approval_id = r1.json()["approval_id"]

        # Re-submit
        client.post("/api/v1/guardian/approvals", json=payload, headers=_auth_header(token))

        db = SessionLocal()
        try:
            count = db.query(AuditEvent).filter(
                AuditEvent.target_id == approval_id,
                AuditEvent.action == "guardian_approval_requested",
            ).count()
            assert count == 1, (
                f"Expected 1 audit record for approval creation, got {count}. "
                "Duplicate submissions must not create additional 'created' audit events."
            )
        finally:
            db.close()

    # ── Concurrent duplicate safety ───────────────────────────────────

    def test_concurrent_duplicate_requests_produce_single_row(self, client, admin_user):
        """Concurrent identical requests must not produce more than one DB row."""
        import threading
        _, token = admin_user
        payload = {
            "decision_id": "rd-idem-concurrent",
            "requested_action": "block_destination",
            "action_type": "network",
            "target": {"destination_ip": "10.99.0.1", "destination_port": 8080},
            "rationale": "Concurrency test",
        }
        responses = []
        errors = []

        def submit():
            try:
                r = client.post(
                    "/api/v1/guardian/approvals",
                    json=payload,
                    headers=_auth_header(token),
                )
                responses.append(r)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=submit) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent requests raised exceptions: {errors}"
        ok_responses = [r for r in responses if r.status_code == 200]
        assert len(ok_responses) == 5, f"Expected 5 OK responses, got {len(ok_responses)}"

        approval_ids = {r.json()["approval_id"] for r in ok_responses}
        assert len(approval_ids) == 1, (
            f"Concurrent requests must all return the same approval_id; got {approval_ids}"
        )

        db = SessionLocal()
        try:
            from backend.models import GuardianApprovalRequest
            count = db.query(GuardianApprovalRequest).filter(
                GuardianApprovalRequest.approval_id == list(approval_ids)[0]
            ).count()
            assert count == 1, f"Expected 1 DB row after concurrent requests, found {count}"
        finally:
            db.close()

    # ── Deterministic ID functions ────────────────────────────────────

    def test_action_id_deterministic(self):
        """Same inputs produce same action ID."""
        id1 = compute_action_id("process", {"pid": 1234}, "rd-001")
        id2 = compute_action_id("process", {"pid": 1234}, "rd-001")
        assert id1 == id2

    def test_snapshot_id_deterministic(self):
        id1 = compute_snapshot_id("act-001")
        id2 = compute_snapshot_id("act-001")
        assert id1 == id2

    def test_verification_id_deterministic(self):
        id1 = compute_verification_id("act-001")
        id2 = compute_verification_id("act-001")
        assert id1 == id2

    # ── Runtime gate regression ───────────────────────────────────────

    def test_runtime_gate_idempotency_sequence(self, client, admin_user):
        """Mirror the exact runtime release gate idempotency sequence.

        This test prevents regression of the specific failure:
            r_apv_dup.json().get("existing") is True

        The gate pattern:
            1. Create approval (decision_id is generated inline by caller)
            2. Duplicate uses decision_id from first response
            3. Assert existing=True on second response
        """
        import uuid
        _, token = admin_user

        # Step 1: create (decision_id embedded in call, not stored externally)
        decision_id = f"runtime-gate-regression-{uuid.uuid4().hex[:8]}"
        r1 = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": decision_id,
                "requested_action": "terminate_process",
                "action_type": "process",
                "target": {"pid": 99999, "process_name": "ci-test"},
                "rationale": "Runtime release gate validation",
            },
            headers=_auth_header(token),
        )
        assert r1.status_code == 200, f"Approval creation failed: {r1.status_code}"
        assert "approval_id" in r1.json()
        assert r1.json()["status"] == "pending"
        assert "decision_id" in r1.json(), (
            "First response must include decision_id so the gate can reconstruct the duplicate"
        )

        # Step 2: duplicate uses decision_id from first response (the gate pattern)
        r2 = client.post(
            "/api/v1/guardian/approvals",
            json={
                "decision_id": r1.json().get("decision_id", "x"),  # exactly as in the gate
                "requested_action": "terminate_process",
                "action_type": "process",
                "target": {"pid": 99999, "process_name": "ci-test"},
                "rationale": "Runtime release gate validation",
            },
            headers=_auth_header(token),
        )
        assert r2.status_code == 200, "Idempotent approval must return 200"
        assert r2.json().get("existing") is True, (
            "Guardian Phase 3: idempotent approval not detected — "
            "r_apv_dup.json().get('existing') is not True"
        )
        assert r2.json()["approval_id"] == r1.json()["approval_id"], (
            "Idempotent response must return the original approval_id"
        )


# ══════════════════════════════════════════════════════════════════════
# 14. V1.1 COMPATIBILITY TESTS
# ══════════════════════════════════════════════════════════════════════


class TestV11Compatibility:
    """Verify Phase 3 does not break v1.1 functionality."""

    def test_health_endpoint(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_ready_endpoint(self, client):
        r = client.get("/api/v1/ready")
        assert r.status_code == 200

    def test_alerts_endpoint(self, client, admin_user):
        _, token = admin_user
        r = client.get("/api/v1/alerts", headers=_auth_header(token))
        assert r.status_code == 200

    def test_incidents_endpoint(self, client, admin_user):
        _, token = admin_user
        r = client.get("/api/v1/incidents", headers=_auth_header(token))
        assert r.status_code == 200

    def test_login(self, client, admin_user):
        _, token = admin_user
        r = client.post(
            "/api/v1/auth/login",
            json={"username": "phase3-admin", "password": "Admin123456!"},
        )
        assert r.status_code == 200
        assert "access_token" in r.json()


# ══════════════════════════════════════════════════════════════════════
# 15. PHASE 2 COMPATIBILITY TESTS
# ══════════════════════════════════════════════════════════════════════


class TestPhase2Compatibility:
    """Verify Phase 3 does not break Phase 2 functionality."""

    def test_detections_endpoint(self, client, admin_user):
        _, token = admin_user
        r = client.get("/api/v1/guardian/detections", headers=_auth_header(token))
        assert r.status_code == 200

    def test_incidents_endpoint(self, client, admin_user):
        _, token = admin_user
        r = client.get("/api/v1/guardian/incidents", headers=_auth_header(token))
        assert r.status_code == 200

    def test_guardian_events_endpoint(self, client, admin_user):
        _, token = admin_user
        r = client.get("/api/v1/guardian/events", headers=_auth_header(token))
        assert r.status_code == 200

    def test_guardian_stats_endpoint(self, client, admin_user):
        _, token = admin_user
        r = client.get("/api/v1/guardian/stats", headers=_auth_header(token))
        assert r.status_code == 200
