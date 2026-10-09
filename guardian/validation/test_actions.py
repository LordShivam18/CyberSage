"""Harmless test action for the Phase 7 harness (PROVIDED — NOT EXECUTED).

Implements the existing BaseAction interface with purely in-memory
behavior: no process signals, no firewall changes, no registry or
persistence edits, no shell, no network calls. It exists so the harness
can traverse the REAL authorization and SafetyEnvelope path (policy,
grant/approval, kill switch, breaker, limiter, target validation,
snapshot, execution, independent verification, explicit rollback,
immutable audit) without destructive effects.

Production destructive action types are validated separately through
their own validate() safety checks; this action never stands in for
their OS effects.
"""

from __future__ import annotations

from typing Any, Dict, List, Optional

from guardian.actions.base import (
    BaseAction,
    ExecutionResult,
    RollbackResult,
    SnapshotData,
    ValidationResult,
    VerificationResult,
)


class NoopSafeTestAction(BaseAction):
    """In-memory toggle used only by the developer-run harness."""

    action_type = "test"
    action_name = "noop_safe"

    def __init__(self) -> None:
        self._state: Dict[str, bool] = {}

    @property
    def rollback_supported(self) -> bool:
        return True

    def validate(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> ValidationResult:
        errors: List[str] = []
        token = target.get("harness_token")
        if token != "e2e-harmless":
            errors.append("target.harness_token must be 'e2e-harmless'")
        action = (parameters or {}).get("action")
        if action not in ("set", "leave-unset"):
            errors.append("parameters.action must be 'set' or 'leave-unset'")
        return ValidationResult(valid=not errors, errors=errors)

    def snapshot(self, target: Dict[str, Any], action_id: str) -> Optional[SnapshotData]:
        return SnapshotData(
            snapshot_id="", action_id=action_id, action_type=self.action_type,
            target=dict(target), prior_state={"flag": self._state.get(action_id, False)},
            metadata={"harness": True}, immutable=True,
        )

    def execute(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None,
                snapshot: Optional[SnapshotData] = None) -> ExecutionResult:
        action = (parameters or {}).get("action", "set")
        # Deliberate mismatch mode for failed-verification cases:
        if action == "leave-unset":
            return ExecutionResult(success=True, output={"claimed": True})
        action_id = (snapshot.action_id if snapshot else "harness")
        self._state[action_id] = True
        return ExecutionResult(success=True, output={"flag": True})

    def verify(self, target: Dict[str, Any], result: ExecutionResult,
               snapshot: Optional[SnapshotData] = None) -> VerificationResult:
        action_id = snapshot.action_id if snapshot else "harness"
        observed = self._state.get(action_id, False)
        if observed:
            return VerificationResult(passed=True, checks=[{"check": "flag_set"}],
                                      evidence={"observed": observed}, observed_state={"flag": observed})
        return VerificationResult(passed=False, checks=[{"check": "flag_set"}],
                                  evidence={"observed": observed}, observed_state={"flag": observed},
                                  failure_reason="flag not set; execution claim did not take effect")

    def rollback(self, target: Dict[str, Any], snapshot: SnapshotData) -> RollbackResult:
        self._state[snapshot.action_id] = bool((snapshot.prior_state or {}).get("flag", False))
        return RollbackResult(success=True, output={"restored": True})

    def describe(self) -> str:
        return "Harmless in-memory harness action (no OS effects)."
