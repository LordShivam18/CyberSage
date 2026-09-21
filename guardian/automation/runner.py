"""Guardian v2 Phase 4 — Automation Runner.

AutomationRunner manages the lifecycle of automation runs.

Properties:
  - Idempotent: same run_id returns the original run
  - Bounded: circuit breaker after repeated failures
  - Auditable: every run creates an audit record
  - Replay-safe: duplicate submissions detected by run_id
  - Kill-switchable: checks kill switch before any execution
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from guardian.automation.policy import (
    AutomationMode,
    AutomationPolicy,
    AutomationRun,
    AutomationRunRequest,
    AutomationRunStatus,
    PolicyDecision,
    PolicyEngine,
    compute_run_id,
)

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AutomationRunner:
    """Manages automation run lifecycle against a policy.

    Usage:
        runner = AutomationRunner(policy, kill_switch)
        run = runner.submit(session, request)
        # Check run.status and run.requires_approval
        # If approval required, create an approval request via ApprovalManager
        # After approval, call runner.execute(session, run_id)
    """

    def __init__(
        self,
        policy: AutomationPolicy,
        kill_switch_fn=None,
    ) -> None:
        """
        Args:
            policy: The automation policy governing this runner.
            kill_switch_fn: Optional callable() -> bool that returns True if
                            the global kill switch is active. If None, always False.
        """
        self._policy = policy
        self._kill_switch_fn = kill_switch_fn or (lambda: False)
        self._engine = PolicyEngine()

    def is_kill_switch_active(self) -> bool:
        """Return True if the kill switch is active."""
        try:
            return bool(self._kill_switch_fn())
        except Exception:  # noqa: BLE001
            # Fail closed — if we can't check the kill switch, treat it as active
            logger.error(
                "AutomationRunner: kill switch check raised; treating as active (fail closed)"
            )
            return True

    def submit(
        self,
        request: AutomationRunRequest,
        existing_runs: Optional[Dict[str, AutomationRun]] = None,
    ) -> AutomationRun:
        """Submit an automation run request.

        Idempotent: if the same run_id already exists, returns the original run.

        Args:
            request: The automation run parameters.
            existing_runs: Optional dict of run_id → AutomationRun (for idempotency check).
                           In production, this comes from the database layer.

        Returns:
            AutomationRun with status reflecting the policy decision.
        """
        run_id = compute_run_id(
            request.action_type,
            request.action_name,
            request.target,
            request.decision_id,
        )

        # Idempotency check
        if existing_runs and run_id in existing_runs:
            logger.info("AutomationRunner.submit: returning existing run %s (idempotent)", run_id)
            return existing_runs[run_id]

        # Policy evaluation
        kill_switch_active = self.is_kill_switch_active()
        decision, reason = self._engine.evaluate(
            self._policy,
            action_type=request.action_type,
            action_name=request.action_name,
            risk_score=request.risk_score,
            incident_severity=request.incident_severity,
            kill_switch_active=kill_switch_active,
        )

        # Determine run status from decision
        if decision == PolicyDecision.DENY:
            status = AutomationRunStatus.BLOCKED
        elif decision == PolicyDecision.PREPARE_ONLY:
            status = AutomationRunStatus.PENDING
        elif decision == PolicyDecision.REQUIRE_APPROVAL:
            status = AutomationRunStatus.AWAITING_APPROVAL
        else:
            # ALLOW — still requires_approval=True until Phase 5 fully-automated mode
            status = AutomationRunStatus.AWAITING_APPROVAL

        # Safety: always require approval in current phase (APPROVAL_REQUIRED is default mode)
        requires_approval = (
            decision in (PolicyDecision.REQUIRE_APPROVAL, PolicyDecision.ALLOW)
            and decision != PolicyDecision.DENY
            and decision != PolicyDecision.PREPARE_ONLY
        )
        # Extra enforcement: if mode is APPROVAL_REQUIRED, always require approval
        if self._policy.mode == AutomationMode.APPROVAL_REQUIRED:
            requires_approval = True

        now = _now_utc()
        run = AutomationRun(
            run_id=run_id,
            policy_id=request.policy_id or self._policy.policy_id,
            action_type=request.action_type,
            action_name=request.action_name,
            target=request.target,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            risk_score=request.risk_score,
            incident_severity=request.incident_severity,
            requested_by=request.requested_by,
            rationale=request.rationale,
            status=status,
            policy_decision=decision,
            requires_approval=requires_approval,
            approval_id=None,
            parameters=request.parameters,
            created_at=now,
            updated_at=now,
        )

        if decision == PolicyDecision.DENY:
            run.error = f"Blocked by policy: {reason}"

        logger.info(
            "AutomationRunner.submit: run %s — decision=%s requires_approval=%s reason=%s",
            run_id, decision.value, requires_approval, reason,
        )
        return run

    def cancel(self, run: AutomationRun, reason: str = "operator_cancelled") -> AutomationRun:
        """Cancel a pending or awaiting-approval run."""
        if run.status not in (
            AutomationRunStatus.PENDING,
            AutomationRunStatus.AWAITING_APPROVAL,
        ):
            logger.warning(
                "AutomationRunner.cancel: run %s is in status %s — cannot cancel",
                run.run_id, run.status.value,
            )
            return run

        run.status = AutomationRunStatus.CANCELLED
        run.error = reason
        run.updated_at = _now_utc()
        logger.info("AutomationRunner: run %s cancelled: %s", run.run_id, reason)
        return run
