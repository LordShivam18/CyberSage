"""Guardian v2 Phase 5 Slice 2 — safety-envelope executor.

The single authoritative path that connects policy, approval, the action
registry, kill switch, circuit breaker, rate limiter, target validation,
execution, independent verification, rollback, and immutable audit.

Mandated execution order (no step skippable):

    resolve policy -> verify active -> verify version -> verify identity
      -> kill switch (global, then agent/action) -> circuit breaker
      -> rate limiter (+ policy cooldown/frequency caps)
      -> target validation -> policy authorization (deny still wins)
      -> approval validation -> create execution record -> execute
      -> independently verify -> rollback-available (explicit only)
      -> finalize audit

Safety precedence enforced: KILL SWITCH > CIRCUIT BREAKER > RATE LIMITER
> TARGET SAFETY > POLICY AUTHORIZATION > APPROVAL > EXECUTION.

Slice 2 authorization modes: SIMULATION (never executes), AWAITING_APPROVAL,
APPROVED_MANUAL (human approval required, always). Pre-authorized execution
is NOT honored in this slice: a pre_authorized rule still requires a valid
approval, recorded explicitly in the gate detail.

Design rules:
  - Reuse, never duplicate: ApprovalManager, action registry + BaseAction
    lifecycle, Snapshot/Verification/Rollback managers, KillSwitch,
    CircuitBreaker, ActionRateLimiter, Slice 1 evaluate/store.
  - Idempotent: deterministic execution_id; UNIQUE(execution_id) is the
    final concurrency arbiter; racers resolve to the winning row.
  - No open transaction across action.execute(): pre-create records, commit,
    execute, then verify/finalize. A crash mid-flight leaves a non-success
    row (fail closed), never an apparent success without audit.
  - No AI dependency: this module takes no AI input and references no AI
    output. AI cannot authorize, approve, or trigger execution.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from guardian.actions.base import (
    ActionStatus,
    RollbackStatus,
    compute_action_id,
    compute_audit_id,
    compute_rollback_id,
    compute_snapshot_id,
    compute_verification_id,
    validate_state_transition,
)
from guardian.actions.registry import get_action, is_registered
from guardian.actions.verification import VerificationManager
from guardian.approval.manager import ApprovalManager
from guardian.automation.policy import AutomationMode, PolicyDecision
from guardian.automation.policy_v5 import (
    ApprovalMode,
    EvaluationRequest,
    PolicyValidationError,
    evaluate_policies,
)
from guardian.automation import store as policy_store
from guardian.safety import kill_switch_store
from guardian.safety.kill_switch import KillSwitch, KillSwitchScope, get_default_kill_switch
from guardian.safety.registry import get_breaker, get_execution_limiter

logger = logging.getLogger(__name__)


# How long a replay waits for an in-flight execution to reach a terminal
# state before returning the latest observed state (fail-closed: the
# returned status is whatever is recorded, never invented).
REPLAY_WAIT_SECONDS = 60.0
REPLAY_POLL_SECONDS = 0.05


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Modes & gates ─────────────────────────────────────────────────────

class ExecutionMode(str, Enum):
    SIMULATION = "simulation"  # never executes (dry-run only)
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED_MANUAL = "approved_manual_execution"
    # PRE_AUTHORIZED intentionally absent in Slice 2.


# Ordered gate names. check_gates() always returns one result per gate in
# this order so audit rows are comparable across runs.
GATE_ORDER = [
    "policy_active",
    "policy_version",
    "identity",
    "kill_switch_global",
    "kill_switch_scoped",
    "circuit_breaker",
    "rate_limit",
    "cooldown",
    "target_validation",
    "policy_authorization",
    "approval",
]

# Envelope row lifecycle. Mirrors base.VALID_ACTION_TRANSITIONS and adds the
# envelope-only pre-state safety_check plus the fail-closed blocked branch.
ENVELOPE_TRANSITIONS: Dict[str, List[str]] = {
    "safety_check": ["executing", "blocked"],
    "executing": ["verifying", "execution_failed", "blocked"],
    "verifying": ["succeeded", "verification_failed", "execution_failed"],
    "verification_failed": ["rollback_available", "rollback_failed"],
    "execution_failed": ["rollback_available", "rollback_failed"],
    "rollback_available": ["rollback_requested", "blocked"],
    "rollback_requested": ["rolling_back"],
    "rolling_back": ["rolled_back", "rollback_failed"],
    "succeeded": [],
    "rolled_back": [],
    "rollback_failed": [],
    "blocked": [],
}

TERMINAL_STATUSES = frozenset({"succeeded", "rolled_back", "rollback_failed", "blocked"})
# Rows a replay may rest in: terminal states plus failure/awaiting-rollback
# end states (execution_failed / verification_failed without rollback
# support, rollback_available awaiting an explicit request). In-flight
# states (safety_check, executing, verifying, rollback_requested,
# rolling_back) are waited on instead of returned.
SETTLED_STATUSES = TERMINAL_STATUSES | frozenset({
    "execution_failed", "verification_failed", "rollback_available",
})
NON_EXECUTED_STATUSES = frozenset({"blocked"})  # rows that never ran the action


class EnvelopeTransitionError(ValueError):
    """Raised on invalid envelope state transitions."""


def transition_envelope_status(current: str, target: str) -> str:
    """Validate an envelope status transition. Returns target or raises."""
    allowed = ENVELOPE_TRANSITIONS.get(current, [])
    if target not in allowed:
        raise EnvelopeTransitionError(
            f"Invalid envelope transition '{current}' -> '{target}'"
        )
    return target


@dataclass
class GateResult:
    gate: str
    passed: bool
    reason: str
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate": self.gate,
            "passed": self.passed,
            "reason": self.reason,
            "detail": self.detail,
        }


@dataclass
class EnvelopeRequest:
    """Authorized execution request. Plain data; never AI output."""

    policy_id: str
    expected_policy_version: int
    action_type: str
    action_name: str
    target: Dict[str, Any]
    decision_id: str
    approval_id: str
    risk_score: float = 0.0
    incident_severity: str = "low"
    incident_id: Optional[int] = None
    event_ids: List[str] = field(default_factory=list)
    evaluation_id: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    agent_key: Optional[str] = None
    correlation_id: Optional[str] = None
    requested_by: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "expected_policy_version": self.expected_policy_version,
            "action_type": self.action_type,
            "action_name": self.action_name,
            "target": self.target,
            "decision_id": self.decision_id,
            "approval_id": self.approval_id,
            "risk_score": self.risk_score,
            "incident_severity": self.incident_severity,
            "incident_id": self.incident_id,
            "event_ids": self.event_ids,
            "evaluation_id": self.evaluation_id,
            "parameters": self.parameters,
            "agent_key": self.agent_key,
            "correlation_id": self.correlation_id,
            "requested_by": self.requested_by,
        }


@dataclass
class EnvelopeResult:
    execution_id: str
    status: str
    existing: bool
    gates: List[Dict[str, Any]]
    action_id: Optional[str] = None
    verification: Optional[Dict[str, Any]] = None
    rollback: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "status": self.status,
            "existing": self.existing,
            "gates": self.gates,
            "action_id": self.action_id,
            "verification": self.verification,
            "rollback": self.rollback,
            "error": self.error,
        }


# ── Deterministic identity ────────────────────────────────────────────

def canonical_target_hash(target: Dict[str, Any]) -> str:
    fingerprint = json.dumps(target or {}, sort_keys=True, separators=(",", ":"), default=str)
    return "tgt-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


def compute_execution_id(request: EnvelopeRequest) -> str:
    """Deterministic execution identity.

    Dimensions: policy_id + expected version + evaluation binding + concrete
    action + canonical target hash + incident + decision + approval + agent
    scope. Agent scope is included because it changes the safety verdict.
    Correlation IDs are deliberately excluded: retries of the same authorized
    request (new correlation) must resolve to the same execution.
    """
    fingerprint = json.dumps(
        {
            "policy_id": request.policy_id,
            "policy_version": int(request.expected_policy_version),
            "evaluation_id": request.evaluation_id or "",
            "action_type": request.action_type,
            "action_name": request.action_name,
            "target_hash": canonical_target_hash(request.target),
            "incident_id": request.incident_id,
            "decision_id": request.decision_id,
            "approval_id": request.approval_id,
            "agent_key": request.agent_key or "",
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return "exe-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


def validate_envelope_request(request: EnvelopeRequest) -> None:
    """Shape validation. Raises PolicyValidationError (mapped to 422)."""
    if not isinstance(request.policy_id, str) or not request.policy_id or len(request.policy_id) > 128:
        raise PolicyValidationError("policy_id must be 1-128 chars")
    if not isinstance(request.expected_policy_version, int) or request.expected_policy_version < 1:
        raise PolicyValidationError("expected_policy_version must be an integer >= 1")
    if not is_registered(request.action_type, request.action_name):
        raise PolicyValidationError(
            f"Action '{request.action_type}:{request.action_name}' is not registered"
        )
    if "*" in (request.action_type, request.action_name):
        raise PolicyValidationError("Execution requires a concrete action (wildcards forbidden)")
    if not isinstance(request.target, dict):
        raise PolicyValidationError("target must be an object")
    if not request.decision_id or len(request.decision_id) > 128:
        raise PolicyValidationError("decision_id must be 1-128 chars")
    if not request.approval_id or len(request.approval_id) > 128:
        raise PolicyValidationError("approval_id is required in Slice 2 (approved manual execution only)")
    try:
        risk = float(request.risk_score)
    except (TypeError, ValueError):
        raise PolicyValidationError("risk_score must be a number")
    if not (0.0 <= risk <= 100.0):
        raise PolicyValidationError("risk_score must be 0-100")
    if request.incident_severity not in ("low", "medium", "high", "critical"):
        raise PolicyValidationError("incident_severity must be low|medium|high|critical")
    if not isinstance(request.event_ids, list) or len(request.event_ids) > 100:
        raise PolicyValidationError("event_ids must be a list (max 100)")
    if not isinstance(request.parameters, dict):
        raise PolicyValidationError("parameters must be an object")


# ── Safety envelope ───────────────────────────────────────────────────

class SafetyEnvelope:
    """Authoritative fail-closed execution path.

    Dependencies are injectable for tests; defaults are the process-wide
    shared instances (kill-switch singleton, breaker registry, limiter).
    """

    def __init__(
        self,
        kill_switch: Optional[KillSwitch] = None,
        breaker_fn=None,
        limiter=None,
    ) -> None:
        self._kill_switch = kill_switch or get_default_kill_switch()
        self._breaker_fn = breaker_fn or get_breaker
        self._limiter = limiter if limiter is not None else get_execution_limiter()
        self._approvals = ApprovalManager()
        self._verification = VerificationManager()

    # ── Gate evaluation (ordered, auditable) ──────────────────────────

    def check_gates(
        self,
        session: Session,
        request: EnvelopeRequest,
        *,
        record_quota: bool = False,
    ) -> Tuple[List[GateResult], Dict[str, Any]]:
        """Evaluate every gate in mandated order.

        Side effects: none, except optionally consuming one rate-limit quota
        unit (record_quota=True, execution path only). Simulations MUST pass
        record_quota=False. Returns (gates, context) where context carries
        the loaded policy/rule/evaluation for the run phase.
        """
        validate_envelope_request(request)
        gates: List[GateResult] = []
        ctx: Dict[str, Any] = {}

        def _fail(gate: str, reason: str, detail: Optional[str] = None) -> Tuple[List[GateResult], Dict[str, Any]]:
            gates.append(GateResult(gate=gate, passed=False, reason=reason, detail=detail))
            for remaining in GATE_ORDER[len(gates):]:
                gates.append(GateResult(gate=remaining, passed=False, reason="skipped_after_failure"))
            return gates, ctx

        def _pass(gate: str, reason: str, detail: Optional[str] = None) -> None:
            gates.append(GateResult(gate=gate, passed=True, reason=reason, detail=detail))

        # 1. Resolve policy.
        policy = policy_store.get_policy(session, request.policy_id)
        if policy is None:
            return _fail("policy_active", "policy_not_found",
                         f"policy '{request.policy_id}' does not exist")

        # 1a. Policy active? (enabled, mode, expiry)
        if not policy.enabled or policy.mode == AutomationMode.DISABLED or policy.is_expired():
            return _fail("policy_active", "policy_not_active",
                         f"enabled={policy.enabled} mode={policy.mode.value}")
        _pass("policy_active", "policy_active",
              f"{policy.policy_id} v{policy.version} mode={policy.mode.value}")
        ctx["policy"] = policy

        # 2. Version match (TOCTOU guard).
        if int(policy.version) != int(request.expected_policy_version):
            return _fail("policy_version", "stale_policy_version",
                         f"expected v{request.expected_policy_version}, current v{policy.version}")
        _pass("policy_version", "version_match", f"v{policy.version}")
        ctx["matched_rule"] = None

        # Fresh deterministic evaluation for rule context + deny-wins-at-execution.
        eval_req = EvaluationRequest(
            action_type=request.action_type,
            action_name=request.action_name,
            target=dict(request.target),
            risk_score=float(request.risk_score),
            incident_severity=request.incident_severity,
            incident_id=request.incident_id,
            event_ids=list(request.event_ids),
            requested_by=request.requested_by,
            correlation_id=request.correlation_id,
        )
        fresh = evaluate_policies([policy], eval_req)

        # 3. Identity: evaluation binding (when supplied).
        if request.evaluation_id:
            from backend.models import GuardianPolicyEvaluation

            row = session.query(GuardianPolicyEvaluation).filter(
                GuardianPolicyEvaluation.evaluation_id == request.evaluation_id
            ).first()
            if row is None:
                return _fail("identity", "evaluation_not_found",
                             f"evaluation '{request.evaluation_id}' does not exist")
            mismatches = []
            if row.policy_id != request.policy_id:
                mismatches.append("policy_id")
            if row.action_type != request.action_type or row.action_name != request.action_name:
                mismatches.append("action")
            if canonical_target_hash(row.target or {}) != canonical_target_hash(request.target):
                mismatches.append("target")
            if row.incident_id != request.incident_id:
                mismatches.append("incident_id")
            if mismatches:
                return _fail("identity", "identity_mismatch",
                             f"evaluation binding differs: {','.join(sorted(mismatches))}")
            ctx["evaluation"] = {
                "evaluation_id": row.evaluation_id,
                "policy_version": row.policy_version,
                "matched_rule_id": row.matched_rule_id,
            }
            if row.policy_version is not None and int(row.policy_version) != int(request.expected_policy_version):
                return _fail("identity", "stale_evaluation_version",
                             f"evaluation was v{row.policy_version}, request expects v{request.expected_policy_version}")
        _pass("identity", "identity_verified" if request.evaluation_id else "no_evaluation_binding")

        # 4/5. Kill switches: global first, then scoped (memory OR persisted).
        blocked, reason = kill_switch_store.is_blocked_combined(
            session, self._kill_switch, KillSwitchScope.GLOBAL, "global",
            agent_key=request.agent_key, action_key=request.action_type,
        )
        if blocked:
            return _fail("kill_switch_global", "kill_switch_active", reason)
        _pass("kill_switch_global", "kill_switch_clear")
        # 5. Scoped switches: per-agent + per-action (global cleared above).
        scoped_pairs = [(KillSwitchScope.ACTION, request.action_type)]
        if request.agent_key:
            scoped_pairs.append((KillSwitchScope.AGENT, request.agent_key))
        for scope, key in scoped_pairs:
            mem_blocked, mem_reason = self._kill_switch.is_blocked(scope, key)
            if mem_blocked:
                return _fail("kill_switch_scoped", "kill_switch_active", mem_reason)
            try:
                if kill_switch_store.is_persisted_active(session, scope, key):
                    return _fail(
                        "kill_switch_scoped", "kill_switch_active",
                        f"persisted {scope.value} kill switch active for {key}",
                    )
            except Exception as exc:  # noqa: BLE001
                logger.error("envelope: scoped kill-switch read failed; failing closed: %s", exc)
                return _fail("kill_switch_scoped", "kill_switch_check_error_fail_closed")
        _pass("kill_switch_scoped", "kill_switch_clear")

        # 6. Circuit breaker.
        try:
            breaker = self._breaker_fn(request.action_type)
            if not breaker.allow_action():
                stats = breaker.get_stats()
                return _fail("circuit_breaker", "circuit_breaker_open",
                             f"state={stats.get('state')} failures={stats.get('consecutive_failures')}")
        except Exception as exc:  # noqa: BLE001
            logger.error("envelope: breaker check failed; failing closed: %s", exc)
            return _fail("circuit_breaker", "circuit_breaker_error_fail_closed")
        _pass("circuit_breaker", "circuit_breaker_closed", f"state={breaker.get_stats().get('state')}")
        ctx["breaker"] = breaker

        # 7. Rate limiter (quota consumed here on the execution path only).
        try:
            if record_quota:
                allowed, limit_reason = self._limiter.check_and_record(request.action_type)
            else:
                allowed, limit_reason = self._limiter.check_only(request.action_type)
        except Exception as exc:  # noqa: BLE001
            logger.error("envelope: limiter check failed; failing closed: %s", exc)
            return _fail("rate_limit", "rate_limiter_error_fail_closed")
        if not allowed:
            return _fail("rate_limit", "rate_limit_exceeded", limit_reason)
        _pass("rate_limit", "rate_limit_ok")

        # 8. Cooldown / max-frequency caps from the matched rule.
        rule = None
        if fresh.matched_rule_id:
            for candidate in policy.rules:
                if candidate.rule_id == fresh.matched_rule_id:
                    rule = candidate
                    break
        ctx["matched_rule"] = rule
        if rule is not None:
            from backend.models import GuardianEnvelopeRun

            now = _now_utc()
            base_q = session.query(GuardianEnvelopeRun).filter(
                GuardianEnvelopeRun.policy_id == policy.policy_id,
                GuardianEnvelopeRun.target_hash == canonical_target_hash(request.target),
                GuardianEnvelopeRun.status.notin_(list(NON_EXECUTED_STATUSES)),
            )
            if rule.cooldown_seconds:
                cutoff = now - timedelta(seconds=int(rule.cooldown_seconds))
                recent = base_q.filter(GuardianEnvelopeRun.created_at >= cutoff).count()
                if recent > 0:
                    return _fail("cooldown", "cooldown_active",
                                 f"{recent} execution(s) within cooldown_seconds={rule.cooldown_seconds}")
            if rule.max_executions_per_hour:
                cutoff = now - timedelta(hours=1)
                recent = base_q.filter(GuardianEnvelopeRun.created_at >= cutoff).count()
                if recent >= int(rule.max_executions_per_hour):
                    return _fail("cooldown", "max_frequency_exceeded",
                                 f"{recent} execution(s) in the last hour (max {rule.max_executions_per_hour})")
        _pass("cooldown", "cooldown_clear",
              f"rule={rule.rule_id if rule else 'none'}")

        # 9. Target validation (immediately before authorization).
        action = get_action(request.action_type, request.action_name)
        if action is None:  # validate_envelope_request already guarantees registry presence
            return _fail("target_validation", "action_not_registered")
        validation = action.validate(request.target, request.parameters)
        if not validation.valid:
            return _fail("target_validation", "target_invalid", "; ".join(validation.errors))
        _pass("target_validation", "target_valid")
        ctx["action"] = action

        # 10. Policy authorization: deny still wins, even with an approval.
        if fresh.decision == PolicyDecision.DENY:
            return _fail("policy_authorization", "deny_overrides_approval",
                         f"rule {fresh.matched_rule_id} denies this action")
        if rule is not None and rule.approval_mode == ApprovalMode.PRE_AUTHORIZED:
            _pass("policy_authorization", "authorized_pre_authorized_rule_noted",
                  "pre-authorized rules still require approval in Slice 2")
        else:
            _pass("policy_authorization", "authorized",
                  f"decision={fresh.decision.value} rule={fresh.matched_rule_id}")
        ctx["fresh_decision"] = fresh.decision

        # 11. Approval validation (Slice 2 always requires approval).
        valid, err = self._approvals.validate_for_execution(
            session,
            approval_id=request.approval_id,
            decision_id=request.decision_id,
            target=request.target,
            action_type=request.action_type,
        )
        if not valid:
            return _fail("approval", "approval_invalid", err)
        _pass("approval", "approval_valid", f"approval_id={request.approval_id}")

        return gates, ctx

    # ── Full execution ────────────────────────────────────────────────

    def run(self, session: Session, request: EnvelopeRequest, *, actor: str) -> EnvelopeResult:
        """Execute an authorized request through the full envelope.

        Idempotent: an existing execution_id row is returned without any
        re-execution, re-quota, or state change (existing=True).
        """
        from backend.models import (
            GuardianActionAttempt,
            GuardianActionAudit,
            GuardianActionRollback,
            GuardianActionSnapshot,
            GuardianActionVerification,
            GuardianEnvelopeRun,
        )
        from backend.auth import audit_event

        validate_envelope_request(request)
        execution_id = compute_execution_id(request)
        target_hash = canonical_target_hash(request.target)
        action_id = "act-" + hashlib.sha256(f"envelope:{execution_id}".encode()).hexdigest()[:32]

        # Replay fast-path: no gates, no quota, no mutation. In-flight rows
        # are resolved to their terminal result (see _resolve_existing).
        existing_row = session.query(GuardianEnvelopeRun).filter(
            GuardianEnvelopeRun.execution_id == execution_id
        ).first()
        if existing_row is not None:
            logger.info("envelope: replay %s -> %s (idempotent)", execution_id, existing_row.status)
            return self._resolve_existing(session, execution_id)

        # Gates (quota consumed here on first attempt only).
        gates, ctx = self.check_gates(session, request, record_quota=True)
        failed = next((g for g in gates if not g.passed), None)

        def _persist_blocked(reason_gate: GateResult) -> EnvelopeResult:
            row = GuardianEnvelopeRun(
                execution_id=execution_id,
                evaluation_id=request.evaluation_id,
                policy_id=request.policy_id,
                policy_version=int(request.expected_policy_version),
                rule_id=(ctx.get("matched_rule").rule_id if ctx.get("matched_rule") else None),
                incident_id=request.incident_id,
                event_ids=list(request.event_ids),
                decision_id=request.decision_id,
                approval_id=request.approval_id,
                action_id=None,
                actor=actor,
                action_type=request.action_type,
                action_name=request.action_name,
                target=dict(request.target),
                target_hash=target_hash,
                parameters=dict(request.parameters),
                status="blocked",
                gate_results=[g.to_dict() for g in gates],
                error=f"{reason_gate.gate}: {reason_gate.reason}",
                correlation_id=request.correlation_id,
            )
            try:
                session.add(row)
                session.commit()
            except IntegrityError:
                session.rollback()
                return self._resolve_existing(session, execution_id)
            logger.warning("envelope: blocked %s at %s (%s)", execution_id, reason_gate.gate, reason_gate.reason)
            return self._row_to_result(session, row, existing=False)

        if failed is not None:
            return _persist_blocked(failed)

        policy = ctx["policy"]
        action = ctx["action"]

        # Create execution + attempt records (status safety_check), then advance
        # to executing. Any IntegrityError here resolves to the winning row.
        now = _now_utc()
        row = GuardianEnvelopeRun(
            execution_id=execution_id,
            evaluation_id=request.evaluation_id,
            policy_id=request.policy_id,
            policy_version=int(request.expected_policy_version),
            rule_id=(ctx["matched_rule"].rule_id if ctx.get("matched_rule") else None),
            incident_id=request.incident_id,
            event_ids=list(request.event_ids),
            decision_id=request.decision_id,
            approval_id=request.approval_id,
            action_id=action_id,
            actor=actor,
            action_type=request.action_type,
            action_name=request.action_name,
            target=dict(request.target),
            target_hash=target_hash,
            parameters=dict(request.parameters),
            status="safety_check",
            gate_results=[g.to_dict() for g in gates],
            correlation_id=request.correlation_id,
        )
        attempt = GuardianActionAttempt(
            action_id=action_id,
            approval_id=request.approval_id,
            incident_id=request.incident_id,
            decision_id=request.decision_id,
            action_type=request.action_type,
            action_name=request.action_name,
            target=dict(request.target),
            parameters=dict(request.parameters),
            status=ActionStatus.PLANNED,
        )
        try:
            session.add(row)
            session.add(attempt)
            session.flush()
        except IntegrityError:
            session.rollback()
            return self._resolve_existing(session, execution_id)

        def _set_attempt(target: str) -> None:
            if not validate_state_transition(attempt.status, target):
                raise EnvelopeTransitionError(
                    f"Invalid attempt transition '{attempt.status}' -> '{target}'"
                )
            attempt.status = target
            attempt.updated_at = _now_utc()

        try:
            _set_attempt(ActionStatus.AWAITING_APPROVAL)
            _set_attempt(ActionStatus.APPROVED)
            row.status = transition_envelope_status(row.status, "executing")
            _set_attempt(ActionStatus.EXECUTING)
            attempt.execution_started_at = _now_utc()
            attempt.updated_at = _now_utc()
            session.commit()
        except (IntegrityError, EnvelopeTransitionError) as exc:
            session.rollback()
            row.status = "blocked"
            row.error = f"record_creation_failed: {exc}"
            session.add(row)
            session.commit()
            return self._row_to_result(session, row, existing=False)

        # Snapshot (persisted before execution when supported).
        snapshot_data = None
        try:
            if action.requires_snapshot:
                raw_snapshot = action.snapshot(request.target, action_id)
                if raw_snapshot is not None:
                    raw_snapshot.snapshot_id = compute_snapshot_id(action_id)
                    snapshot_data = raw_snapshot
                    session.add(GuardianActionSnapshot(
                        snapshot_id=raw_snapshot.snapshot_id,
                        action_id=action_id,
                        action_type=request.action_type,
                        target=raw_snapshot.target,
                        prior_state=raw_snapshot.prior_state,
                        snapshot_metadata=raw_snapshot.metadata,
                        immutable=True,
                        created_at=raw_snapshot.created_at,
                    ))
                    attempt.snapshot_id = raw_snapshot.snapshot_id
                    session.commit()
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            logger.error("envelope %s: snapshot failed: %s", execution_id, exc)

        # ── EXECUTE (no DB transaction held across this call) ─────────
        breaker = ctx.get("breaker")
        try:
            exec_result = action.execute(request.target, request.parameters, snapshot_data)
        except Exception as exc:  # noqa: BLE001
            from guardian.actions.base import ExecutionResult as _ER

            exec_result = _ER(success=False, error=f"execute raised: {exc}")

        attempt.execution_finished_at = _now_utc()
        attempt.result = dict(exec_result.output or {})
        attempt.updated_at = _now_utc()
        if exec_result.success:
            _set_attempt(ActionStatus.VERIFYING)
            row.status = transition_envelope_status(row.status, "verifying")
        else:
            attempt.status = ActionStatus.EXECUTION_FAILED
            attempt.error = exec_result.error
            row.status = transition_envelope_status(row.status, "execution_failed")
            row.error = exec_result.error
        session.commit()

        verification = None
        verification_id = None
        if exec_result.success:
            try:
                verification = self._verification.verify_action(
                    action_id, request.target, exec_result, action.verify
                )
            except Exception as exc:  # noqa: BLE001
                from guardian.actions.base import VerificationResult as _VR

                verification = _VR(passed=False, failure_reason=f"verify raised: {exc}")
            verification_id = compute_verification_id(action_id)
            session.add(GuardianActionVerification(
                verification_id=verification_id,
                action_id=action_id,
                passed=bool(verification.passed),
                checks=list(verification.checks or []),
                evidence=dict(verification.evidence or {}),
                observed_state=dict(verification.observed_state or {}),
                failure_reason=verification.failure_reason,
            ))
            attempt.verification_id = verification_id
            if verification.passed:
                _set_attempt(ActionStatus.SUCCEEDED)
                row.status = transition_envelope_status(row.status, "succeeded")
                if breaker is not None:
                    breaker.record_success(action_id)
            else:
                attempt.status = ActionStatus.VERIFICATION_FAILED
                attempt.error = verification.failure_reason
                row.status = transition_envelope_status(row.status, "verification_failed")
                row.error = verification.failure_reason
                if breaker is not None:
                    breaker.record_failure(action_id)
            session.commit()
        else:
            if breaker is not None:
                breaker.record_failure(action_id)

        # Rollback offered explicitly (never automatic): mirror Phase 3 by
        # staging an AVAILABLE rollback record only when the action actually
        # ran but verification failed. A failed execution ran nothing, so
        # there is nothing to roll back: execution_failed stays terminal.
        rollback_info: Optional[Dict[str, Any]] = None
        if row.status == "verification_failed" and action.rollback_supported and attempt.snapshot_id:
            rollback_id = compute_rollback_id(action_id)
            session.add(GuardianActionRollback(
                rollback_id=rollback_id,
                action_id=action_id,
                snapshot_id=attempt.snapshot_id,
                status=RollbackStatus.AVAILABLE,
                created_at=_now_utc(),
            ))
            attempt.rollback_id = rollback_id
            try:
                row.status = transition_envelope_status(row.status, "rollback_available")
            except EnvelopeTransitionError:
                pass
            attempt.status = ActionStatus.ROLLBACK_AVAILABLE
            rollback_info = {"rollback_id": rollback_id, "status": RollbackStatus.AVAILABLE}
            session.commit()

        # ── Finalize audit (fail closed: never "succeeded" without audit) ──
        try:
            audit_id = compute_audit_id(action_id)
            session.add(GuardianActionAudit(
                audit_id=audit_id,
                incident_id=request.incident_id,
                approval_id=request.approval_id,
                action_id=action_id,
                actor=actor,
                action_type=request.action_type,
                target=dict(request.target),
                snapshot_id=attempt.snapshot_id,
                execution_started_at=attempt.execution_started_at,
                execution_finished_at=attempt.execution_finished_at,
                verification_passed=(verification.passed if verification else None),
                verification_result=(verification.to_dict() if verification else None),
                rollback_result=(rollback_info or None),
                status=row.status,
                error=row.error,
                created_at=_now_utc(),
            ))
            row.execution_result = dict(exec_result.output or {})
            if verification is not None:
                row.verification = verification.to_dict()
            if rollback_info is not None:
                row.rollback = rollback_info
            row.updated_at = _now_utc()
            audit_event(
                session, f"guardian_envelope_{row.status}", "guardian_envelope",
                execution_id,
                {"policy_id": request.policy_id, "status": row.status, "actor": actor},
                user=None,
            )
            session.commit()
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            logger.error("envelope %s: audit finalize failed: %s", execution_id, exc)
            try:
                fresh = session.query(GuardianEnvelopeRun).filter(
                    GuardianEnvelopeRun.execution_id == execution_id
                ).first()
                if fresh is not None and fresh.status == "succeeded":
                    fresh.status = "execution_failed"  # fail closed: success without audit is invalid
                    fresh.error = f"audit_finalize_failed: {exc}"
                    fresh.updated_at = _now_utc()
                    session.commit()
            except Exception:  # noqa: BLE001
                session.rollback()

        final = session.query(GuardianEnvelopeRun).filter(
            GuardianEnvelopeRun.execution_id == execution_id
        ).first()
        logger.info("envelope: %s finished with status %s", execution_id, final.status)
        return self._row_to_result(session, final, existing=False)

    # ── Read helpers ──────────────────────────────────────────────────

    def _resolve_existing(self, session: Session, execution_id: str) -> EnvelopeResult:
        """Return the winning row, waiting for terminal state if in-flight.

        Concurrent duplicate submissions must resolve to the SAME execution
        result. If the row is mid-flight (another thread/process is running
        it), poll until it reaches a terminal state or the wait budget
        expires. Never invents a status: on timeout the latest recorded
        state is returned as-is.
        """
        from backend.models import GuardianEnvelopeRun

        deadline = time.monotonic() + REPLAY_WAIT_SECONDS
        row = session.query(GuardianEnvelopeRun).filter(
            GuardianEnvelopeRun.execution_id == execution_id
        ).first()
        while row is not None and row.status not in SETTLED_STATUSES:
            if time.monotonic() >= deadline:
                logger.warning(
                    "envelope: replay %s timed out waiting for terminal state (%s)",
                    execution_id, row.status,
                )
                break
            time.sleep(REPLAY_POLL_SECONDS)
            session.expire_all()
            row = session.query(GuardianEnvelopeRun).filter(
                GuardianEnvelopeRun.execution_id == execution_id
            ).first()
        return self._row_to_result(session, row, existing=True)

    def _row_to_result(self, session: Session, row: Any, *, existing: bool) -> EnvelopeResult:
        verification = None
        if row.verification:
            verification = dict(row.verification)
        rollback = dict(row.rollback) if row.rollback else None
        return EnvelopeResult(
            execution_id=row.execution_id,
            status=row.status,
            existing=existing,
            gates=list(row.gate_results or []),
            action_id=row.action_id,
            verification=verification,
            rollback=rollback,
            error=row.error,
        )

    def get_execution(self, session: Session, execution_id: str) -> Optional[Dict[str, Any]]:
        from backend.models import GuardianEnvelopeRun

        row = session.query(GuardianEnvelopeRun).filter(
            GuardianEnvelopeRun.execution_id == execution_id
        ).first()
        if row is None:
            return None
        return _envelope_row_to_dict(row)

    def list_executions(
        self,
        session: Session,
        *,
        policy_id: Optional[str] = None,
        incident_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        from backend.models import GuardianEnvelopeRun

        query = session.query(GuardianEnvelopeRun)
        if policy_id:
            query = query.filter(GuardianEnvelopeRun.policy_id == policy_id)
        if incident_id is not None:
            query = query.filter(GuardianEnvelopeRun.incident_id == incident_id)
        if status:
            query = query.filter(GuardianEnvelopeRun.status == status)
        total = query.count()
        rows = (
            query.order_by(GuardianEnvelopeRun.created_at.desc())
            .offset(offset)
            .limit(min(max(limit, 1), 500))
            .all()
        )
        return total, [_envelope_row_to_dict(r) for r in rows]


def _envelope_row_to_dict(row: Any) -> Dict[str, Any]:
    return {
        "execution_id": row.execution_id,
        "evaluation_id": row.evaluation_id,
        "policy_id": row.policy_id,
        "policy_version": row.policy_version,
        "rule_id": row.rule_id,
        "incident_id": row.incident_id,
        "event_ids": row.event_ids,
        "decision_id": row.decision_id,
        "approval_id": row.approval_id,
        "action_id": row.action_id,
        "actor": row.actor,
        "action_type": row.action_type,
        "action_name": row.action_name,
        "target": row.target,
        "parameters": row.parameters,
        "status": row.status,
        "gates": row.gate_results,
        "execution_result": row.execution_result,
        "verification": row.verification,
        "rollback": row.rollback,
        "error": row.error,
        "correlation_id": row.correlation_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


# ── Shared pre-execution gates for the legacy Phase 3 path ────────────

def pre_execution_safety(
    session: Session,
    *,
    action_type: str,
    agent_key: Optional[str] = None,
    kill_switch: Optional[KillSwitch] = None,
) -> Tuple[bool, int, str]:
    """Kill -> breaker -> limiter for callers outside the envelope.

    Returns (allowed, http_status, reason). Consumes one limiter quota unit
    when all higher gates pass. Returns 503 for kill/breaker blocks (fail
    closed, including check errors) and 429 for rate limits.
    """
    ks = kill_switch or get_default_kill_switch()
    blocked, reason = kill_switch_store.is_blocked_combined(
        session, ks, KillSwitchScope.GLOBAL, "global",
        agent_key=agent_key, action_key=action_type,
    )
    if blocked:
        return False, 503, f"kill_switch: {reason}"

    try:
        breaker = get_breaker(action_type)
        if not breaker.allow_action():
            return False, 503, f"circuit_breaker_open for '{action_type}'"
    except Exception as exc:  # noqa: BLE001
        logger.error("pre_execution_safety: breaker error; failing closed: %s", exc)
        return False, 503, "circuit_breaker_error (fail closed)"

    try:
        allowed, limit_reason = get_execution_limiter().check_and_record(action_type)
    except Exception as exc:  # noqa: BLE001
        logger.error("pre_execution_safety: limiter error; failing closed: %s", exc)
        return False, 503, "rate_limiter_error (fail closed)"
    if not allowed:
        return False, 429, limit_reason or "rate_limit_exceeded"
    return True, 200, "safety_gates_passed"


def record_breaker_outcome(action_type: str, success: bool, action_id: str = "") -> None:
    """Record a verified execution outcome on the action breaker."""
    try:
        breaker = get_breaker(action_type)
        if success:
            breaker.record_success(action_id)
        else:
            breaker.record_failure(action_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("record_breaker_outcome failed for %s: %s", action_type, exc)
