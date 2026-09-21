"""Guardian v2 Phase 4 — Automation Policy Engine.

Automation must NEVER bypass approval unless an explicit policy permits it.
Default: approval required.

Every automation run is:
  - Authenticated
  - Authorized
  - Deterministic
  - Bounded
  - Auditable
  - Replay-safe
  - Kill-switchable

No arbitrary AI-generated commands execute through this engine.
The deterministic PolicyEngine is authoritative.
"""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────


class AutomationMode(str, enum.Enum):
    """Automation execution mode."""
    DISABLED = "disabled"       # No automated actions
    PREPARE_ONLY = "prepare_only"  # Prepare actions but don't execute
    APPROVAL_REQUIRED = "approval_required"  # Execute only after approval (default)
    # NOTE: FULLY_AUTOMATED is intentionally absent from Phase 4.
    # Future mode requiring explicit policy opt-in per action type.


class PolicyDecision(str, enum.Enum):
    """Result of PolicyEngine evaluation."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    PREPARE_ONLY = "prepare_only"


class AutomationRunStatus(str, enum.Enum):
    """Status of an automation run."""
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


# ── Data Models ────────────────────────────────────────────────────────


@dataclass
class AutomationRule:
    """A single rule within an automation policy.

    Rules are evaluated in order. The first matching rule wins.
    If no rule matches, the policy default applies.
    """
    rule_id: str
    description: str
    action_type: str          # e.g. "process", "network", "*" (wildcard)
    action_name: str          # e.g. "terminate_process", "*"
    min_risk_score: float = 0.0
    max_risk_score: float = 100.0
    incident_severity: Optional[str] = None   # "low"|"medium"|"high"|"critical"|None (any)
    decision: PolicyDecision = PolicyDecision.REQUIRE_APPROVAL
    requires_approval: bool = True  # Explicit — never inferred from decision alone


@dataclass
class AutomationPolicy:
    """Automation policy governing when automated actions may execute.

    Default mode is APPROVAL_REQUIRED — automation cannot bypass approval
    without an explicit policy rule that sets requires_approval=False AND
    the policy mode permits it.
    """
    policy_id: str
    name: str
    description: str
    mode: AutomationMode = AutomationMode.APPROVAL_REQUIRED
    rules: List[AutomationRule] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "mode": self.mode.value,
            "enabled": self.enabled,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "description": r.description,
                    "action_type": r.action_type,
                    "action_name": r.action_name,
                    "min_risk_score": r.min_risk_score,
                    "max_risk_score": r.max_risk_score,
                    "incident_severity": r.incident_severity,
                    "decision": r.decision.value,
                    "requires_approval": r.requires_approval,
                }
                for r in self.rules
            ],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class AutomationRunRequest:
    """Parameters for a new automation run."""
    action_type: str
    action_name: str
    target: Dict[str, Any]
    incident_id: Optional[int]
    decision_id: str
    risk_score: float
    incident_severity: str
    requested_by: str
    rationale: str
    policy_id: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutomationRun:
    """Record of a single automation run.

    Idempotent: same run_id always refers to the same logical run.
    Replay-safe: submitting the same run twice returns the original.
    """
    run_id: str
    policy_id: Optional[str]
    action_type: str
    action_name: str
    target: Dict[str, Any]
    incident_id: Optional[int]
    decision_id: str
    risk_score: float
    incident_severity: str
    requested_by: str
    rationale: str
    status: AutomationRunStatus
    policy_decision: PolicyDecision
    requires_approval: bool
    approval_id: Optional[str]
    parameters: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "policy_id": self.policy_id,
            "action_type": self.action_type,
            "action_name": self.action_name,
            "target": self.target,
            "incident_id": self.incident_id,
            "decision_id": self.decision_id,
            "risk_score": self.risk_score,
            "incident_severity": self.incident_severity,
            "requested_by": self.requested_by,
            "rationale": self.rationale,
            "status": self.status.value,
            "policy_decision": self.policy_decision.value,
            "requires_approval": self.requires_approval,
            "approval_id": self.approval_id,
            "parameters": self.parameters,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "error": self.error,
            "result": self.result,
        }


# ── Policy Engine ──────────────────────────────────────────────────────


class PolicyEngine:
    """Deterministic automation policy evaluation engine.

    The PolicyEngine is authoritative — AI output may suggest actions
    but cannot directly instruct the engine to bypass approval.

    Rules:
        1. If the kill switch is active → DENY
        2. If the policy is disabled or mode=DISABLED → DENY
        3. If mode=PREPARE_ONLY → PREPARE_ONLY (no execution)
        4. Evaluate rules in order; first match wins
        5. If no rule matches → default is REQUIRE_APPROVAL
        6. requires_approval=True is enforced regardless of decision field

    AI boundary:
        AI may call evaluate() with a suggested action.
        AI may NEVER:
          - modify the policy
          - alter RBAC
          - override requires_approval
          - fabricate a PolicyDecision
    """

    def evaluate(
        self,
        policy: AutomationPolicy,
        *,
        action_type: str,
        action_name: str,
        risk_score: float,
        incident_severity: str,
        kill_switch_active: bool = False,
    ) -> Tuple[PolicyDecision, str]:
        """Evaluate a potential automated action against a policy.

        Returns:
            Tuple of (decision, reason_string).
        """
        # 1. Kill switch — hard deny
        if kill_switch_active:
            return PolicyDecision.DENY, "kill_switch_active"

        # 2. Policy disabled or DISABLED mode
        if not policy.enabled:
            return PolicyDecision.DENY, "policy_disabled"

        if policy.mode == AutomationMode.DISABLED:
            return PolicyDecision.DENY, "policy_mode_disabled"

        # 3. Prepare-only mode — never execute
        if policy.mode == AutomationMode.PREPARE_ONLY:
            return PolicyDecision.PREPARE_ONLY, "policy_mode_prepare_only"

        # 4. Evaluate rules in order
        for rule in policy.rules:
            if self._rule_matches(rule, action_type, action_name, risk_score, incident_severity):
                decision = rule.decision
                # Safety override: requires_approval=True always means REQUIRE_APPROVAL
                # regardless of what the decision field says
                if rule.requires_approval and decision == PolicyDecision.ALLOW:
                    decision = PolicyDecision.REQUIRE_APPROVAL
                return decision, f"rule:{rule.rule_id}"

        # 5. Default
        return PolicyDecision.REQUIRE_APPROVAL, "default_policy"

    def _rule_matches(
        self,
        rule: AutomationRule,
        action_type: str,
        action_name: str,
        risk_score: float,
        incident_severity: str,
    ) -> bool:
        """Return True if the rule matches the proposed action."""
        # Action type match (wildcard "*" matches any)
        if rule.action_type != "*" and rule.action_type != action_type:
            return False
        # Action name match (wildcard "*" matches any)
        if rule.action_name != "*" and rule.action_name != action_name:
            return False
        # Risk score range
        if not (rule.min_risk_score <= risk_score <= rule.max_risk_score):
            return False
        # Severity match (None = any)
        if rule.incident_severity is not None and rule.incident_severity != incident_severity:
            return False
        return True


def compute_run_id(
    action_type: str,
    action_name: str,
    target: Dict[str, Any],
    decision_id: str,
) -> str:
    """Compute a deterministic, idempotent run ID.

    Same inputs always produce the same run_id.
    Changing action_type, action_name, target, or decision_id
    always produces a different run_id.
    """
    fingerprint = json.dumps(
        {
            "action_type": action_type,
            "action_name": action_name,
            "target": target,
            "decision_id": decision_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(fingerprint.encode()).hexdigest()[:32]
    return f"run-{digest}"


# ── Default safe policy ────────────────────────────────────────────────

DEFAULT_POLICY = AutomationPolicy(
    policy_id="default",
    name="Default Policy",
    description=(
        "Default automation policy — all automated actions require explicit approval. "
        "No automated execution without operator approval."
    ),
    mode=AutomationMode.APPROVAL_REQUIRED,
    rules=[],  # No rules — default decision applies (REQUIRE_APPROVAL)
    enabled=True,
)
