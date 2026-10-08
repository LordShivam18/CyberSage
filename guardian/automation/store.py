"""Guardian v2 Phase 5 Slice 1 — versioned policy persistence.

CRUD + versioning + enable/disable + evaluation audit for automation
policies, backed by the Phase 4 tables (extended by migration 008) and the
``guardian_policy_evaluations`` simulation audit table.

Rules enforced here:
  - Strict validation of every policy/rule/scope before any write.
  - Idempotent creation: re-creating an existing policy_id returns the
    existing row (``existing=True``) instead of duplicating it.
  - Versioning: every modification bumps ``version`` by exactly 1 and stamps
    ``updated_by``; evaluations record the version they evaluated so stale
    decisions are detectable.
  - Expiration/disable never delete: rows stay for audit; evaluation skips
    them deterministically.
  - Evaluation audit rows are immutable once written (no update path).
  - This layer never executes actions, never touches the OS/network, and
    never creates approvals — it only persists policy data and simulation
    audit records.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from guardian.automation.policy import AutomationMode, PolicyDecision
from guardian.automation.policy_v5 import (
    ApprovalMode,
    AutomationPolicyV5,
    EvaluationRequest,
    EvaluationResult,
    PolicyRuleV5,
    PolicyValidationError,
    compute_evaluation_id,
    validate_policy,
    validate_request,
    validate_scope,
)

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_mode(value: Any) -> AutomationMode:
    if isinstance(value, AutomationMode):
        return value
    try:
        return AutomationMode(str(value))
    except ValueError:
        raise PolicyValidationError(
            f"mode must be one of {[m.value for m in AutomationMode]}"
        )


def _parse_decision(value: Any) -> PolicyDecision:
    if isinstance(value, PolicyDecision):
        return value
    try:
        return PolicyDecision(str(value))
    except ValueError:
        raise PolicyValidationError(
            f"decision must be one of {[d.value for d in PolicyDecision]}"
        )


def _parse_approval_mode(value: Any) -> ApprovalMode:
    if isinstance(value, ApprovalMode):
        return value
    try:
        return ApprovalMode(str(value))
    except ValueError:
        raise PolicyValidationError(
            f"approval_mode must be one of {[m.value for m in ApprovalMode]}"
        )


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise PolicyValidationError(f"Invalid datetime: {value!r}")
    raise PolicyValidationError(f"Invalid datetime: {value!r}")


def deterministic_rule_id(policy_id: str, payload: Dict[str, Any]) -> str:
    """Deterministic rule id so re-POSTs of identical rules are idempotent."""
    import json as _json

    fingerprint = _json.dumps(
        {"policy_id": policy_id, **{k: payload.get(k) for k in sorted(payload.keys())}},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"r-{hashlib.sha256(fingerprint.encode()).hexdigest()[:12]}"


def build_rule(payload: Dict[str, Any], policy_id: str) -> PolicyRuleV5:
    """Build and validate a PolicyRuleV5 from a plain dict. Fail closed."""
    if not isinstance(payload, dict):
        raise PolicyValidationError("rule must be an object")
    rule_id = payload.get("rule_id") or deterministic_rule_id(policy_id, payload)
    rule = PolicyRuleV5(
        rule_id=rule_id,
        description=payload.get("description", ""),
        action_type=payload.get("action_type", ""),
        action_name=payload.get("action_name", ""),
        min_risk_score=float(payload.get("min_risk_score", 0.0)),
        max_risk_score=float(payload.get("max_risk_score", 100.0)),
        incident_severity=payload.get("incident_severity"),
        decision=_parse_decision(payload.get("decision", PolicyDecision.REQUIRE_APPROVAL.value)),
        requires_approval=bool(payload.get("requires_approval", True)),
        priority=int(payload.get("priority", 100)),
        target_scope=validate_scope(payload.get("target_scope")),
        approval_mode=_parse_approval_mode(payload.get("approval_mode", ApprovalMode.REQUIRED.value)),
        max_executions_per_hour=payload.get("max_executions_per_hour"),
        cooldown_seconds=payload.get("cooldown_seconds"),
    )
    # validate_rule runs inside validate_policy too; run here for early errors.
    from guardian.automation.policy_v5 import validate_rule

    validate_rule(rule)
    return rule


def build_policy(payload: Dict[str, Any]) -> AutomationPolicyV5:
    """Build and validate an AutomationPolicyV5 from a plain dict."""
    if not isinstance(payload, dict):
        raise PolicyValidationError("policy must be an object")
    rules_payload = payload.get("rules", [])
    if not isinstance(rules_payload, list):
        raise PolicyValidationError("rules must be a list")
    policy_id = payload.get("policy_id", "")
    rules = [build_rule(r, policy_id) for r in rules_payload]
    policy = AutomationPolicyV5(
        policy_id=policy_id,
        name=payload.get("name", ""),
        description=payload.get("description", ""),
        mode=_parse_mode(payload.get("mode", AutomationMode.APPROVAL_REQUIRED.value)),
        enabled=bool(payload.get("enabled", True)),
        version=int(payload.get("version", 1)),
        priority=int(payload.get("priority", 100)),
        expires_at=_parse_datetime(payload.get("expires_at")),
        rules=rules,
    )
    validate_policy(policy)
    return policy


def build_request(payload: Dict[str, Any], requested_by: str) -> EvaluationRequest:
    """Build and validate an EvaluationRequest from a plain dict."""
    if not isinstance(payload, dict):
        raise PolicyValidationError("simulation request must be an object")
    request = EvaluationRequest(
        action_type=payload.get("action_type", ""),
        action_name=payload.get("action_name", ""),
        target=payload.get("target", {}),
        risk_score=payload.get("risk_score", 0.0),
        incident_severity=payload.get("incident_severity", ""),
        incident_id=payload.get("incident_id"),
        event_ids=list(payload.get("event_ids", []) or []),
        requested_by=requested_by,
        correlation_id=payload.get("correlation_id"),
    )
    validate_request(request)
    return request


# ── Row <-> domain mapping ────────────────────────────────────────────

def _row_to_policy(policy_row: Any, rule_rows: List[Any]) -> AutomationPolicyV5:
    rules = []
    for r in sorted(rule_rows, key=lambda x: x.rule_id):
        rules.append(
            PolicyRuleV5(
                rule_id=r.rule_id,
                description=r.description or "",
                action_type=r.action_type,
                action_name=r.action_name,
                min_risk_score=float(r.min_risk_score),
                max_risk_score=float(r.max_risk_score),
                incident_severity=r.incident_severity,
                decision=_parse_decision(r.decision),
                requires_approval=bool(r.requires_approval),
                priority=int(r.priority if r.priority is not None else 100),
                target_scope=r.target_scope or {},
                approval_mode=_parse_approval_mode(r.approval_mode or "required"),
                max_executions_per_hour=r.max_executions_per_hour,
                cooldown_seconds=r.cooldown_seconds,
            )
        )
    return AutomationPolicyV5(
        policy_id=policy_row.policy_id,
        name=policy_row.name,
        description=policy_row.description or "",
        mode=_parse_mode(policy_row.mode),
        enabled=bool(policy_row.enabled),
        version=int(policy_row.version or 1),
        priority=int(policy_row.priority if policy_row.priority is not None else 100),
        expires_at=policy_row.expires_at,
        rules=rules,
        created_at=policy_row.created_at,
        updated_at=policy_row.updated_at,
    )


# ── CRUD ──────────────────────────────────────────────────────────────

def create_policy(
    session: Session, payload: Dict[str, Any], created_by: str
) -> Tuple[AutomationPolicyV5, bool]:
    """Create a policy. Idempotent: existing policy_id returns (policy, True)."""
    from backend.models import GuardianAutomationPolicy, GuardianAutomationRule

    policy = build_policy(payload)
    existing = session.query(GuardianAutomationPolicy).filter(
        GuardianAutomationPolicy.policy_id == policy.policy_id
    ).first()
    if existing:
        rule_rows = session.query(GuardianAutomationRule).filter(
            GuardianAutomationRule.policy_id == policy.policy_id
        ).all()
        return _row_to_policy(existing, rule_rows), True

    now = _now_utc()
    row = GuardianAutomationPolicy(
        policy_id=policy.policy_id,
        name=policy.name,
        description=policy.description,
        mode=policy.mode.value,
        enabled=policy.enabled,
        version=1,
        priority=policy.priority,
        expires_at=policy.expires_at,
        updated_by=created_by,
        created_at=now,
        updated_at=now,
    )
    session.add(row)
    session.flush()
    for rule in policy.rules:
        session.add(
            GuardianAutomationRule(
                policy_id=policy.policy_id,
                rule_id=rule.rule_id,
                description=rule.description,
                action_type=rule.action_type,
                action_name=rule.action_name,
                min_risk_score=float(rule.min_risk_score),
                max_risk_score=float(rule.max_risk_score),
                incident_severity=rule.incident_severity,
                decision=rule.decision.value,
                requires_approval=rule.requires_approval,
                priority=rule.priority,
                target_scope=rule.target_scope or {},
                approval_mode=rule.approval_mode.value,
                max_executions_per_hour=rule.max_executions_per_hour,
                cooldown_seconds=rule.cooldown_seconds,
            )
        )
    session.flush()
    logger.info("PolicyStore: created policy %s v1 by %s", policy.policy_id, created_by)
    rule_rows = session.query(GuardianAutomationRule).filter(
        GuardianAutomationRule.policy_id == policy.policy_id
    ).all()
    created = session.query(GuardianAutomationPolicy).filter(
        GuardianAutomationPolicy.policy_id == policy.policy_id
    ).first()
    return _row_to_policy(created, rule_rows), False


def get_policy(session: Session, policy_id: str) -> Optional[AutomationPolicyV5]:
    """Fetch one policy with its rules, or None."""
    from backend.models import GuardianAutomationPolicy, GuardianAutomationRule

    row = session.query(GuardianAutomationPolicy).filter(
        GuardianAutomationPolicy.policy_id == policy_id
    ).first()
    if not row:
        return None
    rule_rows = session.query(GuardianAutomationRule).filter(
        GuardianAutomationRule.policy_id == policy_id
    ).all()
    return _row_to_policy(row, rule_rows)


def list_policies(
    session: Session, *, include_disabled: bool = True
) -> List[AutomationPolicyV5]:
    """List all policies (deterministic order by policy_id)."""
    from backend.models import GuardianAutomationPolicy, GuardianAutomationRule

    query = session.query(GuardianAutomationPolicy).order_by(
        GuardianAutomationPolicy.policy_id.asc()
    )
    if not include_disabled:
        query = query.filter(GuardianAutomationPolicy.enabled.is_(True))
    policies = []
    for row in query.all():
        rule_rows = session.query(GuardianAutomationRule).filter(
            GuardianAutomationRule.policy_id == row.policy_id
        ).all()
        policies.append(_row_to_policy(row, rule_rows))
    return policies


def update_policy(
    session: Session, policy_id: str, payload: Dict[str, Any], updated_by: str
) -> AutomationPolicyV5:
    """Modify a policy. Bumps version by exactly 1. Rules replace-all when given."""
    from backend.models import GuardianAutomationPolicy, GuardianAutomationRule

    if not isinstance(payload, dict):
        raise PolicyValidationError("update payload must be an object")
    row = session.query(GuardianAutomationPolicy).filter(
        GuardianAutomationPolicy.policy_id == policy_id
    ).first()
    if not row:
        raise PolicyValidationError(f"policy '{policy_id}' not found")

    current_rules = session.query(GuardianAutomationRule).filter(
        GuardianAutomationRule.policy_id == policy_id
    ).all()
    current = _row_to_policy(row, current_rules)

    # Apply scalar updates.
    if "name" in payload:
        current.name = payload["name"]
    if "description" in payload:
        current.description = payload["description"]
    if "mode" in payload:
        current.mode = _parse_mode(payload["mode"])
    if "priority" in payload:
        current.priority = int(payload["priority"])
    if "expires_at" in payload:
        current.expires_at = _parse_datetime(payload["expires_at"])
    if "enabled" in payload:
        current.enabled = bool(payload["enabled"])
    if "rules" in payload:
        if not isinstance(payload["rules"], list):
            raise PolicyValidationError("rules must be a list")
        current.rules = [build_rule(r, policy_id) for r in payload["rules"]]
    current.version = int(row.version or 1) + 1
    validate_policy(current)

    row.name = current.name
    row.description = current.description
    row.mode = current.mode.value
    row.priority = current.priority
    row.expires_at = current.expires_at
    row.enabled = current.enabled
    row.version = current.version
    row.updated_by = updated_by
    row.updated_at = _now_utc()

    if "rules" in payload:
        session.query(GuardianAutomationRule).filter(
            GuardianAutomationRule.policy_id == policy_id
        ).delete(synchronize_session=False)
        for rule in current.rules:
            session.add(
                GuardianAutomationRule(
                    policy_id=policy_id,
                    rule_id=rule.rule_id,
                    description=rule.description,
                    action_type=rule.action_type,
                    action_name=rule.action_name,
                    min_risk_score=float(rule.min_risk_score),
                    max_risk_score=float(rule.max_risk_score),
                    incident_severity=rule.incident_severity,
                    decision=rule.decision.value,
                    requires_approval=rule.requires_approval,
                    priority=rule.priority,
                    target_scope=rule.target_scope or {},
                    approval_mode=rule.approval_mode.value,
                    max_executions_per_hour=rule.max_executions_per_hour,
                    cooldown_seconds=rule.cooldown_seconds,
                )
            )
    session.flush()
    logger.info(
        "PolicyStore: updated policy %s to v%d by %s", policy_id, current.version, updated_by
    )
    rule_rows = session.query(GuardianAutomationRule).filter(
        GuardianAutomationRule.policy_id == policy_id
    ).all()
    return _row_to_policy(row, rule_rows)


def set_policy_enabled(
    session: Session, policy_id: str, enabled: bool, updated_by: str
) -> AutomationPolicyV5:
    """Enable/disable a policy. Disabling never deletes (audit preserved)."""
    from backend.models import GuardianAutomationPolicy

    row = session.query(GuardianAutomationPolicy).filter(
        GuardianAutomationPolicy.policy_id == policy_id
    ).first()
    if not row:
        raise PolicyValidationError(f"policy '{policy_id}' not found")
    row.enabled = enabled
    row.version = int(row.version or 1) + 1
    row.updated_by = updated_by
    row.updated_at = _now_utc()
    session.flush()
    logger.info(
        "PolicyStore: policy %s %s (v%d) by %s",
        policy_id, "enabled" if enabled else "disabled", row.version, updated_by,
    )
    policy = get_policy(session, policy_id)
    assert policy is not None
    return policy


# ── Evaluation audit ──────────────────────────────────────────────────

def record_evaluation(
    session: Session,
    request: EvaluationRequest,
    result: EvaluationResult,
) -> Tuple[str, bool]:
    """Persist an immutable simulation audit record. Idempotent on evaluation_id.

    Returns (evaluation_id, existing). This row is the explicitly-designed
    simulation artifact: it records what a simulation concluded and never
    represents real execution.
    """
    from backend.models import GuardianPolicyEvaluation

    evaluation_id = compute_evaluation_id(request)
    existing = session.query(GuardianPolicyEvaluation).filter(
        GuardianPolicyEvaluation.evaluation_id == evaluation_id
    ).first()
    if existing:
        return evaluation_id, True
    session.add(
        GuardianPolicyEvaluation(
            evaluation_id=evaluation_id,
            policy_id=result.matched_policy_id,
            policy_version=result.matched_policy_version,
            matched_rule_id=result.matched_rule_id,
            incident_id=request.incident_id,
            event_ids=list(request.event_ids),
            risk_score=float(request.risk_score),
            incident_severity=request.incident_severity,
            action_type=request.action_type,
            action_name=request.action_name,
            target=dict(request.target),
            decision=result.decision.value,
            reason=result.reason,
            approval_mode=result.approval_mode.value,
            would_execute=False,  # Slice 1 never executes
            blocked_reason=result.blocked_reason,
            safety_checks=list(result.safety_checks),
            requested_by=request.requested_by,
            correlation_id=request.correlation_id,
        )
    )
    session.flush()
    return evaluation_id, False


def list_evaluations(
    session: Session,
    *,
    policy_id: Optional[str] = None,
    incident_id: Optional[int] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[int, List[Dict[str, Any]]]:
    """List simulation audit records (newest first)."""
    from backend.models import GuardianPolicyEvaluation

    query = session.query(GuardianPolicyEvaluation)
    if policy_id:
        query = query.filter(GuardianPolicyEvaluation.policy_id == policy_id)
    if incident_id is not None:
        query = query.filter(GuardianPolicyEvaluation.incident_id == incident_id)
    total = query.count()
    rows = (
        query.order_by(GuardianPolicyEvaluation.created_at.desc())
        .offset(offset)
        .limit(min(max(limit, 1), 500))
        .all()
    )
    items = [
        {
            "evaluation_id": r.evaluation_id,
            "policy_id": r.policy_id,
            "policy_version": r.policy_version,
            "matched_rule_id": r.matched_rule_id,
            "incident_id": r.incident_id,
            "event_ids": r.event_ids,
            "risk_score": r.risk_score,
            "incident_severity": r.incident_severity,
            "action_type": r.action_type,
            "action_name": r.action_name,
            "target": r.target,
            "decision": r.decision,
            "reason": r.reason,
            "approval_mode": r.approval_mode,
            "would_execute": bool(r.would_execute),
            "blocked_reason": r.blocked_reason,
            "safety_checks": r.safety_checks,
            "requested_by": r.requested_by,
            "correlation_id": r.correlation_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
    return total, items
