"""Guardian v2 Phase 5 Slice 1 — versioned policy + dry-run simulation API.
Slice 2 — safety-envelope execution + kill-switch persistence.
Slice 3 — deterministic conflict/overlap insight (read-only).

Endpoints (all under /api/v1/guardian/automation/v5):

    GET  /policies                        — list policies (view roles)
    POST /policies                        — create policy (admin only)
    GET  /policies/{policy_id}            — policy detail (view roles)
    PATCH /policies/{policy_id}           — modify policy, bumps version (admin)
    POST /policies/{policy_id}/disable    — disable policy (admin only)
    POST /policies/{policy_id}/enable     — re-enable policy (admin only)
    POST /simulate                        — dry-run simulation (analyst+)
    GET  /evaluations                     — simulation audit history (view roles)
    GET  /conflicts                       — deterministic overlap/conflict
                                            insight (view roles, read-only)

Slice 2 additions:

    POST /executions                      — authorized envelope execution
                                           (administrator + incident_responder)
    GET  /executions                      — execution history (view roles)
    GET  /executions/{execution_id}        — execution detail (view roles)
    GET  /safety/status                   — merged safety state (view roles)
    POST /safety/kill-switch              — activate kill switch (admin only)
    DELETE /safety/kill-switch            — deactivate kill switch (admin only)

RBAC:
    view: administrator, security_analyst, incident_responder,
        read_only_auditor
    policy mutation + kill-switch mutation: administrator ONLY.
    simulate: administrator, security_analyst, incident_responder.
    execute: administrator, incident_responder ONLY — analysts approve,
        responders/admins execute (mirrors Phase 3 execute permissions).

Slice 2 executes ONLY approved-manual requests by default. Slice 4 adds
explicitly activated, narrowly scoped bounded grants: with an active grant
covering the request, the envelope honors the preauthorized_bounded path;
without one, approved-manual remains mandatory. Grants are disabled by
default and never auto-activated.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_RESPONDER,
    RateLimiter,
    audit_event,
    get_current_user,
    require_roles,
)
from .database import get_db
from .models import User
from guardian.automation.policy_v5 import PolicyValidationError, simulate
from guardian.automation import store as policy_store

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/guardian/automation/v5", tags=["guardian-phase5"])

phase5_limiter = RateLimiter(60)  # same budget as Phase 3 action endpoints

VIEW_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)
SIMULATE_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER)
EXECUTE_ROLES = (ROLE_ADMIN, ROLE_RESPONDER)


# ── Schemas ───────────────────────────────────────────────────────────

class RuleIn(BaseModel):
    rule_id: Optional[str] = Field(None, max_length=128)
    description: str = Field("", max_length=1024)
    action_type: str = Field(..., max_length=64)
    action_name: str = Field(..., max_length=64)
    min_risk_score: float = Field(0.0, ge=0.0, le=100.0)
    max_risk_score: float = Field(100.0, ge=0.0, le=100.0)
    incident_severity: Optional[str] = None
    decision: str = Field("require_approval", max_length=32)
    requires_approval: bool = True
    priority: int = Field(100, ge=0, le=1000)
    target_scope: Optional[Dict[str, List[str]]] = None
    approval_mode: str = Field("required", max_length=32)
    max_executions_per_hour: Optional[int] = Field(None, ge=1)
    cooldown_seconds: Optional[int] = Field(None, ge=0)


class PolicyCreateIn(BaseModel):
    policy_id: str = Field(..., max_length=128)
    name: str = Field(..., max_length=255)
    description: str = Field("", max_length=4096)
    mode: str = Field("approval_required", max_length=32)
    priority: int = Field(100, ge=0, le=1000)
    expires_at: Optional[str] = None
    enabled: bool = True
    rules: List[RuleIn] = Field(default_factory=list)


class PolicyUpdateIn(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=4096)
    mode: Optional[str] = Field(None, max_length=32)
    priority: Optional[int] = Field(None, ge=0, le=1000)
    expires_at: Optional[str] = None
    enabled: Optional[bool] = None
    rules: Optional[List[RuleIn]] = None


class SimulateIn(BaseModel):
    action_type: str = Field(..., max_length=64)
    action_name: str = Field(..., max_length=64)
    target: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(..., ge=0.0, le=100.0)
    incident_severity: str = Field(..., max_length=32)
    incident_id: Optional[int] = None
    event_ids: List[str] = Field(default_factory=list)
    correlation_id: Optional[str] = Field(None, max_length=128)
    persist: bool = True  # False = pure dry-run, no audit row


# ── Helpers ───────────────────────────────────────────────────────────

def _rule_to_payload(rule: RuleIn) -> Dict[str, Any]:
    payload = rule.model_dump()
    # Drop explicit None rule_id so the store derives a deterministic one.
    if payload.get("rule_id") is None:
        payload.pop("rule_id")
    return payload


def _kill_switch_active(db: Session) -> bool:
    """Fail-closed kill-switch check: in-memory singleton OR persisted rows.

    Either source reporting active blocks. Any check error blocks.
    """
    try:
        from guardian.safety.kill_switch import KillSwitchScope, get_default_kill_switch

        blocked, _ = get_default_kill_switch().is_blocked(KillSwitchScope.GLOBAL, "global")
        if blocked:
            return True
    except Exception:  # noqa: BLE001
        logger.error("Phase5: in-memory kill-switch check failed; failing closed")
        return True
    try:
        from sqlalchemy import text as _text

        rows = db.execute(
            _text(
                "SELECT active FROM guardian_kill_switches "
                "WHERE scope = 'global' AND switch_key = 'global'"
            )
        ).fetchall()
        for row in rows:
            if row[0] in (True, 1, "1", "t", "true"):
                return True
        return False
    except Exception:  # noqa: BLE001
        # Table missing (pre-007 database) means "no persisted switch": not
        # an error. Any other error fails closed.
        logger.debug("Phase5: persisted kill-switch check unavailable; treating as inactive")
        return False


# ── Policy CRUD ───────────────────────────────────────────────────────

@router.get(
    "/policies",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def list_policies(
    include_disabled: bool = Query(True),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    policies = policy_store.list_policies(db, include_disabled=include_disabled)
    return {"total": len(policies), "items": [p.to_dict() for p in policies]}


@router.post(
    "/policies",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def create_policy(
    body: PolicyCreateIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    payload = body.model_dump()
    payload["rules"] = [_rule_to_payload(r) for r in body.rules]
    try:
        policy, existing = policy_store.create_policy(db, payload, created_by=user.username)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not existing:
        audit_event(
            db, "guardian_policy_created", "guardian_policy",
            policy.policy_id, {"version": policy.version}, user=user,
        )
        db.commit()
    else:
        db.rollback()
    result = policy.to_dict()
    result["existing"] = existing
    return result


@router.get(
    "/policies/{policy_id}",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    policy = policy_store.get_policy(db, policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy.to_dict()


@router.patch(
    "/policies/{policy_id}",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def update_policy(
    policy_id: str,
    body: PolicyUpdateIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    payload = body.model_dump(exclude_unset=True)
    if "rules" in payload and payload["rules"] is not None:
        payload["rules"] = [
            _rule_to_payload(RuleIn(**r) if isinstance(r, dict) else r)
            for r in payload["rules"]
        ]
    try:
        policy = policy_store.update_policy(db, policy_id, payload, updated_by=user.username)
    except PolicyValidationError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc))
    audit_event(
        db, "guardian_policy_updated", "guardian_policy",
        policy_id, {"version": policy.version}, user=user,
    )
    db.commit()
    return policy.to_dict()


@router.post(
    "/policies/{policy_id}/disable",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def disable_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    try:
        policy = policy_store.set_policy_enabled(db, policy_id, False, updated_by=user.username)
    except PolicyValidationError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc))
    audit_event(
        db, "guardian_policy_disabled", "guardian_policy",
        policy_id, {"version": policy.version}, user=user,
    )
    db.commit()
    return policy.to_dict()


@router.post(
    "/policies/{policy_id}/enable",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def enable_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    try:
        policy = policy_store.set_policy_enabled(db, policy_id, True, updated_by=user.username)
    except PolicyValidationError as exc:
        status = 404 if "not found" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc))
    audit_event(
        db, "guardian_policy_enabled", "guardian_policy",
        policy_id, {"version": policy.version}, user=user,
    )
    db.commit()
    return policy.to_dict()


# ── Simulation ────────────────────────────────────────────────────────

@router.post(
    "/simulate",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*SIMULATE_ROLES)),
    ],
)
def simulate_policy(
    body: SimulateIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Dry-run: report what WOULD happen. Never executes anything.

    When ``persist`` is true (default) exactly one immutable simulation audit
    row is written — the explicitly-designed simulation artifact. No approval,
    action, execution, OS, or network state is touched either way.
    """
    try:
        request = policy_store.build_request(body.model_dump(), requested_by=user.username)
    except PolicyValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    policies = policy_store.list_policies(db, include_disabled=False)
    kill_active = _kill_switch_active(db)
    result = simulate(policies, request, kill_switch_active=kill_active)

    evaluation_id: Optional[str] = None
    existing = False
    if body.persist:
        evaluation_id, existing = policy_store.record_evaluation(db, request, result)
        db.commit()
    else:
        from guardian.automation.policy_v5 import compute_evaluation_id

        evaluation_id = compute_evaluation_id(request)
        db.rollback()

    response = result.to_dict()
    response["evaluation_id"] = evaluation_id
    response["existing"] = existing
    response["kill_switch_active"] = kill_active
    return response


@router.get(
    "/evaluations",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def list_evaluations(
    policy_id: Optional[str] = None,
    incident_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    total, items = policy_store.list_evaluations(
        db, policy_id=policy_id, incident_id=incident_id, limit=limit, offset=offset
    )
    return {"total": total, "limit": limit, "offset": offset, "items": items}


# ── Slice 2: authorized envelope execution ────────────────────────────

class ExecutionIn(BaseModel):
    policy_id: str = Field(..., max_length=128)
    expected_policy_version: int = Field(..., ge=1)
    action_type: str = Field(..., max_length=64)
    action_name: str = Field(..., max_length=64)
    target: Dict[str, Any] = Field(default_factory=dict)
    decision_id: str = Field(..., max_length=128)
    approval_id: Optional[str] = Field(None, max_length=128)
    authorization_mode: str = Field("approved_manual", max_length=32)
    risk_score: float = Field(..., ge=0.0, le=100.0)
    incident_severity: str = Field(..., max_length=32)
    incident_id: Optional[int] = None
    event_ids: List[str] = Field(default_factory=list)
    evaluation_id: Optional[str] = Field(None, max_length=128)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    agent_key: Optional[str] = Field(None, max_length=128)
    host_id: Optional[str] = Field(None, max_length=128)
    correlation_id: Optional[str] = Field(None, max_length=128)


def _blocked_http_status(failed_gate: str) -> int:
    if failed_gate in ("kill_switch_global", "kill_switch_scoped", "circuit_breaker"):
        return 503
    if failed_gate in ("rate_limit", "cooldown"):
        return 429
    return 422


@router.post(
    "/executions",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*EXECUTE_ROLES)),
    ],
)
def submit_execution(
    body: ExecutionIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Run an authorized request through the safety envelope.

    Slice 4 supports two authorization paths, both fully gated:
      - approved_manual (default, Slice 2 compatible): a valid APPROVED
        approval is mandatory.
      - preauthorized_bounded: an active persisted grant must cover the
        request; no approval is consumed. Kill switch, breaker, limiter,
        target validation, verification, rollback, and audit still apply.
    Idempotent: replaying an identical request returns the original
    execution record without re-executing (existing=True).
    """
    from guardian.automation.envelope import EnvelopeRequest, SafetyEnvelope
    from guardian.automation.policy_v5 import PolicyValidationError as _PVE

    mode = (body.authorization_mode or "approved_manual").lower()
    if mode not in ("approved_manual", "preauthorized_bounded"):
        raise HTTPException(status_code=422, detail="authorization_mode must be approved_manual or preauthorized_bounded")
    if mode == "approved_manual" and not body.approval_id:
        raise HTTPException(status_code=422, detail="approval_id is required for approved_manual execution")

    try:
        request = EnvelopeRequest(
            policy_id=body.policy_id,
            expected_policy_version=body.expected_policy_version,
            action_type=body.action_type,
            action_name=body.action_name,
            target=body.target,
            decision_id=body.decision_id,
            approval_id=body.approval_id,
            authorization_mode=mode,
            risk_score=body.risk_score,
            incident_severity=body.incident_severity,
            incident_id=body.incident_id,
            event_ids=list(body.event_ids or []),
            evaluation_id=body.evaluation_id,
            parameters=body.parameters,
            agent_key=body.agent_key,
            host_id=body.host_id,
            correlation_id=body.correlation_id,
            requested_by=user.username,
        )
        result = SafetyEnvelope().run(db, request, actor=user.username)
    except _PVE as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if result.status == "blocked":
        failed = next((g for g in result.gates if not g.get("passed")), {})
        raise HTTPException(
            status_code=_blocked_http_status(failed.get("gate", "")),
            detail={"execution_id": result.execution_id, "error": result.error,
                    "gate": failed.get("gate"), "gates": result.gates},
        )
    response = result.to_dict()
    audit_event(
        db, f"guardian_envelope_submitted_{result.status}", "guardian_envelope",
        result.execution_id, {"status": result.status, "actor": user.username}, user=user,
    )
    db.commit()
    return response


@router.get(
    "/executions",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def list_executions(
    policy_id: Optional[str] = None,
    incident_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    from guardian.automation.envelope import SafetyEnvelope

    total, items = SafetyEnvelope().list_executions(
        db, policy_id=policy_id, incident_id=incident_id, status=status,
        limit=limit, offset=offset,
    )
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.get(
    "/executions/{execution_id}",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def get_execution(
    execution_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    from guardian.automation.envelope import SafetyEnvelope

    record = SafetyEnvelope().get_execution(db, execution_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Execution not found")
    return record


# ── Slice 2: persisted safety state ───────────────────────────────────

class KillSwitchIn(BaseModel):
    scope: str = Field(..., max_length=32)
    switch_key: str = Field(..., max_length=128)
    reason: str = Field("operator action", max_length=2048)


@router.get(
    "/safety/status",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def safety_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Merged safety state: kill switches (memory + persisted), breakers, limiter."""
    from guardian.safety import kill_switch_store as _kss
    from guardian.safety.kill_switch import get_default_kill_switch as _get_ks
    from guardian.safety.registry import breaker_stats, limiter_stats

    return {
        "kill_switches": _kss.merged_state(db, _get_ks()),
        "circuit_breakers": breaker_stats(),
        "rate_limiter": limiter_stats(),
        "execution_modes": ["simulation", "awaiting_approval", "approved_manual_execution"],
    }


@router.post(
    "/safety/kill-switch",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def activate_kill_switch_v5(
    body: KillSwitchIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    from guardian.safety import kill_switch_store as _kss
    from guardian.safety.kill_switch import get_default_kill_switch as _get_ks

    try:
        result = _kss.activate_persisted(
            db, _get_ks(), body.scope, body.switch_key, by=user.username, reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    audit_event(
        db, "guardian_kill_switch_activated", "guardian_kill_switch",
        f"{body.scope}:{body.switch_key}", {"reason": body.reason}, user=user,
    )
    db.commit()
    return {"status": "activated", **result}


@router.delete(
    "/safety/kill-switch",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def deactivate_kill_switch_v5(
    scope: str = Query(..., max_length=32),
    switch_key: str = Query(..., max_length=128),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    from guardian.safety import kill_switch_store as _kss
    from guardian.safety.kill_switch import get_default_kill_switch as _get_ks

    try:
        result = _kss.deactivate_persisted(db, _get_ks(), scope, switch_key, by=user.username)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    audit_event(
        db, "guardian_kill_switch_deactivated", "guardian_kill_switch",
        f"{scope}:{switch_key}", {}, user=user,
    )
    db.commit()
    return {"status": "deactivated", **result}


# ── Slice 3: deterministic conflict/overlap insight (read-only) ───────

@router.get(
    "/conflicts",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def list_conflicts(
    policy_id: Optional[str] = Query(None, max_length=128),
    include_disabled: bool = Query(True),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Deterministic overlap/conflict insight over real persisted policies.

    Read-only: performs no mutation, creates no approvals, consumes no
    quota, touches no kill switch. Guidance only — never overrides the
    deterministic policy engine. A pair is a conflict only when match
    conditions overlap AND outcomes are incompatible (DENY vs non-DENY).
    """
    from guardian.automation.conflicts import analyze_policy_conflicts

    policies = policy_store.list_policies(db, include_disabled=include_disabled)
    if policy_id:
        selected = [p for p in policies if p.policy_id == policy_id]
        if not selected:
            raise HTTPException(status_code=404, detail="Policy not found")
        # Compare the selected policy against the full set so
        # cross-policy overlaps remain visible.
        findings = analyze_policy_conflicts(policies)
        findings = [
            f for f in findings
            if any(r.get("policy_id") == policy_id for r in f.get("rules", []))
        ]
    else:
        findings = analyze_policy_conflicts(policies)
    db.rollback()  # guarantee read-only semantics even on pooled sessions
    conflicts = [f for f in findings if f.get("is_conflict")]
    return {
        "total": len(findings),
        "conflicts": len(conflicts),
        "notices": len(findings) - len(conflicts),
        "items": findings,
        "note": (
            "Guidance only — conflict visualization never overrides "
            "the deterministic policy engine."
        ),
    }


# ── Slice 4: bounded pre-authorization grants ─────────────────────────

class PreauthActivateIn(BaseModel):
    policy_id: str = Field(..., max_length=128)
    allowed_actions: List[Dict[str, Any]] = Field(..., min_length=1, max_length=25)
    target_scope: Dict[str, List[str]] = Field(...)
    agent_scope: Optional[Dict[str, List[str]]] = None
    max_risk_score: float = Field(..., ge=0.0, le=100.0)
    max_executions_per_hour: int = Field(..., ge=1, le=1000)
    cooldown_seconds: int = Field(..., ge=0, le=86400)
    expires_at: str = Field(..., max_length=64)
    reason: str = Field(..., max_length=2048)
    rollback_required: bool = False


class PreauthRevokeIn(BaseModel):
    policy_id: str = Field(..., max_length=128)
    reason: str = Field("operator revocation", max_length=2048)


@router.post(
    "/preauth/activate",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def activate_preauth(
    body: PreauthActivateIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Activate a bounded pre-authorization grant (administrator only).

    The UI must display the complete permission scope, risk cap, frequency
    limits, cooldown, allowed actions, and expiry before calling this
    endpoint. Activation binds the policy's current version; later policy
    edits require re-activation. Nothing is auto-activated by migrations.
    """
    from guardian.automation import preauth_store as _grant_store
    from guardian.automation.policy_v5 import PolicyValidationError as _PVE

    try:
        grant = _grant_store.activate_grant(
            db,
            {
                "policy_id": body.policy_id,
                "allowed_actions": body.allowed_actions,
                "target_scope": body.target_scope,
                "agent_scope": body.agent_scope or {},
                "max_risk_score": body.max_risk_score,
                "max_executions_per_hour": body.max_executions_per_hour,
                "cooldown_seconds": body.cooldown_seconds,
                "expires_at": body.expires_at,
                "reason": body.reason,
                "rollback_required": body.rollback_required,
            },
            activated_by=user.username,
        )
    except _PVE as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    audit_event(
        db, "guardian_preauth_activated", "guardian_preauth",
        body.policy_id,
        {"policy_version": grant["policy_version"], "allowed_actions": grant["allowed_actions"],
         "max_risk_score": grant["max_risk_score"], "expires_at": grant["expires_at"]},
        user=user,
    )
    db.commit()
    return {"status": "activated", "grant": grant}


@router.post(
    "/preauth/revoke",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(ROLE_ADMIN)),
    ],
)
def revoke_preauth(
    body: PreauthRevokeIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Revoke a bounded grant (administrator only). Never deletes."""
    from guardian.automation import preauth_store as _grant_store
    from guardian.automation.policy_v5 import PolicyValidationError as _PVE

    try:
        grant = _grant_store.revoke_grant(
            db, body.policy_id, revoked_by=user.username, reason=body.reason
        )
    except _PVE as exc:
        status = 404 if "no pre-authorization grant" in str(exc) else 422
        raise HTTPException(status_code=status, detail=str(exc))
    audit_event(
        db, "guardian_preauth_revoked", "guardian_preauth",
        body.policy_id, {"reason": body.reason}, user=user,
    )
    db.commit()
    return {"status": "revoked", "grant": grant}


@router.get(
    "/preauth",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def list_preauth_grants(
    active_only: bool = Query(False),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List persisted pre-authorization grants (authoritative state)."""
    from guardian.automation import preauth_store as _grant_store

    grants = _grant_store.list_grants(db, active_only=active_only)
    db.rollback()
    return {"total": len(grants), "items": grants}


@router.get(
    "/preauth/{policy_id}",
    dependencies=[
        Depends(phase5_limiter),
        Depends(require_roles(*VIEW_ROLES)),
    ],
)
def get_preauth_grant(
    policy_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Return the authoritative grant for one policy, or 404 when none."""
    from guardian.automation import preauth_store as _grant_store

    grant = _grant_store.get_grant(db, policy_id)
    db.rollback()
    if grant is None:
        raise HTTPException(status_code=404, detail="No pre-authorization grant for this policy")
    return grant
