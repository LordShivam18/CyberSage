"""Guardian v2 Phase 5 Slice 4 — persisted pre-authorization grant store.

Activation and revocation are explicit administrator operations, persisted
and auditable. Reads consult the authoritative row per request (no cache),
so policy updates, expiry, revocation, and restarts cannot preserve stale
authorization. This layer never executes actions and takes no AI input.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from guardian.automation.policy_v5 import PolicyValidationError
from guardian.automation.preauth import validate_grant_bounds

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _row_to_dict(row: Any) -> Dict[str, Any]:
    return {
        "policy_id": row.policy_id,
        "policy_version": int(row.policy_version),
        "active": bool(row.active),
        "allowed_actions": list(row.allowed_actions or []),
        "agent_scope": dict(row.agent_scope or {}),
        "target_scope": dict(row.target_scope or {}),
        "max_risk_score": float(row.max_risk_score),
        "max_executions_per_hour": int(row.max_executions_per_hour),
        "cooldown_seconds": int(row.cooldown_seconds),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "safety_gates": list(row.safety_gates or []),
        "rollback_required": bool(row.rollback_required),
        "reason": row.reason,
        "activated_by": row.activated_by,
        "activated_at": row.activated_at.isoformat() if row.activated_at else None,
        "revoked_by": row.revoked_by,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoke_reason": row.revoke_reason,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def get_grant(session: Session, policy_id: str) -> Optional[Dict[str, Any]]:
    """Return the authoritative grant row for a policy, or None."""
    from backend.models import GuardianPreauthGrant

    row = session.query(GuardianPreauthGrant).filter(
        GuardianPreauthGrant.policy_id == policy_id
    ).first()
    return _row_to_dict(row) if row else None


def list_grants(session: Session, *, active_only: bool = False) -> List[Dict[str, Any]]:
    """List grants in deterministic policy_id order."""
    from backend.models import GuardianPreauthGrant

    query = session.query(GuardianPreauthGrant).order_by(
        GuardianPreauthGrant.policy_id.asc()
    )
    if active_only:
        query = query.filter(GuardianPreauthGrant.active.is_(True))
    return [_row_to_dict(row) for row in query.all()]


def activate_grant(
    session: Session,
    payload: Dict[str, Any],
    *,
    activated_by: str,
) -> Dict[str, Any]:
    """Activate (or re-activate) a bounded grant. Binds current policy version.

    Re-activation after a policy update binds the new version; stale
    versions never authorize. Raises PolicyValidationError fail-closed.
    """
    from backend.models import GuardianPreauthGrant
    from guardian.automation import store as policy_store

    bounds = validate_grant_bounds(payload)
    policy = policy_store.get_policy(session, bounds["policy_id"])
    if policy is None:
        raise PolicyValidationError(f"policy '{bounds['policy_id']}' not found")
    eligible, reason = __import__(
        "guardian.automation.preauth", fromlist=["policy_supports_preauth"]
    ).policy_supports_preauth(policy)
    if not eligible:
        raise PolicyValidationError(f"policy not eligible for pre-authorization: {reason}")
    # Every allowed action must be covered by a PRE_AUTHORIZED rule in the
    # current policy version; otherwise the grant would authorize something
    # the policy does not explicitly permit.
    from guardian.automation.preauth import find_preauth_rule

    for action in bounds["allowed_actions"]:
        rule = find_preauth_rule(
            policy, action_type=action["action_type"], action_name=action["action_name"]
        )
        if rule is None:
            raise PolicyValidationError(
                f"policy has no PRE_AUTHORIZED rule for '{action['action_type']}:{action['action_name']}'"
            )

    now = _now_utc()
    row = session.query(GuardianPreauthGrant).filter(
        GuardianPreauthGrant.policy_id == bounds["policy_id"]
    ).first()
    if row is None:
        row = GuardianPreauthGrant(
            policy_id=bounds["policy_id"],
            policy_version=int(policy.version),
            active=True,
            allowed_actions=bounds["allowed_actions"],
            agent_scope=bounds["agent_scope"],
            target_scope=bounds["target_scope"],
            max_risk_score=bounds["max_risk_score"],
            max_executions_per_hour=bounds["max_executions_per_hour"],
            cooldown_seconds=bounds["cooldown_seconds"],
            expires_at=bounds["expires_at"],
            safety_gates=bounds["safety_gates"],
            rollback_required=bounds["rollback_required"],
            reason=bounds["reason"],
            activated_by=activated_by,
            activated_at=now,
            revoked_by=None,
            revoked_at=None,
            revoke_reason=None,
            created_at=now,
            updated_at=now,
        )
        session.add(row)
    else:
        row.policy_version = int(policy.version)
        row.active = True
        row.allowed_actions = bounds["allowed_actions"]
        row.agent_scope = bounds["agent_scope"]
        row.target_scope = bounds["target_scope"]
        row.max_risk_score = bounds["max_risk_score"]
        row.max_executions_per_hour = bounds["max_executions_per_hour"]
        row.cooldown_seconds = bounds["cooldown_seconds"]
        row.expires_at = bounds["expires_at"]
        row.safety_gates = bounds["safety_gates"]
        row.rollback_required = bounds["rollback_required"]
        row.reason = bounds["reason"]
        row.activated_by = activated_by
        row.activated_at = now
        row.revoked_by = None
        row.revoked_at = None
        row.revoke_reason = None
        row.updated_at = now
    session.flush()
    logger.warning(
        "preauth_store: ACTIVATED policy=%s v%d by=%s",
        bounds["policy_id"], int(policy.version), activated_by,
    )
    return _row_to_dict(row)


def revoke_grant(
    session: Session,
    policy_id: str,
    *,
    revoked_by: str,
    reason: str = "operator revocation",
) -> Dict[str, Any]:
    """Revoke a grant. Never deletes (audit preserved). Idempotent."""
    from backend.models import GuardianPreauthGrant

    if not policy_id or len(policy_id) > 128:
        raise PolicyValidationError("policy_id must be 1-128 chars")
    if not reason or len(reason) > 2048:
        raise PolicyValidationError("reason must be 1-2048 chars")
    row = session.query(GuardianPreauthGrant).filter(
        GuardianPreauthGrant.policy_id == policy_id
    ).first()
    if row is None:
        raise PolicyValidationError(f"no pre-authorization grant for policy '{policy_id}'")
    now = _now_utc()
    row.active = False
    row.revoked_by = revoked_by
    row.revoked_at = now
    row.revoke_reason = reason
    row.updated_at = now
    session.flush()
    logger.warning("preauth_store: REVOKED policy=%s by=%s", policy_id, revoked_by)
    return _row_to_dict(row)


def check_grant_for_request(
    session: Session,
    policy: Any,
    *,
    action_type: str,
    action_name: str,
    target: Dict[str, Any],
    risk_score: float,
    agent_key: Optional[str] = None,
    host_id: Optional[str] = None,
    expected_policy_version: Optional[int] = None,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Authoritative per-request grant check. Fail closed.

    Returns (authorized, reason, grant_or_None). Checks: grant exists and
    active, version binding (grant version == current policy version ==
    request expected version), bounds coverage, expiry, and grant-level
    frequency caps against envelope run history.
    """
    from guardian.automation.preauth import grant_covers_request

    grant = get_grant(session, policy.policy_id)
    if grant is None or not grant.get("active"):
        return False, "no_active_grant", grant
    try:
        if int(grant.get("policy_version", -1)) != int(policy.version):
            return False, "stale_grant_version", grant
        if expected_policy_version is not None and int(expected_policy_version) != int(policy.version):
            return False, "stale_policy_version", grant
    except (TypeError, ValueError):
        return False, "version_unparseable_fail_closed", grant
    covered, cover_reason = grant_covers_request(
        grant,
        action_type=action_type,
        action_name=action_name,
        target=target,
        risk_score=risk_score,
        agent_key=agent_key,
        host_id=host_id,
    )
    if not covered:
        return False, cover_reason, grant
    # Grant-level frequency cap (in addition to rule-level caps enforced
    # by the envelope cooldown gate).
    try:
        from backend.models import GuardianEnvelopeRun

        now = _now_utc()
        from datetime import timedelta

        cutoff = now - timedelta(hours=1)
        recent = session.query(GuardianEnvelopeRun).filter(
            GuardianEnvelopeRun.policy_id == policy.policy_id,
            GuardianEnvelopeRun.status.notin_(["blocked"]),
        ).filter(GuardianEnvelopeRun.created_at >= cutoff).count()
        if recent >= int(grant.get("max_executions_per_hour", 1)):
            return False, "grant_max_frequency_exceeded", grant
    except Exception:  # noqa: BLE001
        logger.error("preauth_store: frequency check failed; failing closed")
        return False, "grant_frequency_check_error_fail_closed", grant
    return True, "grant_authorizes_request", grant
