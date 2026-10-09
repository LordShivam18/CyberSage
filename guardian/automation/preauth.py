"""Guardian v2 Phase 5 Slice 4 — bounded pre-authorization domain logic.

Pure, deterministic helpers for narrowly scoped pre-authorized execution.
No I/O, no database access, no OS calls, no network calls, no AI input.

Design (additive over Slices 1-3):
  - Existing policies keep their safe behavior. Pre-authorization is
    disabled by default: with no active grant row, the envelope follows
    the Slice 2 approved-manual path unchanged.
  - An ALLOW evaluation alone never authorizes execution. A pre-authorized
    execution additionally requires: an active persisted grant for the
    policy, a matching PRE_AUTHORIZED rule, and every bound below.
  - Missing or unsupported permission fields never expand the effective
    permission set: validation rejects them fail-closed.
  - Unknown modes, conflicting policies, and ambiguous authorization
    fail closed at the envelope gate (see envelope.py).

A bounded grant explicitly constrains:
  - permitted concrete actions (registered, no wildcards),
  - agent/host scope (at least one dimension when set; empty means the
    grant does not restrict that dimension but the rule scope still applies),
  - permitted target scope (at least one scope key required),
  - maximum accepted risk (0-100),
  - maximum execution frequency per hour (>= 1) and cooldown seconds (>= 0),
  - explicit expiration timestamp (required),
  - required safety gates (must equal the envelope GATE_ORDER),
  - rollback expectation recorded where the action supports it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from guardian.automation.policy import AutomationMode
from guardian.automation.policy_v5 import (
    AutomationPolicyV5,
    PolicyRuleV5,
    PolicyValidationError,
    scope_matches_target,
    validate_scope,
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Actions that Slice 4 will never pre-authorize, even if registered.
# The envelope already forbids wildcards; this list additionally blocks
# broad destructive surface from ever entering a bounded grant.
FORBIDDEN_PREAUTH_ACTIONS = frozenset({
    ("process", "*"),
    ("network", "*"),
    ("persistence", "*"),
})

REQUIRED_SAFETY_GATES = [
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
    "preauth_authorization",
    "approval",
]


def validate_allowed_actions(actions: Any) -> List[Dict[str, str]]:
    """Validate the grant's permitted concrete action list. Fail closed."""
    if not isinstance(actions, list) or not actions:
        raise PolicyValidationError("allowed_actions must be a non-empty list")
    if len(actions) > 25:
        raise PolicyValidationError("allowed_actions has too many entries (max 25)")
    from guardian.actions import registry as action_registry

    cleaned: List[Dict[str, str]] = []
    seen = set()
    for entry in actions:
        if not isinstance(entry, dict):
            raise PolicyValidationError("allowed_actions entries must be objects")
        action_type = entry.get("action_type", "")
        action_name = entry.get("action_name", "")
        if not isinstance(action_type, str) or not action_type or len(action_type) > 64:
            raise PolicyValidationError("allowed action_type must be 1-64 chars")
        if not isinstance(action_name, str) or not action_name or len(action_name) > 64:
            raise PolicyValidationError("allowed action_name must be 1-64 chars")
        if "*" in (action_type, action_name):
            raise PolicyValidationError("pre-authorization forbids wildcard actions")
        if (action_type, action_name) in FORBIDDEN_PREAUTH_ACTIONS:
            raise PolicyValidationError(
                f"action '{action_type}:{action_name}' is never pre-authorizable"
            )
        if not action_registry.is_registered(action_type, action_name):
            raise PolicyValidationError(
                f"action '{action_type}:{action_name}' is not registered"
            )
        key = (action_type, action_name)
        if key in seen:
            raise PolicyValidationError(f"duplicate allowed action '{action_type}:{action_name}'")
        seen.add(key)
        cleaned.append({"action_type": action_type, "action_name": action_name})
    return cleaned


def validate_grant_bounds(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a pre-authorization grant payload. Returns normalized copy.

    Required keys: policy_id, allowed_actions, target_scope, max_risk_score,
    max_executions_per_hour, cooldown_seconds, expires_at.
    Optional: agent_scope, reason, safety_gates, rollback_required.
    """
    if not isinstance(payload, dict):
        raise PolicyValidationError("grant payload must be an object")
    policy_id = payload.get("policy_id", "")
    if not isinstance(policy_id, str) or not policy_id or len(policy_id) > 128:
        raise PolicyValidationError("policy_id must be 1-128 chars")

    allowed_actions = validate_allowed_actions(payload.get("allowed_actions"))

    target_scope = validate_scope(payload.get("target_scope"))
    if not target_scope:
        raise PolicyValidationError(
            "target_scope must constrain at least one scope dimension for pre-authorization"
        )

    agent_scope = validate_scope(payload.get("agent_scope") or {})
    # agent_scope may be empty (no additional agent restriction beyond rule scope).

    try:
        max_risk = float(payload.get("max_risk_score"))
    except (TypeError, ValueError):
        raise PolicyValidationError("max_risk_score must be a number 0-100")
    if not (0.0 <= max_risk <= 100.0):
        raise PolicyValidationError("max_risk_score must be 0-100")

    max_freq = payload.get("max_executions_per_hour")
    if not isinstance(max_freq, int) or max_freq < 1 or max_freq > 1000:
        raise PolicyValidationError("max_executions_per_hour must be an integer 1-1000")

    cooldown = payload.get("cooldown_seconds")
    if not isinstance(cooldown, int) or cooldown < 0 or cooldown > 86400:
        raise PolicyValidationError("cooldown_seconds must be an integer 0-86400")

    expires_at = payload.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise PolicyValidationError("expires_at must be ISO-8601 datetime")
    if not isinstance(expires_at, datetime):
        raise PolicyValidationError("expires_at is required for pre-authorization")
    if expires_at <= _now_utc():
        raise PolicyValidationError("expires_at must be in the future")

    safety_gates = payload.get("safety_gates") or list(REQUIRED_SAFETY_GATES)
    if list(safety_gates) != list(REQUIRED_SAFETY_GATES):
        raise PolicyValidationError("safety_gates must equal the required envelope gate order")

    reason = payload.get("reason", "")
    if not isinstance(reason, str) or not reason or len(reason) > 2048:
        raise PolicyValidationError("reason must be 1-2048 chars")

    rollback_required = bool(payload.get("rollback_required", False))

    return {
        "policy_id": policy_id,
        "allowed_actions": allowed_actions,
        "target_scope": dict(target_scope),
        "agent_scope": dict(agent_scope),
        "max_risk_score": float(max_risk),
        "max_executions_per_hour": int(max_freq),
        "cooldown_seconds": int(cooldown),
        "expires_at": expires_at,
        "safety_gates": list(safety_gates),
        "reason": reason,
        "rollback_required": rollback_required,
    }


def grant_covers_request(
    grant: Dict[str, Any],
    *,
    action_type: str,
    action_name: str,
    target: Dict[str, Any],
    risk_score: float,
    agent_key: Optional[str] = None,
    host_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Tuple[bool, str]:
    """Check whether a grant covers a concrete request. Pure function.

    Returns (covered, reason). Never raises on content; malformed inputs
    fail closed as not covered.
    """
    try:
        moment = now or _now_utc()
        if not grant.get("active", False):
            return False, "grant_inactive"
        expires_at = grant.get("expires_at")
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                return False, "grant_expiry_unparseable_fail_closed"
        if not isinstance(expires_at, datetime) or moment >= expires_at:
            return False, "grant_expired"
        allowed = grant.get("allowed_actions") or []
        if not any(
            a.get("action_type") == action_type and a.get("action_name") == action_name
            for a in allowed if isinstance(a, dict)
        ):
            return False, "action_not_in_grant"
        try:
            if float(risk_score) > float(grant.get("max_risk_score", -1)):
                return False, "risk_above_grant_cap"
        except (TypeError, ValueError):
            return False, "risk_unparseable_fail_closed"
        grant_scope = grant.get("target_scope") or {}
        if not grant_scope:
            return False, "grant_scope_empty_fail_closed"
        if not scope_matches_target(grant_scope, target if isinstance(target, dict) else {}):
            return False, "target_outside_grant_scope"
        agent_scope = grant.get("agent_scope") or {}
        if agent_scope:
            agent_target = {"agent_key": agent_key, "host_id": host_id}
            if not scope_matches_target(agent_scope, agent_target):
                return False, "agent_outside_grant_scope"
        return True, "grant_covers_request"
    except Exception:  # noqa: BLE001
        return False, "grant_check_error_fail_closed"


def find_preauth_rule(
    policy: AutomationPolicyV5,
    *,
    action_type: str,
    action_name: str,
) -> Optional[PolicyRuleV5]:
    """Return the policy's PRE_AUTHORIZED rule for the action, if any."""
    from guardian.automation.policy_v5 import ApprovalMode

    for rule in policy.rules:
        if rule.action_type != "*" and rule.action_type != action_type:
            continue
        if rule.action_name != "*" and rule.action_name != action_name:
            continue
        if rule.approval_mode == ApprovalMode.PRE_AUTHORIZED:
            return rule
    return None


def policy_supports_preauth(policy: AutomationPolicyV5) -> Tuple[bool, str]:
    """Check policy-level eligibility without authorizing anything."""
    if not policy.enabled:
        return False, "policy_disabled"
    if policy.mode == AutomationMode.DISABLED:
        return False, "policy_mode_disabled"
    if policy.is_expired():
        return False, "policy_expired"
    if not any(getattr(r, "approval_mode", None) and r.approval_mode.value == "pre_authorized" for r in policy.rules):
        return False, "no_preauthorized_rule"
    return True, "policy_preauth_eligible"
