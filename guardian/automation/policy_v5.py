"""Guardian v2 Phase 5 Slice 1 — Versioned policy model + deterministic evaluation + dry-run.

Scope of this module (deliberately narrow):
  - Policy definitions with lifecycle fields (version, priority, expiration).
  - Deterministic multi-policy evaluation with an explicit precedence model.
  - Pure dry-run simulation: answers what WOULD happen without mutating
    anything (no OS calls, no network calls, no DB writes, no approvals,
    no action registry invocation).

What this module does NOT do (deferred to later slices):
  - No autonomous execution (``would_execute`` is always False).
  - No new execution mode: only the Phase 4 ``AutomationMode`` values
    (disabled / prepare_only / approval_required) are accepted. A
    pre-authorized execution mode arrives with the Slice 2 executor.
  - No AI input: the evaluator takes no AI output. AI cannot alter
    precedence, and precedence inputs are plain data validated here.

Precedence model (deterministic, fail-closed):
  1. Kill switch active  -> DENY (global wins over everything).
  2. Disabled or expired policies never match (silently skipped).
  3. DENY rules override all non-DENY matches (fail closed on conflict).
  4. Among same-effect candidates the winner is, in order:
       a. higher rule priority,
       b. narrower target scope (higher specificity score),
       c. higher policy priority,
       d. lexicographically smaller policy_id, then rule_id (final tiebreak).
  5. Newest version is authoritative only when explicitly activated: the
     store activates exactly one row per policy_id, and evaluation records
     the version it evaluated. Version numbers never auto-win.
  6. No rule matches -> REQUIRE_APPROVAL (default deny-by-approval).
  7. Phase 4 safety invariants preserved: ``requires_approval=True`` on a
     rule forces REQUIRE_APPROVAL even when the rule says ALLOW, and policies
     in APPROVAL_REQUIRED mode always report approval as required.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from guardian.automation.policy import AutomationMode, PolicyDecision

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────

class ApprovalMode(str, Enum):
    """Per-rule approval expectation for a future executor.

    REQUIRED means a human approval must exist before execution.
    PRE_AUTHORIZED means the policy pre-authorizes execution subject to the
    full safety envelope (kill switch, circuit breaker, rate limiter, target
    validation, verification, audit). Slice 1 only *reports* this value in
    simulations; no executor honors it yet.
    """

    REQUIRED = "required"
    PRE_AUTHORIZED = "pre_authorized"


SEVERITIES = frozenset({"low", "medium", "high", "critical"})

ALLOWED_SCOPE_KEYS = frozenset({
    "host_ids",
    "agent_keys",
    "destination_ips",  # exact IPs or CIDR ranges
    "process_names",  # case-insensitive exact match
    "persistence_types",
    "persistence_paths",  # case-insensitive exact-or-prefix match
    "file_paths",  # case-insensitive exact-or-prefix match
    "user_names",  # case-insensitive exact match
})

MAX_RULES_PER_POLICY = 100
MAX_EVENT_IDS = 100
MAX_SCOPE_ENTRIES = 100

# Safety controls that a future executor MUST run, in required order.
# Listed here so simulations can honestly answer "what would run".
# Required precedence: kill switch > circuit breaker > rate limiter >
# target safety checks > policy authorization > execution.
SAFETY_CHECKS_SLICE1 = [
    "kill_switch",
    "circuit_breaker",
    "rate_limiter",
    "target_validation",
    "approval_verification",
    "audit_record",
    "independent_verification",
    "rollback_if_supported",
]

_POLICY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Errors ────────────────────────────────────────────────────────────

class PolicyValidationError(ValueError):
    """Raised when a policy, rule, scope, or evaluation request is invalid."""


# ── Domain dataclasses ────────────────────────────────────────────────

@dataclass
class PolicyRuleV5:
    """A single deterministic rule inside a versioned automation policy."""

    rule_id: str
    description: str
    action_type: str  # e.g. "process", "network", "*" (wildcard)
    action_name: str  # e.g. "terminate_process", "*"
    min_risk_score: float = 0.0
    max_risk_score: float = 100.0
    incident_severity: Optional[str] = None  # None = any severity
    decision: PolicyDecision = PolicyDecision.REQUIRE_APPROVAL
    requires_approval: bool = True
    priority: int = 100  # higher wins within the same effect
    target_scope: Optional[Dict[str, List[str]]] = None  # None/{} = any target
    approval_mode: ApprovalMode = ApprovalMode.REQUIRED
    max_executions_per_hour: Optional[int] = None
    cooldown_seconds: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "action_type": self.action_type,
            "action_name": self.action_name,
            "min_risk_score": self.min_risk_score,
            "max_risk_score": self.max_risk_score,
            "incident_severity": self.incident_severity,
            "decision": self.decision.value,
            "requires_approval": self.requires_approval,
            "priority": self.priority,
            "target_scope": self.target_scope or {},
            "approval_mode": self.approval_mode.value,
            "max_executions_per_hour": self.max_executions_per_hour,
            "cooldown_seconds": self.cooldown_seconds,
        }


@dataclass
class AutomationPolicyV5:
    """Versioned automation policy.

    Exactly one active row per policy_id exists in the store; ``version`` is
    incremented on every modification and recorded on every evaluation so
    that stale-policy decisions are detectable.
    """

    policy_id: str
    name: str
    description: str
    mode: AutomationMode = AutomationMode.APPROVAL_REQUIRED
    enabled: bool = True
    version: int = 1
    priority: int = 100  # higher wins after rule priority and scope
    expires_at: Optional[datetime] = None  # None = never expires
    rules: List[PolicyRuleV5] = field(default_factory=list)
    created_at: datetime = field(default_factory=_now_utc)
    updated_at: datetime = field(default_factory=_now_utc)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or _now_utc()) >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "mode": self.mode.value,
            "enabled": self.enabled,
            "version": self.version,
            "priority": self.priority,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rules": [r.to_dict() for r in self.rules],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class EvaluationRequest:
    """Inputs to deterministic policy evaluation (plain data, never AI output)."""

    action_type: str
    action_name: str
    target: Dict[str, Any]
    risk_score: float
    incident_severity: str
    incident_id: Optional[int] = None
    event_ids: List[str] = field(default_factory=list)
    requested_by: str = "system"
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "action_name": self.action_name,
            "target": self.target,
            "risk_score": self.risk_score,
            "incident_severity": self.incident_severity,
            "incident_id": self.incident_id,
            "event_ids": self.event_ids,
            "requested_by": self.requested_by,
            "correlation_id": self.correlation_id,
        }


@dataclass
class EvaluationResult:
    """Outcome of deterministic evaluation (also the dry-run answer)."""

    decision: PolicyDecision
    reason: str
    matched_policy_id: Optional[str]
    matched_policy_version: Optional[int]
    matched_rule_id: Optional[str]
    approval_mode: ApprovalMode
    would_require_approval: bool
    would_execute: bool  # always False in Slice 1
    blocked_reason: Optional[str]
    safety_checks: List[str]
    evaluated_policies: int
    candidate_rules: int
    scope_specificity: int
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "matched_policy_id": self.matched_policy_id,
            "matched_policy_version": self.matched_policy_version,
            "matched_rule_id": self.matched_rule_id,
            "approval_mode": self.approval_mode.value,
            "would_require_approval": self.would_require_approval,
            "would_execute": self.would_execute,
            "blocked_reason": self.blocked_reason,
            "safety_checks": list(self.safety_checks),
            "evaluated_policies": self.evaluated_policies,
            "candidate_rules": self.candidate_rules,
            "scope_specificity": self.scope_specificity,
            "explanation": self.explanation,
        }


# ── Validation ────────────────────────────────────────────────────────

def _require_registered_or_wildcard(kind: str, value: str) -> None:
    if value == "*":
        return
    # Lazy import avoids hard dependency cycles at module import time.
    from guardian.actions import registry as action_registry

    known_types = {a["action_type"] for a in action_registry.list_actions()}
    if kind == "action_type":
        if value not in known_types:
            raise PolicyValidationError(
                f"Unknown action_type '{value}'. Registered: {sorted(known_types)} or '*'."
            )
        return
    # action_name: must exist for at least one registered type, or be "*".
    known_names = {a["action_name"] for a in action_registry.list_actions()}
    if value not in known_names:
        raise PolicyValidationError(
            f"Unknown action_name '{value}'. Registered: {sorted(known_names)} or '*'."
        )


def validate_scope(scope: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Validate a target scope dict. Returns a normalized copy. Fail closed."""
    if scope is None:
        return {}
    if not isinstance(scope, dict):
        raise PolicyValidationError("target_scope must be an object")
    normalized: Dict[str, List[str]] = {}
    for key, values in scope.items():
        if key not in ALLOWED_SCOPE_KEYS:
            raise PolicyValidationError(
                f"Unknown scope key '{key}'. Allowed: {sorted(ALLOWED_SCOPE_KEYS)}."
            )
        if not isinstance(values, list):
            raise PolicyValidationError(f"Scope '{key}' must be a list of strings")
        if len(values) > MAX_SCOPE_ENTRIES:
            raise PolicyValidationError(
                f"Scope '{key}' has too many entries (max {MAX_SCOPE_ENTRIES})"
            )
        cleaned: List[str] = []
        for entry in values:
            if not isinstance(entry, str) or not entry or len(entry) > 512:
                raise PolicyValidationError(
                    f"Scope '{key}' entries must be non-empty strings (max 512 chars)"
                )
            cleaned.append(entry)
        if key == "destination_ips":
            for entry in cleaned:
                try:
                    if "/" in entry:
                        ipaddress.ip_network(entry, strict=False)
                    else:
                        ipaddress.ip_address(entry)
                except ValueError:
                    raise PolicyValidationError(
                        f"Scope 'destination_ips' entry '{entry}' is not a valid IP or CIDR"
                    )
        if key in ("persistence_paths", "file_paths"):
            for entry in cleaned:
                if ".." in entry:
                    raise PolicyValidationError(
                        f"Scope '{key}' entry '{entry}' contains path traversal ('..')"
                    )
        if cleaned:
            normalized[key] = cleaned
    return normalized


def validate_rule(rule: PolicyRuleV5) -> None:
    """Validate a rule. Raises PolicyValidationError on any problem."""
    if not _RULE_ID_RE.match(rule.rule_id or ""):
        raise PolicyValidationError(
            "rule_id must match ^[A-Za-z0-9_-]{1,128}$"
        )
    if not rule.action_type or len(rule.action_type) > 64:
        raise PolicyValidationError("action_type must be 1-64 chars")
    if not rule.action_name or len(rule.action_name) > 64:
        raise PolicyValidationError("action_name must be 1-64 chars")
    _require_registered_or_wildcard("action_type", rule.action_type)
    _require_registered_or_wildcard("action_name", rule.action_name)
    try:
        min_s = float(rule.min_risk_score)
        max_s = float(rule.max_risk_score)
    except (TypeError, ValueError):
        raise PolicyValidationError("min/max_risk_score must be numbers")
    if not (0.0 <= min_s <= max_s <= 100.0):
        raise PolicyValidationError(
            "Require 0 <= min_risk_score <= max_risk_score <= 100"
        )
    if rule.incident_severity is not None and rule.incident_severity not in SEVERITIES:
        raise PolicyValidationError(
            f"incident_severity must be one of {sorted(SEVERITIES)} or null"
        )
    if not isinstance(rule.decision, PolicyDecision):
        raise PolicyValidationError("decision must be a PolicyDecision")
    if not isinstance(rule.requires_approval, bool):
        raise PolicyValidationError("requires_approval must be a boolean")
    if not isinstance(rule.priority, int) or not (0 <= rule.priority <= 1000):
        raise PolicyValidationError("priority must be an integer 0-1000")
    if not isinstance(rule.approval_mode, ApprovalMode):
        raise PolicyValidationError("approval_mode must be an ApprovalMode")
    if rule.max_executions_per_hour is not None and (
        not isinstance(rule.max_executions_per_hour, int)
        or rule.max_executions_per_hour < 1
    ):
        raise PolicyValidationError("max_executions_per_hour must be an integer >= 1")
    if rule.cooldown_seconds is not None and (
        not isinstance(rule.cooldown_seconds, int) or rule.cooldown_seconds < 0
    ):
        raise PolicyValidationError("cooldown_seconds must be an integer >= 0")
    rule.target_scope = validate_scope(rule.target_scope)


def validate_policy(policy: AutomationPolicyV5) -> None:
    """Validate a policy and all its rules. Raises PolicyValidationError."""
    if not _POLICY_ID_RE.match(policy.policy_id or ""):
        raise PolicyValidationError("policy_id must match ^[A-Za-z0-9_-]{1,128}$")
    if not policy.name or len(policy.name) > 255:
        raise PolicyValidationError("name must be 1-255 chars")
    if len(policy.description or "") > 4096:
        raise PolicyValidationError("description must be at most 4096 chars")
    if not isinstance(policy.mode, AutomationMode):
        raise PolicyValidationError("mode must be an AutomationMode")
    if not isinstance(policy.version, int) or policy.version < 1:
        raise PolicyValidationError("version must be an integer >= 1")
    if not isinstance(policy.priority, int) or not (0 <= policy.priority <= 1000):
        raise PolicyValidationError("priority must be an integer 0-1000")
    if len(policy.rules) > MAX_RULES_PER_POLICY:
        raise PolicyValidationError(
            f"Too many rules (max {MAX_RULES_PER_POLICY})"
        )
    seen = set()
    for rule in policy.rules:
        validate_rule(rule)
        if rule.rule_id in seen:
            raise PolicyValidationError(f"Duplicate rule_id '{rule.rule_id}'")
        seen.add(rule.rule_id)


def validate_request(request: EvaluationRequest) -> None:
    """Validate an evaluation request. Raises PolicyValidationError."""
    if not request.action_type or len(request.action_type) > 64:
        raise PolicyValidationError("action_type must be 1-64 chars")
    if not request.action_name or len(request.action_name) > 64:
        raise PolicyValidationError("action_name must be 1-64 chars")
    if not isinstance(request.target, dict):
        raise PolicyValidationError("target must be an object")
    try:
        risk = float(request.risk_score)
    except (TypeError, ValueError):
        raise PolicyValidationError("risk_score must be a number")
    if not (0.0 <= risk <= 100.0):
        raise PolicyValidationError("risk_score must be 0-100")
    if request.incident_severity not in SEVERITIES:
        raise PolicyValidationError(
            f"incident_severity must be one of {sorted(SEVERITIES)}"
        )
    if not isinstance(request.event_ids, list) or len(request.event_ids) > MAX_EVENT_IDS:
        raise PolicyValidationError(f"event_ids must be a list (max {MAX_EVENT_IDS})")
    for event_id in request.event_ids:
        if not isinstance(event_id, str) or not event_id or len(event_id) > 256:
            raise PolicyValidationError("event_ids entries must be non-empty strings")


# ── Scope matching ────────────────────────────────────────────────────

def scope_specificity(scope: Optional[Dict[str, List[str]]]) -> int:
    """Deterministic narrowness score: higher = narrower scope.

    Empty/None scope scores 0 (broadest). Each constrained dimension adds
    10 points plus up to 10 more for short lists, so a single-host rule
    beats a ten-host rule, which beats an unconstrained rule.
    """
    if not scope:
        return 0
    score = 0
    for key in sorted(scope.keys()):
        values = scope.get(key) or []
        if values:
            score += 10 + max(0, 10 - len(values))
    return score


def _match_ip(scope_entries: List[str], target_ip: Any) -> bool:
    if not isinstance(target_ip, str) or not target_ip:
        return False
    try:
        target = ipaddress.ip_address(target_ip)
    except ValueError:
        return False  # malformed target IP never matches (fail closed)
    for entry in scope_entries:
        try:
            if "/" in entry:
                if target in ipaddress.ip_network(entry, strict=False):
                    return True
            elif target == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue  # invalid scope entries were rejected at creation; skip defensively
    return False


def _match_ci_exact(scope_entries: List[str], target_value: Any) -> bool:
    if not isinstance(target_value, str) or not target_value:
        return False
    lowered = target_value.lower()
    return any(entry.lower() == lowered for entry in scope_entries)


def _match_ci_prefix(scope_entries: List[str], target_value: Any) -> bool:
    if not isinstance(target_value, str) or not target_value:
        return False
    lowered = target_value.lower()
    return any(
        lowered == entry.lower() or lowered.startswith(entry.lower())
        for entry in scope_entries
    )


def scope_matches_target(scope: Optional[Dict[str, List[str]]], target: Dict[str, Any]) -> bool:
    """Return True when the target falls inside the rule scope.

    Empty/None scope matches everything. Every constrained dimension must
    match (AND semantics). Unknown target fields are ignored; missing target
    fields for a constrained dimension mean NO match (fail closed).
    """
    if not scope:
        return True
    if not isinstance(target, dict):
        return False
    checks = (
        ("host_ids", target.get("host_id"), _match_ci_exact),
        ("agent_keys", target.get("agent_key"), _match_ci_exact),
        ("destination_ips", target.get("destination_ip"), _match_ip),
        ("process_names", target.get("process_name"), _match_ci_exact),
        ("persistence_types", target.get("persistence_type"), _match_ci_exact),
        ("persistence_paths", target.get("persistence_path"), _match_ci_prefix),
        ("file_paths", target.get("file_path"), _match_ci_prefix),
        ("user_names", target.get("user_name"), _match_ci_exact),
    )
    for key, target_value, matcher in checks:
        entries = scope.get(key)
        if entries and not matcher(entries, target_value):
            return False
    return True


def _rule_matches(
    rule: PolicyRuleV5,
    action_type: str,
    action_name: str,
    risk_score: float,
    incident_severity: str,
    target: Dict[str, Any],
) -> bool:
    if rule.action_type != "*" and rule.action_type != action_type:
        return False
    if rule.action_name != "*" and rule.action_name != action_name:
        return False
    if not (float(rule.min_risk_score) <= float(risk_score) <= float(rule.max_risk_score)):
        return False
    if rule.incident_severity is not None and rule.incident_severity != incident_severity:
        return False
    if not scope_matches_target(rule.target_scope, target):
        return False
    return True


# ── Deterministic evaluation ──────────────────────────────────────────

def _candidate_sort_key(
    policy: AutomationPolicyV5, rule: PolicyRuleV5, specificity: int
) -> Tuple[int, int, int, str, str]:
    # Higher rule priority first, then narrower scope, then higher policy
    # priority; lexicographic ids are the final deterministic tiebreak.
    return (-rule.priority, -specificity, -policy.priority, policy.policy_id, rule.rule_id)


def evaluate_policies(
    policies: List[AutomationPolicyV5],
    request: EvaluationRequest,
    *,
    now: Optional[datetime] = None,
    kill_switch_active: bool = False,
) -> EvaluationResult:
    """Evaluate a request against policies deterministically. Pure function.

    Performs no I/O: no database access, no OS calls, no network calls, no
    action registry invocation. Safe to call from dry-run paths.
    """
    validate_request(request)
    moment = now or _now_utc()

    if kill_switch_active:
        return EvaluationResult(
            decision=PolicyDecision.DENY,
            reason="kill_switch_active",
            matched_policy_id=None,
            matched_policy_version=None,
            matched_rule_id=None,
            approval_mode=ApprovalMode.REQUIRED,
            would_require_approval=True,
            would_execute=False,
            blocked_reason="kill_switch_active: global kill switch wins over policy authorization",
            safety_checks=list(SAFETY_CHECKS_SLICE1),
            evaluated_policies=len(policies),
            candidate_rules=0,
            scope_specificity=0,
            explanation=(
                f"This incident would be BLOCKED by the global kill switch; "
                f"no policy authorizes {request.action_type}:{request.action_name} "
                f"while the kill switch is active."
            ),
        )

    evaluated = 0
    denies: List[Tuple[Tuple[int, int, int, str, str], AutomationPolicyV5, PolicyRuleV5, int]] = []
    allows: List[Tuple[Tuple[int, int, int, str, str], AutomationPolicyV5, PolicyRuleV5, int]] = []

    for policy in sorted(policies, key=lambda p: p.policy_id):
        if not policy.enabled:
            continue
        if policy.mode == AutomationMode.DISABLED:
            continue
        if policy.is_expired(moment):
            continue
        evaluated += 1
        if policy.mode == AutomationMode.PREPARE_ONLY:
            # Prepare-only policies never authorize execution; they match as
            # PREPARE_ONLY candidates when a rule matches.
            for rule in policy.rules:
                if _rule_matches(
                    rule, request.action_type, request.action_name,
                    float(request.risk_score), request.incident_severity, request.target,
                ):
                    spec = scope_specificity(rule.target_scope)
                    allows.append((_candidate_sort_key(policy, rule, spec), policy, rule, spec))
            continue
        for rule in policy.rules:
            if _rule_matches(
                rule, request.action_type, request.action_name,
                float(request.risk_score), request.incident_severity, request.target,
            ):
                spec = scope_specificity(rule.target_scope)
                entry = (_candidate_sort_key(policy, rule, spec), policy, rule, spec)
                if rule.decision == PolicyDecision.DENY:
                    denies.append(entry)
                else:
                    allows.append(entry)

    total_candidates = len(denies) + len(allows)

    if denies:
        denies.sort(key=lambda e: e[0])
        _, policy, rule, spec = denies[0]
        explanation = (
            f"This incident would be BLOCKED: deny rule {rule.rule_id} "
            f"in policy {policy.policy_id} v{policy.version} matched "
            f"({request.action_type}:{request.action_name}, "
            f"risk {float(request.risk_score):.1f}, {request.incident_severity}). "
            f"Deny overrides {total_candidates - 1} other matching rule(s)."
            if total_candidates > 1 else
            f"This incident would be BLOCKED: deny rule {rule.rule_id} "
            f"in policy {policy.policy_id} v{policy.version} matched "
            f"({request.action_type}:{request.action_name}, "
            f"risk {float(request.risk_score):.1f}, {request.incident_severity})."
        )
        return EvaluationResult(
            decision=PolicyDecision.DENY,
            reason=f"rule:{rule.rule_id}",
            matched_policy_id=policy.policy_id,
            matched_policy_version=policy.version,
            matched_rule_id=rule.rule_id,
            approval_mode=rule.approval_mode,
            would_require_approval=True,
            would_execute=False,
            blocked_reason=f"deny rule {rule.rule_id} in policy {policy.policy_id}",
            safety_checks=list(SAFETY_CHECKS_SLICE1),
            evaluated_policies=evaluated,
            candidate_rules=total_candidates,
            scope_specificity=spec,
            explanation=explanation,
        )

    if allows:
        allows.sort(key=lambda e: e[0])
        _, policy, rule, spec = allows[0]
        decision = rule.decision
        # Phase 4 safety invariant: requires_approval=True forces approval
        # even when the rule decision says ALLOW.
        if rule.requires_approval and decision == PolicyDecision.ALLOW:
            decision = PolicyDecision.REQUIRE_APPROVAL
        would_require_approval = True
        if (
            policy.mode == AutomationMode.APPROVAL_REQUIRED
            or rule.requires_approval
            or rule.approval_mode == ApprovalMode.REQUIRED
        ):
            would_require_approval = True
        else:
            # Pre-authorized path: reachable only when the rule explicitly opts
            # out of approval AND the policy mode permits it. Slice 1 has no
            # executor, so execution stays disabled regardless.
            would_require_approval = False
        if policy.mode == AutomationMode.PREPARE_ONLY:
            decision = PolicyDecision.PREPARE_ONLY
        verb = "require approval before" if would_require_approval else "be pre-authorized for"
        explanation = (
            f"This incident WOULD {verb} {request.action_type}:{request.action_name} "
            f"because rule {rule.rule_id} in policy {policy.policy_id} v{policy.version} "
            f"matched (risk {float(request.risk_score):.1f}, {request.incident_severity}, "
            f"scope specificity {spec}). Autonomous execution is disabled in Slice 1: "
            f"no real action would occur."
        )
        return EvaluationResult(
            decision=decision,
            reason=f"rule:{rule.rule_id}",
            matched_policy_id=policy.policy_id,
            matched_policy_version=policy.version,
            matched_rule_id=rule.rule_id,
            approval_mode=rule.approval_mode,
            would_require_approval=would_require_approval,
            would_execute=False,
            blocked_reason="slice1_simulation_only: autonomous execution is not enabled",
            safety_checks=list(SAFETY_CHECKS_SLICE1),
            evaluated_policies=evaluated,
            candidate_rules=total_candidates,
            scope_specificity=spec,
            explanation=explanation,
        )

    return EvaluationResult(
        decision=PolicyDecision.REQUIRE_APPROVAL,
        reason="default_no_matching_policy",
        matched_policy_id=None,
        matched_policy_version=None,
        matched_rule_id=None,
        approval_mode=ApprovalMode.REQUIRED,
        would_require_approval=True,
        would_execute=False,
        blocked_reason="slice1_simulation_only: autonomous execution is not enabled",
        safety_checks=list(SAFETY_CHECKS_SLICE1),
        evaluated_policies=evaluated,
        candidate_rules=0,
        scope_specificity=0,
        explanation=(
            f"This incident would require approval before "
            f"{request.action_type}:{request.action_name}: no enabled policy "
            f"matched (risk {float(request.risk_score):.1f}, "
            f"{request.incident_severity}). Default is approval-required."
        ),
    )


def simulate(
    policies: List[AutomationPolicyV5],
    request: EvaluationRequest,
    *,
    now: Optional[datetime] = None,
    kill_switch_active: bool = False,
) -> EvaluationResult:
    """Dry-run simulation. Pure function — guaranteed no mutation.

    The function performs zero I/O by construction: it only calls
    ``evaluate_policies`` (pure) and never touches the database, the
    action registry, the approval manager, the OS, or the network.
    Callers MUST NOT execute, approve, or persist production state based
    on the returned value except for writing the explicitly-designed
    simulation audit record.
    """
    return evaluate_policies(
        policies, request, now=now, kill_switch_active=kill_switch_active
    )


def compute_evaluation_id(request: EvaluationRequest) -> str:
    """Deterministic idempotency key for a simulation audit record."""
    fingerprint = json.dumps(
        {
            "action_type": request.action_type,
            "action_name": request.action_name,
            "target": request.target,
            "risk_score": float(request.risk_score),
            "incident_severity": request.incident_severity,
            "incident_id": request.incident_id,
            "event_ids": sorted(request.event_ids),
            "correlation_id": request.correlation_id or "",
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(fingerprint.encode()).hexdigest()[:32]
    return f"evl-{digest}"
