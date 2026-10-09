"""Guardian v2 Phase 5 Slice 3 — deterministic policy conflict analysis.

Advisory-only overlap inspector over the real persisted policy model
(:class:`AutomationPolicyV5` / :class:`PolicyRuleV5`).

What it does:
  - Pairwise rule-overlap detection grounded in overlapping applicability:
    same-or-wildcard action, intersecting risk ranges, compatible severity,
    and scope entries that can match a common target.
  - Incompatible-outcome gating: a pair is a *conflict* only when
    applicability overlaps AND decisions are incompatible (DENY vs
    non-DENY). Same-decision overlaps are reported as redundancy advisories,
    never as conflicts.
  - Precedence relationships using the Slice 1 sort key
    (rule priority > scope specificity > policy priority > lexicographic
    ids), with DENY-wins-over-everything preserved.
  - Shadowed / unreachable analysis: full shadowing when the loser's match
    set is a subset of the winner's, partial otherwise.
  - Dormant overlaps involving disabled / expired / prepare/disabled-mode
    policies are marked non-conflicting with no runtime impact.

What it does NOT do:
  - No I/O, no DB, no OS/network, no AI input. Pure function.
  - Never overrides the deterministic policy engine. Output carries an
    explicit advisory disclaimer for operators.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from guardian.automation.policy import AutomationMode, PolicyDecision
from guardian.automation.policy_v5 import (
    AutomationPolicyV5,
    PolicyRuleV5,
    scope_specificity,
)


ADVISORY_NOTE = (
    "Advisory only — conflict visualization never overrides the "
    "deterministic policy engine."
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ── Applicability overlap ─────────────────────────────────────────────

def actions_overlap(
    action_type_a: str, action_name_a: str,
    action_type_b: str, action_name_b: str,
) -> bool:
    """True when the two action selectors can match a common action."""
    type_overlap = (
        action_type_a == "*" or action_type_b == "*"
        or action_type_a == action_type_b
    )
    name_overlap = (
        action_name_a == "*" or action_name_b == "*"
        or action_name_a == action_name_b
    )
    return bool(type_overlap and name_overlap)


def risk_overlap(
    min_a: float, max_a: float, min_b: float, max_b: float
) -> bool:
    """True when the two closed risk intervals intersect."""
    try:
        return max(float(min_a), float(min_b)) <= min(float(max_a), float(max_b))
    except (TypeError, ValueError):
        return False


def severity_overlap(
    sev_a: Optional[str], sev_b: Optional[str]
) -> bool:
    """None means 'any severity' and overlaps everything."""
    if sev_a is None or sev_b is None:
        return True
    return sev_a == sev_b


def _overlap_ci_exact(entries_a: List[str], entries_b: List[str]) -> bool:
    lowered_b = {str(e).lower() for e in entries_b}
    return any(str(e).lower() in lowered_b for e in entries_a)


def _overlap_ci_prefix(entries_a: List[str], entries_b: List[str]) -> bool:
    """Path overlap: exists a path matching both scopes.

    A target path P matches scope entry E when P == E or P startswith E
    (case-insensitive). Two entries overlap when either is a prefix of the
    other (or equal), since the longer path matches both.
    """
    for a in entries_a:
        la = str(a).lower()
        for b in entries_b:
            lb = str(b).lower()
            if la == lb or la.startswith(lb) or lb.startswith(la):
                return True
    return False


def _ip_entry_to_network(entry: str):
    entry = str(entry)
    if "/" in entry:
        return ipaddress.ip_network(entry, strict=False)
    return ipaddress.ip_address(entry)


def _ip_entries_overlap(entries_a: List[str], entries_b: List[str]) -> bool:
    for a in entries_a:
        try:
            na = _ip_entry_to_network(a)
        except ValueError:
            continue
        for b in entries_b:
            try:
                nb = _ip_entry_to_network(b)
            except ValueError:
                continue
            # address vs address
            if isinstance(na, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and isinstance(
                nb, (ipaddress.IPv4Address, ipaddress.IPv6Address)
            ):
                if na == nb:
                    return True
                continue
            # network vs address
            if isinstance(na, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and isinstance(
                nb, (ipaddress.IPv4Address, ipaddress.IPv6Address)
            ):
                try:
                    if nb in na:
                        return True
                except TypeError:
                    pass
                continue
            if isinstance(na, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and isinstance(
                nb, (ipaddress.IPv4Network, ipaddress.IPv6Network)
            ):
                try:
                    if na in nb:
                        return True
                except TypeError:
                    pass
                continue
            # network vs network
            try:
                if na.overlaps(nb):  # type: ignore[attr-defined]
                    return True
            except (TypeError, AttributeError):
                continue
    return False


_SCOPE_MATCHERS = {
    "host_ids": _overlap_ci_exact,
    "agent_keys": _overlap_ci_exact,
    "process_names": _overlap_ci_exact,
    "user_names": _overlap_ci_exact,
    "persistence_types": _overlap_ci_exact,
    "persistence_paths": _overlap_ci_prefix,
    "file_paths": _overlap_ci_prefix,
    "destination_ips": _ip_entries_overlap,
}


def scope_overlap(
    scope_a: Optional[Dict[str, List[str]]],
    scope_b: Optional[Dict[str, List[str]]],
) -> bool:
    """True when some target can fall inside both scopes.

    Empty/None scope matches everything. Scopes constraining disjoint
    dimensions still overlap (a target carrying both attributes matches
    both). Only shared dimensions with disjoint entries are disjoint.
    """
    a = scope_a or {}
    b = scope_b or {}
    if not a or not b:
        return True
    for key in set(a.keys()) & set(b.keys()):
        entries_a = a.get(key) or []
        entries_b = b.get(key) or []
        if not entries_a or not entries_b:
            continue
        matcher = _SCOPE_MATCHERS.get(key)
        if matcher is None:
            # Unknown key: fail closed by treating as overlapping.
            continue
        if not matcher(list(entries_a), list(entries_b)):
            return False
    return True


def overlapping_scope_keys(
    scope_a: Optional[Dict[str, List[str]]],
    scope_b: Optional[Dict[str, List[str]]],
) -> List[str]:
    """Shared scope dimensions whose entries overlap (sorted, deterministic)."""
    a = scope_a or {}
    b = scope_b or {}
    keys: List[str] = []
    for key in sorted(set(a.keys()) & set(b.keys())):
        entries_a = a.get(key) or []
        entries_b = b.get(key) or []
        if not entries_a or not entries_b:
            continue
        matcher = _SCOPE_MATCHERS.get(key)
        if matcher is None:
            keys.append(key)
        elif matcher(list(entries_a), list(entries_b)):
            keys.append(key)
    return keys


def rules_overlap(rule_a: PolicyRuleV5, rule_b: PolicyRuleV5) -> bool:
    """True when the two rules can match a common evaluation request."""
    if not actions_overlap(
        rule_a.action_type, rule_a.action_name,
        rule_b.action_type, rule_b.action_name,
    ):
        return False
    if not risk_overlap(
        rule_a.min_risk_score, rule_a.max_risk_score,
        rule_b.min_risk_score, rule_b.max_risk_score,
    ):
        return False
    if not severity_overlap(rule_a.incident_severity, rule_b.incident_severity):
        return False
    if not scope_overlap(rule_a.target_scope, rule_b.target_scope):
        return False
    return True


# ── Subset (shadowing) helpers ────────────────────────────────────────

def _subset_ci_exact(inner: List[str], outer: List[str]) -> bool:
    lowered_outer = {str(e).lower() for e in outer}
    return all(str(e).lower() in lowered_outer for e in inner)


def _subset_ci_prefix(inner: List[str], outer: List[str]) -> bool:
    """Inner paths subset of outer when every inner path matches some outer entry."""
    for entry in inner:
        le = str(entry).lower()
        if not any(le == str(o).lower() or le.startswith(str(o).lower()) for o in outer):
            return False
    return True


def _ip_covers(outer_entry: str, inner_entry: str) -> bool:
    try:
        outer = _ip_entry_to_network(outer_entry)
        inner = _ip_entry_to_network(inner_entry)
    except ValueError:
        return False
    if isinstance(outer, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and isinstance(
        inner, (ipaddress.IPv4Address, ipaddress.IPv6Address)
    ):
        return outer == inner
    if isinstance(outer, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and isinstance(
        inner, (ipaddress.IPv4Address, ipaddress.IPv6Address)
    ):
        try:
            return inner in outer
        except TypeError:
            return False
    if isinstance(outer, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and isinstance(
        inner, (ipaddress.IPv4Network, ipaddress.IPv6Network)
    ):
        try:
            return inner.subnet_of(outer)  # type: ignore[attr-defined]
        except (TypeError, AttributeError):
            return False
    return False


def _subset_ips(inner: List[str], outer: List[str]) -> bool:
    return all(any(_ip_covers(o, i) for o in outer) for i in inner)


def scope_is_subset(
    inner: Optional[Dict[str, List[str]]],
    outer: Optional[Dict[str, List[str]]],
) -> bool:
    """True when every target matching inner also matches outer."""
    inner_d = inner or {}
    outer_d = outer or {}
    if not outer_d:
        return True  # broad outer contains everything
    if not inner_d:
        return False  # broad inner matches targets outer excludes
    for key, outer_entries in outer_d.items():
        if not outer_entries:
            continue
        inner_entries = inner_d.get(key) or []
        if not inner_entries:
            return False
        if key in ("host_ids", "agent_keys", "process_names", "user_names", "persistence_types"):
            if not _subset_ci_exact(list(inner_entries), list(outer_entries)):
                return False
        elif key in ("persistence_paths", "file_paths"):
            if not _subset_ci_prefix(list(inner_entries), list(outer_entries)):
                return False
        elif key == "destination_ips":
            if not _subset_ips(list(inner_entries), list(outer_entries)):
                return False
        else:
            return False
    return True


def _action_is_subset(
    inner_type: str, inner_name: str, outer_type: str, outer_name: str
) -> bool:
    type_ok = outer_type == "*" or outer_type == inner_type
    name_ok = outer_name == "*" or outer_name == inner_name
    return bool(type_ok and name_ok)


def rule_match_subset(inner: PolicyRuleV5, outer: PolicyRuleV5) -> bool:
    """True when every request matching inner also matches outer."""
    if not _action_is_subset(
        inner.action_type, inner.action_name, outer.action_type, outer.action_name
    ):
        return False
    try:
        if not (
            float(outer.min_risk_score) <= float(inner.min_risk_score)
            and float(inner.max_risk_score) <= float(outer.max_risk_score)
        ):
            return False
    except (TypeError, ValueError):
        return False
    if outer.incident_severity is not None and outer.incident_severity != inner.incident_severity:
        return False
    if not scope_is_subset(inner.target_scope, outer.target_scope):
        return False
    return True


# ── Policy lifecycle ──────────────────────────────────────────────────

def policy_is_active(policy: AutomationPolicyV5, now: Optional[datetime] = None) -> bool:
    """Mirror Slice 1 evaluation skipping: disabled / disabled-mode / expired."""
    if not policy.enabled:
        return False
    if policy.mode == AutomationMode.DISABLED:
        return False
    if policy.is_expired(now or _now_utc()):
        return False
    return True


def _sort_key(
    policy: AutomationPolicyV5, rule: PolicyRuleV5, specificity: int
) -> Tuple[int, int, int, str, str]:
    return (
        -int(rule.priority),
        -int(specificity),
        -int(policy.priority),
        str(policy.policy_id),
        str(rule.rule_id),
    )


def _conflict_id(
    policy_a: str, rule_a: str, policy_b: str, rule_b: str, kind: str
) -> str:
    first, second = sorted([(policy_a, rule_a), (policy_b, rule_b)])
    fingerprint = json.dumps(
        {"a": first, "b": second, "kind": kind},
        sort_keys=True,
        separators=(",", ":"),
    )
    return "cfx-" + hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


# ── Main analysis ─────────────────────────────────────────────────────

def analyze_policy_conflicts(
    policies: List[AutomationPolicyV5],
    *,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Pairwise deterministic conflict/overlap analysis. Pure function.

    Returns one record per overlapping rule pair, sorted by conflict_id.
    Never raises on policy content; invalid rule shapes fail closed as
    non-overlapping (no false conflicts).
    """
    moment = now or _now_utc()
    ordered = sorted(policies, key=lambda p: p.policy_id)
    findings: List[Dict[str, Any]] = []

    flat: List[Tuple[AutomationPolicyV5, PolicyRuleV5, int]] = []
    for policy in ordered:
        for rule in sorted(policy.rules, key=lambda r: r.rule_id):
            try:
                spec = scope_specificity(rule.target_scope)
            except Exception:  # noqa: BLE001
                spec = 0
            flat.append((policy, rule, spec))

    for idx in range(len(flat)):
        for jdx in range(idx + 1, len(flat)):
            policy_a, rule_a, spec_a = flat[idx]
            policy_b, rule_b, spec_b = flat[jdx]
            try:
                overlaps = rules_overlap(rule_a, rule_b)
            except Exception:  # noqa: BLE001
                overlaps = False
            if not overlaps:
                continue

            active_a = policy_is_active(policy_a, moment)
            active_b = policy_is_active(policy_b, moment)
            runtime = bool(active_a and active_b)

            deny_a = rule_a.decision == PolicyDecision.DENY
            deny_b = rule_b.decision == PolicyDecision.DENY
            incompatible = deny_a != deny_b  # DENY vs non-DENY only

            # Precedence winner.
            if incompatible:
                # Engine invariant: any DENY beats any non-DENY.
                winner = (policy_a, rule_a) if deny_a else (policy_b, rule_b)
                loser = (policy_b, rule_b) if deny_a else (policy_a, rule_a)
                kind = "deny_conflict" if runtime else "dormant_overlap"
                reason = "deny_overrides_non_deny"
            else:
                key_a = _sort_key(policy_a, rule_a, spec_a)
                key_b = _sort_key(policy_b, rule_b, spec_b)
                if key_a <= key_b:
                    winner, loser = (policy_a, rule_a), (policy_b, rule_b)
                else:
                    winner, loser = (policy_b, rule_b), (policy_a, rule_a)
                if not runtime:
                    kind = "dormant_overlap"
                    reason = "dormant_policy_overlap"
                elif rule_a.decision == rule_b.decision:
                    kind = "redundant_overlap"
                    reason = "same_decision_overlap_advisory"
                else:
                    kind = "precedence_shadow"
                    reason = "higher_precedence_wins"

            w_policy, w_rule = winner
            l_policy, l_rule = loser
            try:
                full_shadow = rule_match_subset(l_rule, w_rule)
            except Exception:  # noqa: BLE001
                full_shadow = False
            coverage = "full" if full_shadow else "partial"

            risk_lo = max(
                float(rule_a.min_risk_score), float(rule_b.min_risk_score)
            )
            risk_hi = min(
                float(rule_a.max_risk_score), float(rule_b.max_risk_score)
            )
            severities = sorted(
                {s for s in (rule_a.incident_severity, rule_b.incident_severity) if s}
            )

            is_conflict = bool(runtime and incompatible)
            if not runtime:
                explanation = (
                    f"Rules {rule_a.rule_id} ({policy_a.policy_id}) and "
                    f"{rule_b.rule_id} ({policy_b.policy_id}) have overlapping "
                    f"applicability but at least one policy is inactive "
                    f"(enabled={active_a}/{active_b}); no runtime impact. {ADVISORY_NOTE}"
                )
            elif is_conflict:
                explanation = (
                    f"Deny rule {w_rule.rule_id} in policy {w_policy.policy_id} v{w_policy.version} "
                    f"overrides {l_rule.rule_id} in policy {l_policy.policy_id} v{l_policy.version} "
                    f"for overlapping conditions ({coverage} shadowing). {ADVISORY_NOTE}"
                )
            elif kind == "redundant_overlap":
                explanation = (
                    f"Rules {rule_a.rule_id} ({policy_a.policy_id}) and "
                    f"{rule_b.rule_id} ({policy_b.policy_id}) overlap with the same "
                    f"decision ({rule_a.decision.value}); winner by precedence is "
                    f"{w_rule.rule_id} ({w_policy.policy_id}). Redundancy advisory. {ADVISORY_NOTE}"
                )
            else:
                explanation = (
                    f"Rules {rule_a.rule_id} and {rule_b.rule_id} overlap with different "
                    f"non-deny decisions; precedence winner is {w_rule.rule_id} "
                    f"({w_policy.policy_id}, {coverage} shadowing). Operator review "
                    f"advised. {ADVISORY_NOTE}"
                )

            findings.append(
                {
                    "conflict_id": _conflict_id(
                        policy_a.policy_id, rule_a.rule_id,
                        policy_b.policy_id, rule_b.rule_id, kind,
                    ),
                    "type": kind,
                    "is_conflict": is_conflict,
                    "runtime_impact": runtime,
                    "severity": (
                        "high" if is_conflict
                        else ("low" if kind == "redundant_overlap" else "medium")
                    ),
                    "policies": [
                        {
                            "policy_id": policy_a.policy_id,
                            "version": policy_a.version,
                            "priority": policy_a.priority,
                            "enabled": policy_a.enabled,
                            "mode": policy_a.mode.value,
                            "active": active_a,
                        },
                        {
                            "policy_id": policy_b.policy_id,
                            "version": policy_b.version,
                            "priority": policy_b.priority,
                            "enabled": policy_b.enabled,
                            "mode": policy_b.mode.value,
                            "active": active_b,
                        },
                    ],
                    "rules": [
                        {
                            "policy_id": policy_a.policy_id,
                            "rule_id": rule_a.rule_id,
                            "decision": rule_a.decision.value,
                            "priority": rule_a.priority,
                            "action_type": rule_a.action_type,
                            "action_name": rule_a.action_name,
                        },
                        {
                            "policy_id": policy_b.policy_id,
                            "rule_id": rule_b.rule_id,
                            "decision": rule_b.decision.value,
                            "priority": rule_b.priority,
                            "action_type": rule_b.action_type,
                            "action_name": rule_b.action_name,
                        },
                    ],
                    "overlap": {
                        "action_type": [rule_a.action_type, rule_b.action_type],
                        "action_name": [rule_a.action_name, rule_b.action_name],
                        "risk_range": [risk_lo, risk_hi],
                        "severities": severities,
                        "scope_keys": overlapping_scope_keys(
                            rule_a.target_scope, rule_b.target_scope
                        ),
                        "scope_a": rule_a.target_scope or {},
                        "scope_b": rule_b.target_scope or {},
                    },
                    "precedence": {
                        "winner_policy_id": w_policy.policy_id,
                        "winner_policy_version": w_policy.version,
                        "winner_rule_id": w_rule.rule_id,
                        "reason": reason,
                    },
                    "shadowed": {
                        "policy_id": l_policy.policy_id,
                        "rule_id": l_rule.rule_id,
                        "coverage": coverage,
                    },
                    "ambiguous": bool(runtime and not full_shadow),
                    "advisory": ADVISORY_NOTE,
                    "explanation": explanation,
                }
            )

    findings.sort(key=lambda f: f["conflict_id"])
    return findings
