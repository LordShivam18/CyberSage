"""Pilot operational modes and enforcement helpers (no execution here).

Monitoring: collect + evaluate; response actions must not execute, and
non-execution is observable (zero non-blocked envelope runs for the window).
Approved-manual: every response action needs an authorized approval with
full revalidation; kill-switch and revocation keep precedence.
Bounded pre-authorization: disabled by default; the pilot may only
EVALUATE future narrowly scoped use cases against an evidence threshold
with explicit future human authorization — this module never activates a
grant. Global/unrestricted autonomy is rejected categorically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

GLOBAL_AUTONOMY_DISABLED = True

FORBIDDEN_MODE_NAMES = frozenset({
    "autonomous", "fully_automated", "unrestricted", "global_auto",
    "auto_remediate_all", "preauthorized_all",
})


@dataclass
class ModeDecision:
    allowed: bool
    mode: str
    reason: str


def check_mode_allowed(mode: str) -> ModeDecision:
    """Validate a requested pilot mode name. Fail closed."""
    normalized = str(mode or "").strip().lower()
    if normalized in ("monitoring", "monitor"):
        return ModeDecision(True, "monitoring", "collect and evaluate; no response execution")
    if normalized in ("approved_manual", "approved-manual", "manual"):
        return ModeDecision(True, "approved_manual", "authorized approval required per action")
    if normalized in FORBIDDEN_MODE_NAMES or "autonom" in normalized or "unrestrict" in normalized:
        return ModeDecision(False, normalized, "global/unrestricted autonomy is disabled and cannot be piloted")
    if "preauth" in normalized or "pre-author" in normalized or "pre_author" in normalized:
        return ModeDecision(False, normalized,
                            "bounded pre-authorization needs a separate future authorization with "
                            "evidence threshold, roles, scope, limits, and revocation plan; "
                            "it is not enabled by joining the pilot")
    return ModeDecision(False, normalized, "unknown pilot mode")


def assert_no_executions(envelope_runs: List[Dict[str, Any]], *, window: str) -> Dict[str, Any]:
    """Monitoring-mode check: prove non-execution from recorded evidence.

    Returns {ok, executed, blocked_or_empty}. Executed = any run whose
    status is not 'blocked'. Callers supply rows from the existing
    executions listing; this function performs no I/O.
    """
    executed = [run for run in envelope_runs
                if str(run.get("status", "")).lower() != "blocked"]
    return {"ok": not executed, "window": window,
            "executed": len(executed), "total": len(envelope_runs)}


def preauth_evaluation_requirements() -> Dict[str, Any]:
    """Governance checklist a FUTURE bounded-use proposal must satisfy."""
    return {
        "evidence_threshold": "monitoring + approved-manual scorecards reviewed over the full window",
        "approving_roles": ["administrator", "security_lead", "policy_owner"],
        "permitted_scope": "explicit actions + target/agent scope (concrete, no wildcards)",
        "risk_limits": "max risk cap at or below the approved-manual observed maximum",
        "duration": "bounded expiry (days, not open-ended)",
        "execution_limits": "max/hour + cooldown recorded in the grant",
        "verification": "independent verification + explicit rollback policy per action",
        "revocation": "named revoker, procedure, and emergency stop pre-agreed",
        "activation": "explicit future human authorization via POST /preauth/activate (never automatic)",
    }
