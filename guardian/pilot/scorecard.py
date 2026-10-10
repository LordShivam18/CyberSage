"""Pilot scorecard and go/no-go gates (templates + evaluation, no pilot runs).

Each metric names its calculation, evidence source, window, threshold (or
human-approval requirement), missing-data treatment, and owner. Decisions:
proceed, extend observation, remediate, or stop. Broader rollout needs
actual evidence plus authorized sign-off — never implementation existence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

DECISIONS = ("proceed", "extend", "remediate", "stop")


@dataclass
class ScorecardRow:
    metric: str
    calculation: str
    evidence_source: str
    window: str
    threshold: str
    missing_data: str
    owner: str
    result: str = "not_measured"
    decision: str = "extend"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def monitoring_scorecard(window: str = "baseline + observation") -> List[ScorecardRow]:
    """Go/no-go rows for monitoring mode."""
    return [
        ScorecardRow("telemetry_completeness", "persisted_events / observed_events",
                     "agent queue + backend GuardianEvent rows", window,
                     ">= 0.99 with every gap explained", "gaps block proceed; extend",
                     "pilot_owner"),
        ScorecardRow("detection_precision", "metrics.detection_quality (labeled scenarios)",
                     "corpus labels + detection rows", window,
                     "reviewed by detection owner; no fixed universal bar",
                     "inconclusive without valid labels; extend", "detection_owner"),
        ScorecardRow("false_positive_load", "false positives per endpoint-day (benign workloads)",
                     "workload_observations", window,
                     "operator-reviewed acceptable load", "missing workload logs block proceed",
                     "operator_lead"),
        ScorecardRow("non_execution", "modes.assert_no_executions over the window",
                     "envelope runs listing", window, "zero executed (blocked rows only)",
                     "any executed row forces stop + incident review", "security_lead"),
        ScorecardRow("resource_impact", "metrics.resource_summary vs pilot thresholds",
                     "agent/backend telemetry", window, "within configured pilot thresholds",
                     "missing provenance blocks proceed", "platform_owner"),
        ScorecardRow("audit_completeness", "evidence.reconcile per scenario",
                     "reconciliation reports", window, "complete chains, zero unexplained gaps",
                     "unresolved items block proceed", "security_lead"),
    ]


def approved_manual_scorecard(window: str = "controlled window") -> List[ScorecardRow]:
    """Go/no-go rows for approved-manual mode (includes monitoring rows)."""
    rows = monitoring_scorecard(window)
    rows += [
        ScorecardRow("approval_discipline", "executed only with valid approvals; replays safe",
                     "approvals + envelope gates + audit", window,
                     "100% authorized; zero stale/mismatched executions",
                     "any unauthorized execution forces stop", "security_lead"),
        ScorecardRow("verification_rate", "verified_ok / approved_executed",
                     "verification results", window, "reviewed; failures need rollback evidence",
                     "missing verification blocks proceed", "operator_lead"),
        ScorecardRow("action_latency", "latency distributions incl. censored attempts",
                     "stage timestamps", window, "reported with censoring; no threshold gaming",
                     "excluded difficult cases force remediate", "operator_lead"),
        ScorecardRow("kill_revoke_drill", "kill-switch + revocation drill blocks as specified",
                     "drill records + gates", "drill day", "blocked at the expected gate",
                     "failed drill forces stop", "security_lead"),
    ]
    return rows


def bounded_preauth_gate() -> List[ScorecardRow]:
    """Entry gate for ANY future narrowly scoped preauthorized use (not enabled here)."""
    return [
        ScorecardRow("evidence_threshold", "monitoring + approved-manual scorecards reviewed",
                     "signed scorecards", "full pilot window",
                     "human sign-off by administrator + security_lead + policy_owner",
                     "no sign-off means no grant; decision stays extend/stop",
                     "security_lead"),
        ScorecardRow("scope_approval", "explicit actions/targets/risk/duration/limits/cooldowns",
                     "grant proposal + preauth_evaluation_requirements",
                     "per proposal", "recorded approval before any activation",
                     "missing scope blocks activation", "policy_owner"),
    ]


@dataclass
class SignOff:
    decision: str
    rationale: str
    signers: List[str] = field(default_factory=list)
    date: str = ""

    def finalize(self) -> Dict[str, Any]:
        if self.decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}")
        if not self.signers:
            raise ValueError("sign-off requires at least one named signer")
        if not self.rationale:
            raise ValueError("sign-off requires a rationale tied to evidence")
        return asdict(self)
