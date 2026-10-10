"""Pilot evidence schema and reconciliation report (no collection runs here).

The schema lets an operator reconcile source events through detections,
evidence, incidents, risk/policy, approvals/authorization, attempts,
verification, and audit — with dropped/quarantined/delayed/duplicate/
unresolved records explicit. The chain is complete only when nothing
required is missing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

EVIDENCE_SCHEMA_VERSION = 1

CHAIN_STAGES = (
    "source_events", "observed_events", "persisted_events", "detections",
    "evidence_groups", "incidents", "risk_policy_decisions", "approvals",
    "authorization_checks", "action_attempts", "verification_results",
    "audit_records",
)

NEGATIVE_BUCKETS = ("dropped", "quarantined", "delayed", "duplicate", "unresolved")


@dataclass
class PilotEvidence:
    scenario_id: str
    correlation_id: str
    stages: Dict[str, int] = field(default_factory=dict)
    negatives: Dict[str, int] = field(default_factory=dict)
    unresolved: List[str] = field(default_factory=list)
    synthetic: bool = False
    schema_version: int = EVIDENCE_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def new_evidence(scenario_id: str, correlation_id: str, *, synthetic: bool = False) -> PilotEvidence:
    """Blank evidence record. Pilot results start blank until real collection."""
    return PilotEvidence(scenario_id=scenario_id, correlation_id=correlation_id,
                         stages={stage: 0 for stage in CHAIN_STAGES},
                         negatives={bucket: 0 for bucket in NEGATIVE_BUCKETS},
                         unresolved=[], synthetic=synthetic)


def reconcile(evidence: PilotEvidence) -> Dict[str, Any]:
    """Reconcile the chain. Complete only with zero unresolved and no silent drops."""
    missing = [stage for stage in CHAIN_STAGES if evidence.stages.get(stage, 0) <= 0
               and stage not in ("evidence_groups", "incidents")]
    gaps = list(evidence.unresolved)
    if evidence.negatives.get("dropped", 0) > 0 and "dropped>0" not in gaps:
        gaps.append("dropped>0 requires an explanation entry")
    complete = not missing and not gaps
    return {"scenario_id": evidence.scenario_id, "correlation_id": evidence.correlation_id,
            "complete": complete, "missing_stages": missing,
            "unresolved": gaps, "synthetic": evidence.synthetic,
            "note": "synthetic rows are labeled and never counted as pilot evidence"}


def blank_pilot_report(scenarios: List[str]) -> Dict[str, Any]:
    """Blank multi-scenario report shell. Results stay blank until collected."""
    return {"schema_version": EVIDENCE_SCHEMA_VERSION, "status": "awaiting_pilot_evidence",
            "scenarios": {scenario: {"status": "not_run", "evidence": None} for scenario in scenarios}}
