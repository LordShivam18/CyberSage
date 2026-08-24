"""Deterministic policy engine.

Evaluates risk scores and evidence to produce ResponseDecision recommendations.
All output is data-only — no commands are executed.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class ResponseDecision:
    """Data-only response recommendation.

    This is a recommendation, NOT an executable action.
    All fields are informational.
    """

    decision_id: str = field(default_factory=lambda: f"rd-{uuid.uuid4().hex[:16]}")
    incident_id: Optional[str] = None
    severity: str = "low"
    confidence: float = 0.0
    recommended_action: str = "monitor"  # monitor | investigate | approve_containment | prepare_containment
    rationale: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    expected_effect: str = ""
    risk: Optional[Dict[str, Any]] = None
    requires_approval: bool = True
    rollback_available: bool = False
    verification_plan: str = ""
    created_at: datetime = field(default_factory=_now_utc)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


# Policy thresholds
THRESHOLD_MONITOR = 20.0
THRESHOLD_INVESTIGATE = 40.0
THRESHOLD_APPROVE_CONTAINMENT = 65.0
THRESHOLD_PREPARE_CONTAINMENT = 85.0

# Actions that require explicit user approval
APPROVAL_REQUIRED_ACTIONS = frozenset({
    "approve_containment",
    "prepare_containment",
})

# Actions that are rollback-capable
ROLLBACK_CAPABLE_ACTIONS = frozenset({
    "approve_containment",
    "prepare_containment",
})


class PolicyEngine:
    """Deterministic policy engine.

    Maps risk scores to response recommendations.
    """

    def evaluate(
        self,
        risk_score: float,
        risk_severity: str,
        risk_confidence: float,
        risk_factors: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        incident_id: Optional[str] = None,
    ) -> ResponseDecision:
        """Evaluate risk and evidence to produce a response recommendation.

        Args:
            risk_score: Deterministic risk score (0-100).
            risk_severity: Severity string from risk engine.
            risk_confidence: Confidence from risk engine.
            risk_factors: Risk factors from risk engine.
            evidence: Evidence dicts.
            incident_id: Optional incident candidate ID.

        Returns:
            ResponseDecision with recommendation.
        """
        # Determine action based on score thresholds
        if risk_score >= THRESHOLD_PREPARE_CONTAINMENT:
            action = "prepare_containment"
        elif risk_score >= THRESHOLD_APPROVE_CONTAINMENT:
            action = "approve_containment"
        elif risk_score >= THRESHOLD_INVESTIGATE:
            action = "investigate"
        else:
            action = "monitor"

        requires_approval = action in APPROVAL_REQUIRED_ACTIONS
        rollback_available = action in ROLLBACK_CAPABLE_ACTIONS

        # Build rationale
        rationale = self._build_rationale(action, risk_score, risk_severity, evidence)

        # Build expected effect
        expected_effect = self._build_expected_effect(action)

        # Build verification plan
        verification_plan = self._build_verification_plan(action)

        return ResponseDecision(
            incident_id=incident_id,
            severity=risk_severity,
            confidence=risk_confidence,
            recommended_action=action,
            rationale=rationale,
            evidence=evidence[:10],  # cap evidence list
            expected_effect=expected_effect,
            risk={
                "score": risk_score,
                "severity": risk_severity,
                "confidence": risk_confidence,
                "factors": risk_factors,
            },
            requires_approval=requires_approval,
            rollback_available=rollback_available,
            verification_plan=verification_plan,
        )

    def _build_rationale(
        self, action: str, score: float, severity: str, evidence: List[Dict[str, Any]]
    ) -> str:
        """Build a human-readable rationale for the decision."""
        count = len(evidence)
        if action == "prepare_containment":
            return (
                f"Risk score {score:.1f} ({severity}) with {count} evidence signals "
                f"indicates active threat. Prepare containment pending approval."
            )
        elif action == "approve_containment":
            return (
                f"Risk score {score:.1f} ({severity}) with {count} evidence signals "
                f"requires containment. Awaiting explicit user approval."
            )
        elif action == "investigate":
            return (
                f"Risk score {score:.1f} ({severity}) with {count} evidence signals "
                f"requires investigation before determining next steps."
            )
        else:
            return (
                f"Risk score {score:.1f} ({severity}) with {count} evidence signals "
                f"is within normal bounds. Continue monitoring."
            )

    def _build_expected_effect(self, action: str) -> str:
        """Describe the expected effect of the recommended action."""
        effects = {
            "monitor": "Continue collecting telemetry. No system changes.",
            "investigate": "Analyst reviews evidence and determines response.",
            "approve_containment": "Pending user approval to isolate affected components.",
            "prepare_containment": "Prepare containment measures pending final approval.",
        }
        return effects.get(action, "No action specified.")

    def _build_verification_plan(self, action: str) -> str:
        """Build a verification plan for the recommended action."""
        plans = {
            "monitor": "Verify continued event ingestion and detection output.",
            "investigate": "Verify analyst receives evidence package and investigation ticket.",
            "approve_containment": "Verify approval is recorded before any containment executes.",
            "prepare_containment": "Verify containment preparation is logged and rollback is available.",
        }
        return plans.get(action, "No verification plan specified.")
