"""Deterministic risk scoring engine.

Computes a risk score from detection attributes, evidence correlation,
and contextual factors. No LLM involvement in score calculation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Severity base scores (0-100 scale)
SEVERITY_BASE_SCORES = {
    "critical": 90,
    "high": 70,
    "medium": 40,
    "low": 15,
    "informational": 5,
}

# MITRE technique bonus scores
MITRE_BONUS = {
    "T1059": 10,   # Command and Scripting Interpreter
    "T1059.001": 15,  # PowerShell
    "T1059.003": 10,  # Windows Command Shell
    "T1547": 12,   # Boot or Logon Autostart Execution
    "T1571": 8,    # Non-Standard Port
    "T1071": 8,    # Application Layer Protocol
    "T1071.004": 10,  # DNS
    "T1027": 5,    # Obfuscated Files or Information
    "T1055": 15,   # Process Injection
    "T1003": 12,   # OS Credential Dumping
    "T1087": 5,    # Account Discovery
    "T1105": 8,    # Ingress Tool Transfer
    "T1569": 10,   # System Services
}


@dataclass
class RiskScore:
    """Deterministic risk score with explanation."""

    score: float = 0.0  # 0-100 scale
    severity: str = "low"  # derived from score
    confidence: float = 0.0  # weighted average of input confidences
    factors: List[Dict[str, Any]] = field(default_factory=list)
    explanation: str = ""
    created_at: datetime = field(default_factory=_now_utc)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


class RiskEngine:
    """Deterministic risk scoring engine.

    Computes risk from:
    - Detection severity and confidence
    - MITRE technique bonuses
    - Corroborating signal count
    - Evidence group size
    """

    def __init__(self) -> None:
        self._max_score = 100.0

    def compute_risk(
        self,
        detections: List[Dict[str, Any]],
        evidence_group_size: int = 1,
        recurrence_count: int = 1,
    ) -> RiskScore:
        """Compute a deterministic risk score.

        Args:
            detections: List of detection dicts.
            evidence_group_size: Number of correlated evidence groups.
            recurrence_count: How many times this pattern has been seen.

        Returns:
            RiskScore with score, severity, confidence, factors, and explanation.
        """
        if not detections:
            return RiskScore(score=0.0, severity="low", explanation="No detections to evaluate")

        factors: List[Dict[str, Any]] = []
        total_score = 0.0
        total_confidence = 0.0
        detection_count = len(detections)

        # 1. Base severity score (take highest)
        severity_scores = []
        for det in detections:
            sev = det.get("severity", "low")
            base = SEVERITY_BASE_SCORES.get(sev, 10)
            severity_scores.append(base)
            factors.append({
                "name": f"severity_{sev}",
                "value": base,
                "source": det.get("detector_id", "unknown"),
            })
        max_severity = max(severity_scores)
        total_score += max_severity

        # 2. Confidence (weighted average)
        for det in detections:
            conf = det.get("confidence", 0.0)
            total_confidence += conf
        avg_confidence = total_confidence / detection_count

        # 3. MITRE technique bonuses (deduplicated)
        seen_techniques = set()
        for det in detections:
            technique = det.get("mitre_technique", "")
            if technique and technique not in seen_techniques:
                bonus = MITRE_BONUS.get(technique, 3)
                total_score += bonus
                factors.append({
                    "name": f"mitre_{technique}",
                    "value": bonus,
                    "source": "mitre_mapping",
                })
                seen_techniques.add(technique)

        # 4. Corroborating signals bonus
        if detection_count > 1:
            corroboration_bonus = min((detection_count - 1) * 5, 20)
            total_score += corroboration_bonus
            factors.append({
                "name": "corroborating_signals",
                "value": corroboration_bonus,
                "detail": f"{detection_count} detections",
            })

        # 5. Evidence group size bonus
        if evidence_group_size > 1:
            evidence_bonus = min((evidence_group_size - 1) * 3, 15)
            total_score += evidence_bonus
            factors.append({
                "name": "evidence_groups",
                "value": evidence_bonus,
                "detail": f"{evidence_group_size} groups",
            })

        # 6. Recurrence penalty
        if recurrence_count > 1:
            recurrence_bonus = min((recurrence_count - 1) * 2, 10)
            total_score += recurrence_bonus
            factors.append({
                "name": "recurrence",
                "value": recurrence_bonus,
                "detail": f"{recurrence_count} occurrences",
            })

        # Clamp to 0-100
        total_score = max(0.0, min(self._max_score, total_score))

        # Derive severity from score
        if total_score >= 80:
            severity = "critical"
        elif total_score >= 60:
            severity = "high"
        elif total_score >= 35:
            severity = "medium"
        else:
            severity = "low"

        # Build explanation
        top_factors = sorted(factors, key=lambda f: f.get("value", 0), reverse=True)[:3]
        factor_names = ", ".join(f["name"] for f in top_factors)
        explanation = (
            f"Risk score {total_score:.1f}/100 ({severity}). "
            f"Based on {detection_count} detection(s). "
            f"Top contributing factors: {factor_names}."
        )

        return RiskScore(
            score=round(total_score, 1),
            severity=severity,
            confidence=round(avg_confidence, 3),
            factors=factors,
            explanation=explanation,
        )
