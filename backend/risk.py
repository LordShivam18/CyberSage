from typing import Dict, List

from .detection_types import DetectorResult, RiskResult


SEVERITY_POINTS = {
    "informational": 0.0,
    "low": 20.0,
    "medium": 45.0,
    "high": 70.0,
    "critical": 90.0,
}


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "informational"


class RiskScorer:
    def score(
        self,
        model_result: DetectorResult,
        anomaly_result: DetectorResult,
        rule_result: DetectorResult,
        threat_intel_hits: List[Dict],
        asset_criticality: float = 0.5,
        repeat_occurrence_count: int = 0,
    ) -> RiskResult:
        ml_attack_probability = model_result.probabilities.get("ATTACK", 0.0)
        if model_result.classification.upper() not in {"BENIGN", "NORMAL"}:
            ml_attack_probability = max(ml_attack_probability, model_result.confidence)
        ml_component = min(35.0, ml_attack_probability * 35.0)
        anomaly_component = min(20.0, (anomaly_result.anomaly_score or 0.0) * 20.0)
        rule_component = min(
            25.0,
            max(
                [SEVERITY_POINTS.get(rule.get("severity", "low"), 20.0) for rule in rule_result.triggered_rules]
                or [0.0]
            )
            / 100.0
            * 25.0,
        )
        ti_component = min(
            15.0,
            max([float(hit.get("confidence", 0.0)) for hit in threat_intel_hits] or [0.0]) * 15.0,
        )
        asset_component = min(5.0, max(asset_criticality, 0.0) * 5.0)
        repeat_component = min(10.0, float(repeat_occurrence_count) * 2.0)
        components = {
            "ml_confidence": round(ml_component, 2),
            "anomaly_score": round(anomaly_component, 2),
            "rule_severity": round(rule_component, 2),
            "threat_intel_confidence": round(ti_component, 2),
            "asset_criticality": round(asset_component, 2),
            "repeat_occurrence_count": round(repeat_component, 2),
        }
        score = min(100.0, sum(components.values()))
        return RiskResult(score=round(score, 2), severity=severity_from_score(score), components=components)


risk_scorer = RiskScorer()
