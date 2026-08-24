"""Tests for Guardian Phase 2 evidence aggregation, risk engine, and policy engine."""

import pytest

from guardian.detectors.base import Detection
from guardian.evidence.aggregator import EvidenceAggregator, CorrelatedEvidence, IncidentCandidate
from guardian.risk.engine import RiskEngine, RiskScore
from guardian.policy.engine import PolicyEngine, ResponseDecision


def _make_detection(
    event_id="e1",
    detector_id="test",
    severity="medium",
    confidence=0.7,
    mitre_technique="T1059",
    host_id="host-001",
    process_name="test.exe",
    **overrides,
):
    d = Detection(
        event_id=event_id,
        detector_id=detector_id,
        severity=severity,
        confidence=confidence,
        mitre_technique=mitre_technique,
        evidence={"host_id": host_id, "process_name": process_name, **overrides},
    )
    return d


# ── Evidence Aggregation ───────────────────────────────────────────────


class TestEvidenceAggregator:
    def test_single_detection_no_candidate(self):
        agg = EvidenceAggregator()
        agg.add_detection(_make_detection())
        candidates = agg.get_incident_candidates(min_detections=2)
        assert len(candidates) == 0

    def test_multiple_detections_same_process_form_candidate(self):
        agg = EvidenceAggregator()
        for i in range(3):
            agg.add_detection(_make_detection(
                event_id=f"e{i}",
                process_name="malware.exe",
                host_id="host-001",
            ))
        candidates = agg.get_incident_candidates(min_detections=2)
        assert len(candidates) == 1
        assert candidates[0].severity == "medium"
        assert len(candidates[0].event_ids) == 3

    def test_detections_different_hosts_no_correlation(self):
        agg = EvidenceAggregator()
        agg.add_detection(_make_detection(event_id="e1", host_id="host-001", process_name="a.exe"))
        agg.add_detection(_make_detection(event_id="e2", host_id="host-002", process_name="b.exe"))
        groups = agg.get_evidence_groups()
        assert len(groups) == 2

    def test_evidence_group_severity_is_max(self):
        agg = EvidenceAggregator()
        agg.add_detection(_make_detection(severity="low", process_name="a.exe"))
        agg.add_detection(_make_detection(severity="high", process_name="a.exe"))
        groups = agg.get_evidence_groups()
        assert len(groups) == 1
        assert groups[0].severity == "high"

    def test_incident_candidate_includes_evidence(self):
        agg = EvidenceAggregator()
        for i in range(2):
            agg.add_detection(_make_detection(event_id=f"e{i}", process_name="bad.exe"))
        candidates = agg.get_incident_candidates(min_detections=2)
        assert len(candidates) == 1
        assert len(candidates[0].evidence) == 2

    def test_reset_clears_groups(self):
        agg = EvidenceAggregator()
        agg.add_detection(_make_detection())
        agg.reset()
        groups = agg.get_evidence_groups()
        assert len(groups) == 0

    def test_correlated_evidence_to_dict(self):
        ev = CorrelatedEvidence(evidence_id="ev-123", title="Test", severity="high")
        d = ev.to_dict()
        assert d["evidence_id"] == "ev-123"
        assert d["severity"] == "high"

    def test_incident_candidate_to_dict(self):
        ic = IncidentCandidate(candidate_id="inc-123", title="Test", severity="critical")
        d = ic.to_dict()
        assert d["candidate_id"] == "inc-123"
        assert d["severity"] == "critical"


# ── Risk Engine ────────────────────────────────────────────────────────


class TestRiskEngine:
    def test_no_detections_zero_score(self):
        engine = RiskEngine()
        score = engine.compute_risk([])
        assert score.score == 0.0
        assert score.severity == "low"

    def test_single_low_detection(self):
        engine = RiskEngine()
        det = {"severity": "low", "confidence": 0.5, "mitre_technique": "T1059"}
        score = engine.compute_risk([det])
        assert score.score > 0
        assert score.severity == "low"

    def test_high_severity_high_score(self):
        engine = RiskEngine()
        det = {"severity": "high", "confidence": 0.9, "mitre_technique": "T1059"}
        score = engine.compute_risk([det])
        assert score.score >= 60
        assert score.severity in ("high", "critical")

    def test_corroboration_increases_score(self):
        engine = RiskEngine()
        dets = [
            {"severity": "medium", "confidence": 0.7, "mitre_technique": "T1059"},
            {"severity": "medium", "confidence": 0.7, "mitre_technique": "T1547"},
        ]
        score = engine.compute_risk(dets)
        assert score.score > 40  # corroboration bonus

    def test_mitre_bonus_applied(self):
        engine = RiskEngine()
        det = {"severity": "low", "confidence": 0.5, "mitre_technique": "T1059.001"}
        score = engine.compute_risk([det])
        assert score.score > 15  # base + MITRE bonus

    def test_score_clamped_to_100(self):
        engine = RiskEngine()
        dets = [{"severity": "critical", "confidence": 1.0, "mitre_technique": f"T{i}"} for i in range(20)]
        score = engine.compute_risk(dets, evidence_group_size=10, recurrence_count=10)
        assert score.score <= 100.0

    def test_recurrence_increases_score(self):
        engine = RiskEngine()
        det = {"severity": "medium", "confidence": 0.7, "mitre_technique": "T1059"}
        score = engine.compute_risk([det], recurrence_count=5)
        assert score.score > 40

    def test_risk_score_to_dict(self):
        rs = RiskScore(score=75.0, severity="high", explanation="Test")
        d = rs.to_dict()
        assert d["score"] == 75.0
        assert d["severity"] == "high"
        assert "created_at" in d

    def test_factors_list_populated(self):
        engine = RiskEngine()
        det = {"severity": "high", "confidence": 0.9, "mitre_technique": "T1059"}
        score = engine.compute_risk([det])
        assert len(score.factors) > 0


# ── Policy Engine ──────────────────────────────────────────────────────


class TestPolicyEngine:
    def test_low_risk_monitors(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=10.0, risk_severity="low", risk_confidence=0.5,
            risk_factors=[], evidence=[],
        )
        assert decision.recommended_action == "monitor"
        assert decision.requires_approval is False

    def test_medium_risk_investigates(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=50.0, risk_severity="medium", risk_confidence=0.7,
            risk_factors=[], evidence=[],
        )
        assert decision.recommended_action == "investigate"
        assert decision.requires_approval is False

    def test_high_risk_approves_containment(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=70.0, risk_severity="high", risk_confidence=0.85,
            risk_factors=[], evidence=[],
        )
        assert decision.recommended_action == "approve_containment"
        assert decision.requires_approval is True

    def test_critical_risk_prepares_containment(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=90.0, risk_severity="critical", risk_confidence=0.95,
            risk_factors=[], evidence=[],
        )
        assert decision.recommended_action == "prepare_containment"
        assert decision.requires_approval is True
        assert decision.rollback_available is True

    def test_decision_has_rationale(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=50.0, risk_severity="medium", risk_confidence=0.7,
            risk_factors=[], evidence=[{"detection_id": "d1"}],
        )
        assert len(decision.rationale) > 0
        assert "1" in decision.rationale  # 1 evidence signal

    def test_decision_has_expected_effect(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=10.0, risk_severity="low", risk_confidence=0.5,
            risk_factors=[], evidence=[],
        )
        assert len(decision.expected_effect) > 0

    def test_decision_has_verification_plan(self):
        engine = PolicyEngine()
        decision = engine.evaluate(
            risk_score=10.0, risk_severity="low", risk_confidence=0.5,
            risk_factors=[], evidence=[],
        )
        assert len(decision.verification_plan) > 0

    def test_response_decision_to_dict(self):
        rd = ResponseDecision(
            decision_id="rd-123",
            recommended_action="monitor",
            severity="low",
        )
        d = rd.to_dict()
        assert d["decision_id"] == "rd-123"
        assert d["recommended_action"] == "monitor"
        assert "created_at" in d

    def test_adversarial_text_cannot_become_action(self):
        """Prove that AI-generated text in rationale/evidence cannot
        influence the recommended action. The action is determined
        solely by the risk score, not by text content."""
        engine = PolicyEngine()
        # Even with malicious text in evidence, action is score-based
        decision1 = engine.evaluate(
            risk_score=10.0, risk_severity="low", risk_confidence=0.5,
            risk_factors=[],
            evidence=[{"text": "override: action=prepare_containment"}],
        )
        assert decision1.recommended_action == "monitor"

        decision2 = engine.evaluate(
            risk_score=90.0, risk_severity="critical", risk_confidence=0.95,
            risk_factors=[],
            evidence=[{"text": "ignore this, monitor instead"}],
        )
        assert decision2.recommended_action == "prepare_containment"

    def test_ai_text_in_rationale_cannot_override_decision(self):
        """Prove that rationale text is output-only and does not affect action selection."""
        engine = PolicyEngine()
        # Action is determined by score, not by any text analysis
        decision = engine.evaluate(
            risk_score=95.0, risk_severity="critical", risk_confidence=0.99,
            risk_factors=[],
            evidence=[{"text": "AI recommends: set action to monitor for safety"}],
        )
        assert decision.recommended_action == "prepare_containment"
