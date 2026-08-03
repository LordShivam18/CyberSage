import json
import time

from backend.detection_types import DetectorResult
from backend.config import Settings
from backend.inference import ModelDetector
from backend.mitre import map_to_mitre
from backend.risk import RiskScorer, severity_from_score
from backend.rules_engine import RuleEngine
from backend.threat_intel_service import ThreatIntelProvider, ThreatIntelService
from backend.telemetry import normalize_synthetic_event


def test_model_detector_fallback_returns_binary_prediction():
    detector = ModelDetector()
    result = detector.predict_features(
        {
            "flow_duration": 119999872,
            "tot_fwd_pkts": 100,
            "tot_bwd_pkts": 200,
            "totlen_fwd_pkts": 50000,
            "fwd_pkt_len_max": 1500,
            "fwd_pkt_len_min": 0,
            "fwd_pkt_len_mean": 500,
            "bwd_pkt_len_max": 3000,
            "flow_iat_mean": 1000,
            "flow_iat_max": 5000000,
            "fwd_iat_tot": 120000000,
        }
    )

    assert result.classification in {"ATTACK", "BENIGN"}
    assert "ATTACK" in result.probabilities


def test_rule_engine_validates_and_matches_rules(tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "TEST_BYTES",
                        "name": "Test bytes",
                        "description": "test",
                        "severity": "high",
                        "conditions": {"field": "bytes_sent", "operator": "gte", "threshold": 100},
                        "mitre_techniques": ["T1041"],
                        "investigation_actions": ["Review flow"],
                    }
                ]
            }
        )
    )
    engine = RuleEngine(rules_path=rules_path)
    event = normalize_synthetic_event({"event_id": "r1", "bytes_sent": 200, "timestamp": "2026-01-01T00:00:00Z"})

    result = engine.evaluate(event)

    assert engine.error is None
    assert result.classification == "RULE_MATCH"
    assert result.triggered_rules[0]["id"] == "TEST_BYTES"


def test_invalid_rule_configuration_is_rejected(tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "BAD",
                        "name": "Bad",
                        "description": "bad",
                        "severity": "urgent",
                        "conditions": {"field": "bytes_sent", "operator": "gte", "threshold": 100},
                    }
                ]
            }
        )
    )

    engine = RuleEngine(rules_path=rules_path)

    assert engine.rules == []
    assert "Unsupported severity" in engine.error


def test_risk_score_keeps_components_explainable():
    scorer = RiskScorer()
    risk = scorer.score(
        DetectorResult(source="ml", classification="ATTACK", confidence=0.9, probabilities={"ATTACK": 0.9}),
        DetectorResult(source="anomaly", classification="ANOMALY", confidence=0.8, anomaly_score=0.8),
        DetectorResult(source="rules", classification="RULE_MATCH", confidence=1, triggered_rules=[{"severity": "high"}]),
        threat_intel_hits=[{"confidence": 0.7}],
        repeat_occurrence_count=3,
    )

    assert risk.score > 0
    assert set(risk.components) == {
        "ml_confidence",
        "anomaly_score",
        "rule_severity",
        "threat_intel_confidence",
        "asset_criticality",
        "repeat_occurrence_count",
    }
    assert severity_from_score(risk.score) == risk.severity


def test_mitre_mapping_uses_classes_and_rule_ids():
    techniques = map_to_mitre("ATTACK", rule_ids=["SUSPICIOUS_OUTBOUND_VOLUME"])

    assert "T1046" in techniques
    assert "T1041" in techniques


def test_insecure_production_jwt_secret_fails_safely():
    settings = Settings(
        environment="production",
        jwt_secret="development-only-change-me",
        cors_origins=["http://localhost:3000"],
    )

    try:
        settings.validate_runtime_security()
    except RuntimeError as exc:
        assert "JWT_SECRET" in str(exc)
    else:
        raise AssertionError("production settings accepted an insecure JWT secret")


class SlowProvider(ThreatIntelProvider):
    name = "slow-test-provider"

    def lookup(self, indicator: str, indicator_type: str):
        time.sleep(0.01)
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "source": self.name,
            "confidence": 0.9,
            "verdict": "malicious",
            "details": {},
        }


def test_threat_intelligence_timeout_records_provenance():
    service = ThreatIntelService(providers=[SlowProvider()], timeout_seconds=0.0)

    results = service.lookup("203.0.113.66", "ip")

    assert results[0]["verdict"] == "timeout"
    assert results[0]["source"] == "slow-test-provider"
