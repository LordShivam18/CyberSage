"""Phase 9 pilot-readiness harness (PROVIDED — NOT EXECUTED).

Genuine configuration/mode/metric/evidence/scorecard contract checks for
the developer to run later. Pure functions and temporary structures only.
No endpoint enrollment, no execution, no measurement runs, no network use.
"""

import pytest

from guardian.pilot import config as pilot_config
from guardian.pilot import evidence as evidence_mod
from guardian.pilot import metrics as metrics_mod
from guardian.pilot import modes as modes_mod
from guardian.pilot import scorecard as scorecard_mod


def _valid_config(**over):
    base = {
        "objectives": ["prove telemetry completeness"],
        "scope": "3 isolated endpoints",
        "owner": "pilot-owner",
        "duration_days": 14,
        "endpoints": [],
        "eligible_os": ["Windows 11"],
        "modes": ["monitoring"],
        "baseline_days": 7,
        "benign_workloads": ["office profile"],
        "test_scenarios": ["e2e-benign-process"],
        "exclusions": ["production enrollment"],
        "change_control": "written approval",
        "operator_responsibilities": ["daily review"],
        "escalation_contacts": ["security-lead"],
        "evidence_rules": ["correlation ids required"],
        "stop_conditions": ["unexpected execution"],
    }
    base.update(over)
    return base


def test_pilot_config_requires_scope_and_rejects_autonomy():
    with pytest.raises(ValueError):
        pilot_config.validate_pilot_config(_valid_config(modes=["autonomous"]))
    with pytest.raises(ValueError):
        pilot_config.validate_pilot_config(_valid_config(stop_conditions=[]))
    config = pilot_config.validate_pilot_config(_valid_config())
    assert config.endpoints == [] and config.modes == ["monitoring"]


def test_modes_reject_global_autonomy_and_gate_preauth():
    assert modes_mod.GLOBAL_AUTONOMY_DISABLED is True
    assert modes_mod.check_mode_allowed("monitoring").allowed is True
    assert modes_mod.check_mode_allowed("approved_manual").allowed is True
    assert modes_mod.check_mode_allowed("unrestricted").allowed is False
    assert modes_mod.check_mode_allowed("bounded_preauth_now").allowed is False
    assert "explicit future human authorization" in modes_mod.preauth_evaluation_requirements()["activation"]


def test_monitoring_non_execution_proof():
    assert modes_mod.assert_no_executions([], window="w")["ok"] is True
    blocked = modes_mod.assert_no_executions(
        [{"status": "blocked"}, {"status": "blocked"}], window="w")
    assert blocked["ok"] is True and blocked["total"] == 2
    violated = modes_mod.assert_no_executions([{"status": "succeeded"}], window="w")
    assert violated["ok"] is False and violated["executed"] == 1


def test_metrics_refuse_unlabeled_scores_and_count_censored():
    inconclusive = metrics_mod.detection_quality(true_detections=5, false_positives=1,
                                                 false_negatives=0, labeling_valid=False)
    assert inconclusive["precision"] is None and inconclusive["verdict"] == "inconclusive"
    latency = metrics_mod.latency_distribution([1.0, 2.0, 3.0], censored=2, stage="triage")
    assert latency["count"] == 3 and latency["censored"] == 2 and latency["p50"] == 2.0
    ledger = metrics_mod.action_safety_ledger(blocked=2, awaiting_approval=1, executed=1,
                                              verified_ok=1, verified_failed=0,
                                              rollbacks_attempted=0, rollbacks_ok=0,
                                              revoked_or_stale_denied=1)
    assert ledger["approved_executed"] == 1 and ledger["verified_ok"] == 1


def test_evidence_reconciliation_is_explicit():
    record = evidence_mod.new_evidence("e2e-benign-process", "e2e-abc")
    report = evidence_mod.reconcile(record)
    assert report["complete"] is False and report["missing_stages"]
    synthetic = evidence_mod.new_evidence("e2e-x", "e2e-y", synthetic=True)
    assert evidence_mod.reconcile(synthetic)["synthetic"] is True
    blank = evidence_mod.blank_pilot_report(["e2e-benign-process"])
    assert blank["status"] == "awaiting_pilot_evidence"


def test_scorecard_and_signoff_require_evidence():
    rows = scorecard_mod.monitoring_scorecard()
    assert len(rows) >= 5 and all(row.decision == "extend" for row in rows)
    assert len(scorecard_mod.approved_manual_scorecard()) > len(rows)
    assert len(scorecard_mod.bounded_preauth_gate()) >= 1
    with pytest.raises(ValueError):
        scorecard_mod.SignOff(decision="proceed", rationale="", signers=[]).finalize()
    signed = scorecard_mod.SignOff(decision="extend", rationale="awaiting evidence",
                                   signers=["security-lead"], date="2026-01-01").finalize()
    assert signed["decision"] == "extend"
