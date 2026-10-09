"""Phase 7 end-to-end suite (PROVIDED — NOT EXECUTED).

Developer-run only, against an isolated database and the harmless
in-memory harness action. Covers C4–C11: detection/evidence/incidents,
risk/policy, manual + bounded authorization, execution/verification/
rollback/audit, false-positive boundaries, duplicates/concurrency,
outage/recovery, revocation/kill/breaker/failed-verification.

Status: TEST HARNESS PROVIDED — NOT EXECUTED. No results claimed.
"""

import pytest

from guardian.validation.corpus import SCENARIOS, benign_scenarios, get_scenario
from guardian.validation.e2e_harness import FAILURE_CASES, EndToEndHarness, scenario_correlation_id


def test_corpus_inventory_is_grounded():
    ids = {s["scenario_id"] for s in SCENARIOS}
    assert {"e2e-benign-process", "e2e-suspicious-process", "e2e-suspicious-port",
            "e2e-duplicate-event", "e2e-malformed-missing-fields"} <= ids
    assert get_scenario("e2e-benign-port-boundary")["expected"]["detections"] == []
    assert len(benign_scenarios()) >= 4


def test_harness_correlation_is_deterministic():
    first = scenario_correlation_id("e2e-benign-process", "run-1")
    second = scenario_correlation_id("e2e-benign-process", "run-1")
    other = scenario_correlation_id("e2e-benign-process", "run-2")
    assert first == second and first != other
    harness = EndToEndHarness(scenario_id="e2e-benign-process")
    assert harness.summary()["reconciled"] is True


def test_failure_cases_cover_mandatory_safety():
    ids = {c.case_id for c in FAILURE_CASES}
    assert {"revoked-authorization", "kill-switch", "breaker-limits",
            "failed-verification", "backend-outage", "duplicate-storm"} <= ids
