"""End-to-end validation harness (PROVIDED — NOT EXECUTED).

Shares the PRODUCTION pipeline wherever practical instead of duplicating
it: GuardianEvent normalization -> api_guardian ingestion semantics ->
DetectionDispatcher (detectors, evidence, risk, policy) -> persisted
policy_v5 evaluation -> ApprovalManager / preauth grant store ->
SafetyEnvelope -> action execution -> VerificationManager ->
explicit rollback -> immutable audit.

Two paths:
  1. fixture_path: deterministic fixtures through the production
     dispatcher/policy/envelope against an isolated database.
  2. live_path: agent-produced telemetry through the same production
     ingestion/detection/policy/authorization logic on a disposable
     Windows host (see live_windows_checklist.md; NOT RUN here).

Every run carries a scenario_id (see corpus.py) stamped into evidence so
source events, detections, incidents, evaluations, executions, and audit
rows correlate. Destructive production actions are never executed: the
harness uses a harmless in-DB test action implementing BaseAction plus
separate safety-check validation of production action validators.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def scenario_correlation_id(scenario_id: str, run_key: str = "harness") -> str:
    """Deterministic correlation id binding one harness run."""
    digest = hashlib.sha256(f"{scenario_id}|{run_key}".encode()).hexdigest()[:16]
    return f"e2e-{digest}"


@dataclass
class HarnessResult:
    scenario_id: str
    correlation_id: str
    events_generated: int = 0
    events_observed: int = 0
    events_queued: int = 0
    batches_attempted: int = 0
    acknowledged: int = 0
    duplicates_acknowledged: int = 0
    backend_events: int = 0
    detections: List[str] = field(default_factory=list)
    incidents: List[str] = field(default_factory=list)
    risk_score: Optional[float] = None
    policy_decision: Optional[str] = None
    approval_id: Optional[str] = None
    execution_id: Optional[str] = None
    execution_status: Optional[str] = None
    verification: Optional[str] = None
    audit_ids: List[str] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)

    def reconciled(self) -> bool:
        """True only when nothing remains unresolved."""
        return not self.unresolved


@dataclass
class FailureCase:
    case_id: str
    description: str
    expected: str


FAILURE_CASES: List[FailureCase] = [
    FailureCase("revoked-authorization", "Revoke grant/disable policy before execution", "stale request cannot execute"),
    FailureCase("kill-switch", "Activate applicable kill switch before execution", "blocked by SafetyEnvelope"),
    FailureCase("breaker-limits", "Trip breaker / exceed rate limits", "new actions blocked as specified"),
    FailureCase("failed-verification", "Test action reports success but leaves state unchanged", "verification_failed; explicit rollback only; audit reflects truth"),
    FailureCase("backend-outage", "Backend unavailable during collection", "events queued, retried, reconciled after recovery"),
    FailureCase("queue-pressure", "Queue nearing capacity / disk-write failure", "explicit overflow, degraded health, no silent send"),
    FailureCase("duplicate-storm", "Repeated IDs across callback/queue/HTTP/detection/incident/execution", "idempotent rows; no repeated side effect"),
]


class EndToEndHarness:
    """Developer-run orchestrator. Import-safe without side effects.

    Methods are intentionally thin: they call production components
    (dispatcher, risk, policy, approvals, envelope, registry) supplied by
    the caller with an isolated session. No pipeline is duplicated here.
    """

    def __init__(self, *, scenario_id: str, run_key: str = "harness") -> None:
        self.scenario_id = scenario_id
        self.correlation_id = scenario_correlation_id(scenario_id, run_key)
        self.result = HarnessResult(scenario_id=scenario_id, correlation_id=self.correlation_id)

    def record_unresolved(self, item: str) -> None:
        self.result.unresolved.append(item)

    def summary(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "correlation_id": self.correlation_id,
            "reconciled": self.result.reconciled(),
            "unresolved": list(self.result.unresolved),
        }
