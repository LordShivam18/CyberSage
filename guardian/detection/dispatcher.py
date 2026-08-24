"""Detection dispatcher.

Orchestrates the pipeline: GuardianEvent → detectors → evidence → risk → policy → persist.

This is the core wiring that connects event ingestion to the detection engine.
All operations are deterministic and auditable.
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from guardian.detectors.base import BaseDetector, Detection
from guardian.detectors.process_detectors import (
    SuspiciousProcessDetector,
    SuspiciousParentChildDetector,
    UnusualProcessLocationDetector,
)
from guardian.detectors.network_detectors import SuspiciousPortDetector, UnusualProtocolDetector
from guardian.detectors.persistence_detectors import PersistenceModificationDetector
from guardian.detectors.recurrence_detector import RecurrenceDetector
from guardian.evidence.aggregator import EvidenceAggregator
from guardian.risk.engine import RiskEngine
from guardian.policy.engine import PolicyEngine
from guardian.detection.recurrence_state import RecurrenceState

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class DetectionResult:
    """Result of dispatching a single event through the pipeline."""

    def __init__(self) -> None:
        self.event_id: str = ""
        self.detections_created: int = 0
        self.incidents_created: int = 0
        self.risk_scores_created: int = 0
        self.decisions_created: int = 0
        self.detector_errors: List[Dict[str, Any]] = []


class DetectionDispatcher:
    """Orchestrates event → detection → evidence → risk → policy pipeline.

    Designed to be called synchronously after event persistence.
    Failures in individual detectors are isolated and recorded.
    """

    def __init__(self) -> None:
        self._detectors: List[BaseDetector] = [
            SuspiciousProcessDetector(),
            SuspiciousParentChildDetector(),
            UnusualProcessLocationDetector(),
            SuspiciousPortDetector(),
            UnusualProtocolDetector(),
            PersistenceModificationDetector(),
        ]
        self._recurrence_detector = RecurrenceDetector()
        self._risk_engine = RiskEngine()
        self._policy_engine = PolicyEngine()

    def dispatch(
        self,
        session: Session,
        event_dict: Dict[str, Any],
    ) -> DetectionResult:
        """Dispatch a single event through the full detection pipeline.

        Args:
            session: SQLAlchemy session (caller manages transaction).
            event_dict: GuardianEvent dict (from event.to_dict() or DB row).

        Returns:
            DetectionResult with counts and any detector errors.
        """
        result = DetectionResult()
        result.event_id = event_dict.get("event_id", "")

        # 1. Run detectors
        detections = self._run_detectors(event_dict, result)

        # 2. Persist detections
        detection_dicts = self._persist_detections(session, event_dict, detections)

        # 3. Update recurrence state
        recurrence_state = RecurrenceState(session)
        recurrence_count = self._update_recurrence(event_dict, recurrence_state)

        # 4. Aggregate evidence
        aggregator = EvidenceAggregator()
        for det_dict in detection_dicts:
            aggregator.add_detection(Detection.from_dict(det_dict))

        evidence_groups = aggregator.get_evidence_groups()
        incident_candidates = aggregator.get_incident_candidates(min_detections=2)

        # 5. Persist incidents
        incident_ids = self._persist_incidents(session, incident_candidates, detection_dicts, event_dict)
        result.incidents_created = len(incident_ids)

        # 6. Compute and persist risk scores
        risk_scores = self._compute_and_persist_risks(
            session, detection_dicts, evidence_groups, recurrence_count, incident_ids
        )
        result.risk_scores_created = len(risk_scores)

        # 7. Compute and persist policy decisions
        decisions = self._compute_and_persist_decisions(
            session, risk_scores, evidence_groups, incident_ids
        )
        result.decisions_created = len(decisions)

        # 8. Update incident records with risk/decision IDs
        self._link_incidents(session, incident_ids, risk_scores, decisions)

        return result

    def _run_detectors(
        self, event_dict: Dict[str, Any], result: DetectionResult
    ) -> List[Detection]:
        """Run all detectors against the event, isolating failures."""
        detections = []

        for detector in self._detectors:
            try:
                new_detections = detector.detect(event_dict)
                detections.extend(new_detections)
            except Exception as exc:
                # Detector failure must not crash the pipeline
                error_info = {
                    "detector_id": detector.detector_id,
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                }
                result.detector_errors.append(error_info)
                logger.error(
                    "Detector %s failed: %s", detector.detector_id, exc,
                    exc_info=True,
                )

        # Run recurrence detector
        try:
            recurrence_detections = self._recurrence_detector.detect(event_dict)
            detections.extend(recurrence_detections)
        except Exception as exc:
            result.detector_errors.append({
                "detector_id": "recurrence",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            })
            logger.error("Recurrence detector failed: %s", exc, exc_info=True)

        result.detections_created = len(detections)
        return detections

    def _persist_detections(
        self,
        session: Session,
        event_dict: Dict[str, Any],
        detections: List[Detection],
    ) -> List[Dict[str, Any]]:
        """Persist detections to the database.

        Uses stable detection_id for idempotency.
        """
        from backend.models import GuardianDetection

        persisted = []
        for det in detections:
            # Check for existing detection (idempotency)
            existing = session.query(GuardianDetection).filter(
                GuardianDetection.detection_id == det.detection_id
            ).first()

            if existing:
                persisted.append(existing.__dict__)
                continue

            db_det = GuardianDetection(
                detection_id=det.detection_id,
                event_id=det.event_id,
                detector_id=det.detector_id,
                severity=det.severity,
                confidence=det.confidence,
                title=det.title,
                description=det.description,
                evidence=det.evidence,
                mitre_technique=det.mitre_technique,
                mitre_tactic=det.mitre_tactic,
                created_at=det.created_at,
            )
            session.add(db_det)
            session.flush()
            persisted.append({
                "detection_id": det.detection_id,
                "event_id": det.event_id,
                "detector_id": det.detector_id,
                "severity": det.severity,
                "confidence": det.confidence,
                "title": det.title,
                "description": det.description,
                "evidence": det.evidence,
                "mitre_technique": det.mitre_technique,
                "mitre_tactic": det.mitre_tactic,
                "created_at": det.created_at.isoformat() if isinstance(det.created_at, datetime) else str(det.created_at),
            })

        session.commit()
        return persisted

    def _update_recurrence(
        self, event_dict: Dict[str, Any], state: RecurrenceState
    ) -> int:
        """Update recurrence state and return current count."""
        host_id = event_dict.get("host_id", "unknown")
        process_name = (event_dict.get("process_name") or "").lower()
        dest_ip = event_dict.get("destination_ip") or ""

        count = 0
        if process_name:
            count = state.increment(host_id, f"process:{process_name}")
        elif dest_ip:
            count = state.increment(host_id, f"ip:{dest_ip}")

        return count

    def _persist_incidents(
        self,
        session: Session,
        candidates: List[Any],
        detection_dicts: List[Dict[str, Any]],
        event_dict: Dict[str, Any],
    ) -> List[int]:
        """Persist incident candidates. Returns list of incident DB IDs."""
        from backend.models import GuardianIncident

        incident_ids = []
        for candidate in candidates:
            # Check for existing incident (idempotency)
            existing = session.query(GuardianIncident).filter(
                GuardianIncident.candidate_id == candidate.candidate_id
            ).first()

            if existing:
                incident_ids.append(existing.id)
                continue

            db_inc = GuardianIncident(
                candidate_id=candidate.candidate_id,
                title=candidate.title,
                description=candidate.description,
                severity=candidate.severity,
                confidence=candidate.confidence,
                status="open",
                evidence_ids=candidate.evidence_ids,
                event_ids=candidate.event_ids,
                host_ids=candidate.host_ids,
                mitre_techniques=candidate.mitre_techniques,
                mitre_tactics=candidate.mitre_tactics,
            )
            session.add(db_inc)
            session.flush()
            incident_ids.append(db_inc.id)

        session.commit()
        return incident_ids

    def _compute_and_persist_risks(
        self,
        session: Session,
        detection_dicts: List[Dict[str, Any]],
        evidence_groups: List[Any],
        recurrence_count: int,
        incident_ids: List[int],
    ) -> List[Dict[str, Any]]:
        """Compute risk scores and persist them."""
        from backend.models import GuardianRiskScore

        risk_scores = []

        # Compute risk for the overall detection set
        if detection_dicts:
            risk = self._risk_engine.compute_risk(
                detections=detection_dicts,
                evidence_group_size=len(evidence_groups),
                recurrence_count=recurrence_count,
            )

            incident_id = incident_ids[0] if incident_ids else None
            detection_ids = [d.get("detection_id", "") for d in detection_dicts]

            db_risk = GuardianRiskScore(
                score=risk.score,
                severity=risk.severity,
                confidence=risk.confidence,
                factors=risk.factors,
                explanation=risk.explanation,
                detection_ids=detection_ids,
                incident_id=incident_id,
            )
            session.add(db_risk)
            session.flush()

            risk_scores.append({
                "id": db_risk.id,
                "score": risk.score,
                "severity": risk.severity,
                "confidence": risk.confidence,
                "factors": risk.factors,
                "detection_ids": detection_ids,
                "incident_id": incident_id,
            })

        session.commit()
        return risk_scores

    def _compute_and_persist_decisions(
        self,
        session: Session,
        risk_scores: List[Dict[str, Any]],
        evidence_groups: List[Any],
        incident_ids: List[int],
    ) -> List[Dict[str, Any]]:
        """Compute policy decisions and persist them."""
        from backend.models import GuardianResponseDecision

        decisions = []

        for risk in risk_scores:
            evidence_dicts = []
            for eg in evidence_groups:
                evidence_dicts.extend(eg.detections)

            decision = self._policy_engine.evaluate(
                risk_score=risk["score"],
                risk_severity=risk["severity"],
                risk_confidence=risk["confidence"],
                risk_factors=risk["factors"],
                evidence=evidence_dicts,
                incident_id=str(risk.get("incident_id")) if risk.get("incident_id") else None,
            )

            db_dec = GuardianResponseDecision(
                decision_id=decision.decision_id,
                incident_id=risk.get("incident_id"),
                severity=decision.severity,
                confidence=decision.confidence,
                recommended_action=decision.recommended_action,
                rationale=decision.rationale,
                evidence=decision.evidence,
                expected_effect=decision.expected_effect,
                risk=decision.risk,
                requires_approval=decision.requires_approval,
                rollback_available=decision.rollback_available,
                verification_plan=decision.verification_plan,
            )
            session.add(db_dec)
            session.flush()

            decisions.append({
                "id": db_dec.id,
                "decision_id": decision.decision_id,
                "incident_id": risk.get("incident_id"),
                "recommended_action": decision.recommended_action,
            })

        session.commit()
        return decisions

    def _link_incidents(
        self,
        session: Session,
        incident_ids: List[int],
        risk_scores: List[Dict[str, Any]],
        decisions: List[Dict[str, Any]],
    ) -> None:
        """Update incidents with their risk score and decision IDs."""
        from backend.models import GuardianIncident

        for inc_id in incident_ids:
            inc = session.query(GuardianIncident).filter(
                GuardianIncident.id == inc_id
            ).first()
            if not inc:
                continue

            # Find matching risk score
            for rs in risk_scores:
                if rs.get("incident_id") == inc_id:
                    inc.risk_score_id = rs["id"]
                    break

            # Find matching decision
            for dec in decisions:
                if dec.get("incident_id") == inc_id:
                    inc.response_decision_id = dec["id"]
                    break

        session.commit()
