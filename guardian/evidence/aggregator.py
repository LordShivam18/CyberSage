"""Evidence aggregator.

Combines multiple detections and events into correlated evidence groups.
Groups related signals by host, process, or destination IP.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from guardian.detectors.base import Detection


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class CorrelatedEvidence:
    """A group of related detections and events forming evidence."""

    evidence_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "low"
    confidence: float = 0.0
    detection_count: int = 0
    event_ids: List[str] = field(default_factory=list)
    detections: List[Dict[str, Any]] = field(default_factory=list)
    host_ids: List[str] = field(default_factory=list)
    process_names: List[str] = field(default_factory=list)
    destination_ips: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    correlation_key: str = ""
    created_at: datetime = field(default_factory=_now_utc)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


@dataclass
class IncidentCandidate:
    """An incident candidate formed from correlated evidence."""

    candidate_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "low"
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    host_ids: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=_now_utc)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


class EvidenceAggregator:
    """Aggregates detections into correlated evidence groups.

    Groups detections by correlation key (host_id + process_name or
    host_id + destination_ip) to identify related activity.
    """

    def __init__(self, time_window_seconds: int = 3600) -> None:
        self._time_window = time_window_seconds
        self._groups: Dict[str, List[Dict[str, Any]]] = {}

    def _compute_correlation_key(self, detection: Dict[str, Any]) -> str:
        """Compute a correlation key for grouping related detections.

        Uses host_id + primary entity (process_name or destination_ip).
        """
        event = detection.get("evidence", {})
        host_id = event.get("host_id", "unknown")

        # Prefer process_name for process events, destination_ip for network
        if event.get("process_name"):
            entity = f"process:{event['process_name'].lower()}"
        elif event.get("destination_ip"):
            entity = f"ip:{event['destination_ip']}"
        elif event.get("persistence_type"):
            entity = f"persist:{event['persistence_type']}"
        else:
            entity = "generic"

        return f"{host_id}|{entity}"

    def add_detection(self, detection: Detection) -> None:
        """Add a detection to the aggregation pipeline."""
        det_dict = detection.to_dict()
        key = self._compute_correlation_key(det_dict)

        if key not in self._groups:
            self._groups[key] = []
        self._groups[key].append(det_dict)

    def add_detections(self, detections: List[Detection]) -> None:
        """Add multiple detections."""
        for det in detections:
            self.add_detection(det)

    def get_evidence_groups(self) -> List[CorrelatedEvidence]:
        """Return all current evidence groups."""
        results = []
        for key, group in self._groups.items():
            if not group:
                continue
            results.append(self._build_evidence(key, group))
        return results

    def get_incident_candidates(self, min_detections: int = 2) -> List[IncidentCandidate]:
        """Form incident candidates from evidence groups with enough signal.

        Args:
            min_detections: Minimum number of detections to form a candidate.
        """
        candidates = []
        for eg in self.get_evidence_groups():
            if eg.detection_count >= min_detections:
                candidates.append(self._form_candidate(eg))
        return candidates

    def _build_evidence(self, key: str, group: List[Dict[str, Any]]) -> CorrelatedEvidence:
        """Build a CorrelatedEvidence from a group of detections."""
        event_ids = list({d.get("event_id", "") for d in group if d.get("event_id")})
        host_ids = list({d.get("evidence", {}).get("host_id", "") for d in group if d.get("evidence", {}).get("host_id")})
        process_names = list({d.get("evidence", {}).get("process_name", "") for d in group if d.get("evidence", {}).get("process_name")})
        dest_ips = list({d.get("evidence", {}).get("destination_ip", "") for d in group if d.get("evidence", {}).get("destination_ip")})
        techniques = list({d.get("mitre_technique", "") for d in group if d.get("mitre_technique")})
        tactics = list({d.get("mitre_tactic", "") for d in group if d.get("mitre_tactic")})

        severities = [d.get("severity", "low") for d in group]
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(severities, key=lambda s: severity_order.get(s, 0))

        confidences = [d.get("confidence", 0.0) for d in group]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        timestamps = []
        for d in group:
            ts = d.get("created_at")
            if ts:
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
                    except (ValueError, TypeError):
                        continue
                timestamps.append(ts)

        evidence_id = f"ev-{hashlib.sha256(key.encode()).hexdigest()[:16]}"

        return CorrelatedEvidence(
            evidence_id=evidence_id,
            title=f"Correlated evidence: {key.split('|')[-1]} ({len(group)} detections)",
            description=f"{len(group)} related detections from host(s) {', '.join(host_ids)}",
            severity=max_severity,
            confidence=avg_confidence,
            detection_count=len(group),
            event_ids=event_ids,
            detections=[d for d in group],
            host_ids=host_ids,
            process_names=process_names,
            destination_ips=dest_ips,
            mitre_techniques=techniques,
            mitre_tactics=tactics,
            correlation_key=key,
            first_seen=min(timestamps) if timestamps else None,
            last_seen=max(timestamps) if timestamps else None,
        )

    def _form_candidate(self, evidence: CorrelatedEvidence) -> IncidentCandidate:
        """Form an incident candidate from correlated evidence."""
        candidate_id = f"inc-{evidence.evidence_id[3:]}"
        return IncidentCandidate(
            candidate_id=candidate_id,
            title=f"Incident candidate: {evidence.title}",
            description=(
                f"Multiple correlated detections ({evidence.detection_count}) "
                f"from host(s) {', '.join(evidence.host_ids)} suggest a security incident."
            ),
            severity=evidence.severity,
            confidence=evidence.confidence,
            evidence=evidence.detections,
            evidence_ids=[evidence.evidence_id],
            event_ids=evidence.event_ids,
            host_ids=evidence.host_ids,
            mitre_techniques=evidence.mitre_techniques,
            mitre_tactics=evidence.mitre_tactics,
        )

    def reset(self) -> None:
        """Reset all groups."""
        self._groups.clear()
