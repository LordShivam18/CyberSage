"""Persistence modification detectors.

Detects suspicious persistence mechanisms.
"""

from __future__ import annotations

from typing import Any, Dict, List

from guardian.detectors.base import BaseDetector, Detection, compute_detection_id

# Suspicious persistence paths (lowercase for matching)
SUSPICIOUS_PERSISTENCE_PATHS = {
    "registry_run_key": [
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows\\currentversion\\runonce",
        "\\software\\microsoft\\windows\\currentversion\\runonceex",
    ],
    "scheduled_task": [],
    "startup_folder": [
        "\\microsoft\\windows\\start menu\\programs\\startup",
    ],
    "wmi_event_subscription": [],
    "service_installation": [],
}


class PersistenceModificationDetector(BaseDetector):
    """Detect suspicious persistence modifications."""

    @property
    def detector_id(self) -> str:
        return "persistence_modification"

    @property
    def description(self) -> str:
        return "Detects suspicious persistence mechanism modifications"

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        if event.get("event_category") != "persistence":
            return []

        persistence_type = (event.get("persistence_type") or "").lower()
        persistence_path = (event.get("persistence_path") or "").lower()

        if not persistence_type:
            return []

        suspicious_paths = SUSPICIOUS_PERSISTENCE_PATHS.get(persistence_type, [])

        # Any persistence event is noteworthy; suspicious paths increase severity
        is_suspicious_path = any(
            sp in persistence_path for sp in suspicious_paths
        ) if suspicious_paths else False

        severity = "high" if is_suspicious_path else "medium"
        confidence = 0.85 if is_suspicious_path else 0.5

        return [Detection(
            detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id),
            event_id=event.get("event_id", ""),
            detector_id=self.detector_id,
            severity=severity,
            confidence=confidence,
            title=f"Persistence modification: {persistence_type}",
            description=(
                f"Persistence mechanism '{persistence_type}' was modified at "
                f"'{persistence_path}'. "
                + ("This path is commonly targeted by malware." if is_suspicious_path
                   else "Review recommended.")
            ),
            evidence={
                "persistence_type": persistence_type,
                "persistence_path": persistence_path,
                "persistence_data": event.get("persistence_data"),
                "user_name": event.get("user_name"),
                "process_name": event.get("process_name"),
                "process_exe_path": event.get("process_exe_path"),
            },
            mitre_technique="T1547",
            mitre_tactic="persistence",
        )]
