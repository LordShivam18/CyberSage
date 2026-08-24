"""Recurrence detector.

Detects repeated suspicious behavior from the same host or process.
Requires external state (event history) to function.
"""

from __future__ import annotations

from typing import Any, Dict, List

from guardian.detectors.base import BaseDetector, Detection, compute_detection_id

# Thresholds for recurrence detection
PROCESS_EVENT_THRESHOLD = 5  # same process name seen N times
HOST_EVENT_THRESHOLD = 20  # same host_id seen N events
TIME_WINDOW_SECONDS = 3600  # 1 hour sliding window


class RecurrenceDetector(BaseDetector):
    """Detect repeated suspicious behavior from the same host or process.

    This detector maintains an in-memory sliding window counter.
    For production, this would use a persistent store (Redis, PostgreSQL).
    """

    def __init__(self) -> None:
        self._process_counts: Dict[str, int] = {}
        self._host_counts: Dict[str, int] = {}
        self._process_threshold = PROCESS_EVENT_THRESHOLD
        self._host_threshold = HOST_EVENT_THRESHOLD

    @property
    def detector_id(self) -> str:
        return "recurrence"

    @property
    def description(self) -> str:
        return "Detects repeated suspicious behavior from the same host or process"

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        detections = []

        # Track process name recurrence
        process_name = (event.get("process_name") or "").lower()
        if process_name:
            self._process_counts[process_name] = (
                self._process_counts.get(process_name, 0) + 1
            )
            count = self._process_counts[process_name]
            if count == self._process_threshold:
                detections.append(Detection(
                    detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id + "_process"),
                    event_id=event.get("event_id", ""),
                    detector_id=self.detector_id,
                    severity="medium",
                    confidence=0.7,
                    title=f"Repeated process: {process_name} ({count} events)",
                    description=(
                        f"Process '{process_name}' has been observed {count} times "
                        f"which exceeds the recurrence threshold."
                    ),
                    evidence={
                        "process_name": process_name,
                        "event_count": count,
                        "threshold": self._process_threshold,
                    },
                    mitre_technique="T1059",
                    mitre_tactic="execution",
                ))

        # Track host-level recurrence
        host_id = event.get("host_id", "")
        if host_id:
            self._host_counts[host_id] = (
                self._host_counts.get(host_id, 0) + 1
            )
            count = self._host_counts[host_id]
            if count == self._host_threshold:
                detections.append(Detection(
                    detection_id=compute_detection_id(event.get("event_id", ""), self.detector_id + "_host"),
                    event_id=event.get("event_id", ""),
                    detector_id=self.detector_id,
                    severity="low",
                    confidence=0.5,
                    title=f"High event volume from host ({count} events)",
                    description=(
                        f"Host '{host_id}' has generated {count} events "
                        f"which exceeds the host-level recurrence threshold."
                    ),
                    evidence={
                        "host_id": host_id,
                        "event_count": count,
                        "threshold": self._host_threshold,
                    },
                ))

        return detections

    def reset(self) -> None:
        """Reset counters (for testing or time window rotation)."""
        self._process_counts.clear()
        self._host_counts.clear()
