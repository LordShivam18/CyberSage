"""Base detector interface and detection data model.

All detectors implement BaseDetector and return structured Detection objects.
No detector executes commands or mutates the system.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def compute_detection_id(event_id: str, detector_id: str) -> str:
    """Compute a deterministic detection ID from event_id and detector_id.

    This ensures idempotency: the same event + detector always produces
    the same detection_id.
    """
    payload = f"{event_id}|{detector_id}"
    return f"det-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


@dataclass
class Detection:
    """Structured output from a detector.

    All fields are data-only. No executable content.
    """

    detection_id: str = ""
    event_id: str = ""
    detector_id: str = ""
    severity: str = "low"  # low | medium | high | critical
    confidence: float = 0.0  # 0.0 to 1.0
    title: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: Optional[str] = None  # e.g. "T1059.001"
    mitre_tactic: Optional[str] = None  # e.g. "execution"
    created_at: datetime = field(default_factory=_now_utc)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Detection:
        kwargs = {}
        for f_name in cls.__dataclass_fields__:
            if f_name in data:
                kwargs[f_name] = data[f_name]
        return cls(**kwargs)


class BaseDetector:
    """Abstract base for all Guardian detectors.

    Detectors consume GuardianEvent dicts and return zero or more Detections.
    """

    @property
    def detector_id(self) -> str:
        raise NotImplementedError

    @property
    def description(self) -> str:
        raise NotImplementedError

    def detect(self, event: Dict[str, Any]) -> List[Detection]:
        """Analyze an event and return detections.

        Args:
            event: A GuardianEvent dict (from event.to_dict() or DB row).

        Returns:
            List of Detection objects. Empty list means no detection.
        """
        raise NotImplementedError
