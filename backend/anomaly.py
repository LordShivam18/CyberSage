import json
import math
from pathlib import Path
from typing import Any, Dict, List

import joblib

from .config import settings
from .detection_types import DetectorResult
from .telemetry import LEGACY_FEATURES, NormalizedNetworkEvent, features_from_event


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.feature_list: List[str] = LEGACY_FEATURES
        self.error = None
        self._load()

    def _load(self):
        model_path = settings.resolve_path(settings.anomaly_model_path)
        metadata_path = settings.resolve_path(settings.anomaly_metadata_path)
        try:
            if metadata_path.exists():
                with metadata_path.open("r", encoding="utf-8") as handle:
                    self.metadata = json.load(handle)
                    self.feature_list = self.metadata.get("feature_list") or self.feature_list
            if model_path.exists():
                self.model = joblib.load(model_path)
            else:
                self.error = "Isolation Forest artifact missing; deterministic anomaly fallback is active."
        except Exception as exc:
            self.model = None
            self.error = f"Could not load anomaly detector: {exc}"

    @property
    def available(self):
        return self.model is not None

    def status(self):
        return {
            "available": self.available,
            "model_name": "IsolationForest",
            "metadata": self.metadata,
            "fallback_reason": self.error,
        }

    def score_event(self, event: NormalizedNetworkEvent) -> DetectorResult:
        features = features_from_event(event)
        vector = [[float(features.get(name, 0.0) or 0.0) for name in self.feature_list]]
        if self.available:
            raw_score = float(self.model.decision_function(vector)[0])
            normalized = 1.0 / (1.0 + math.exp(raw_score * 4.0))
        else:
            bytes_total = (event.bytes_sent or 0.0) + (event.bytes_received or 0.0)
            packets_total = (event.packets_sent or 0.0) + (event.packets_received or 0.0)
            normalized = min(1.0, (bytes_total / 100000.0) * 0.55 + (packets_total / 400.0) * 0.45)
        classification = "ANOMALY" if normalized >= 0.6 else "NORMAL"
        severity = "high" if normalized >= 0.85 else "medium" if normalized >= 0.6 else "informational"
        return DetectorResult(
            source="anomaly",
            classification=classification,
            confidence=float(normalized if classification == "ANOMALY" else 1.0 - normalized),
            severity=severity,
            anomaly_score=float(normalized),
            contributing_features=[
                {
                    "feature": "bytes_total",
                    "value": float((event.bytes_sent or 0.0) + (event.bytes_received or 0.0)),
                    "reason": "Volume contributes to the lightweight anomaly score.",
                },
                {
                    "feature": "packets_total",
                    "value": float((event.packets_sent or 0.0) + (event.packets_received or 0.0)),
                    "reason": "Packet count contributes to the lightweight anomaly score.",
                },
            ],
            recommended_actions=["Check whether this volume is expected for the source asset."],
            metadata={"fallback_reason": self.error} if self.error else {},
        )


anomaly_detector = AnomalyDetector()
