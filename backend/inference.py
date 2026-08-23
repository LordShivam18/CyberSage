"""Runtime inference with strict governance checks for newly registered models."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
import torch

from .config import settings
from .detection_types import DetectorResult
from .model_architecture import ThreatTransformer
from .model_governance import GovernanceError, evaluate_drift, file_checksum, validate_model_metadata
from .telemetry import LEGACY_FEATURES, NormalizedNetworkEvent, features_from_event


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise GovernanceError("Model metadata must be a JSON object")
    return value


def _infer_num_classes(state_dict: Dict[str, Any]) -> int:
    decoder_weight = state_dict.get("decoder.weight")
    if decoder_weight is not None and hasattr(decoder_weight, "shape"):
        return int(decoder_weight.shape[0])
    return 2


def _load_transformer_state_dict(model_path: Path) -> Dict[str, torch.Tensor]:
    """Load the governed Tensor-only state dict without object deserialization."""
    try:
        state_dict = torch.load(model_path, map_location="cpu", weights_only=True)
    except Exception as exc:
        raise GovernanceError("Transformer artifact must be a safe PyTorch weights-only state dictionary") from exc
    if not isinstance(state_dict, dict) or not state_dict:
        raise GovernanceError("Transformer artifact must contain a non-empty PyTorch state dictionary")
    if any(not isinstance(name, str) or not isinstance(value, torch.Tensor) for name, value in state_dict.items()):
        raise GovernanceError("Transformer artifact state dictionary must contain only named tensors")
    return state_dict


def _severity_from_prediction(label: str, confidence: float) -> str:
    if label.upper() in {"BENIGN", "NORMAL"}:
        return "informational"
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.55:
        return "medium"
    return "low"


class ModelDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.metadata: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self.class_mapping: Dict[int, str] = {0: "BENIGN", 1: "ATTACK"}
        self.model_name = "ThreatTransformer"
        self.model_version = "unavailable"
        self.checksum: Optional[str] = None
        self.error: Optional[str] = None
        self.sequence_length = 10
        self.lifecycle_state = "degraded_fallback"
        self.legacy_compatibility = False
        self.last_drift: Dict[str, Any] = {
            "status": "insufficient_data",
            "reason": "No production feature window has been evaluated.",
        }
        self._load()

    def _set_fallback(self, reason: str) -> None:
        self.model = None
        self.scaler = None
        self.error = reason
        self.lifecycle_state = "degraded_fallback"

    def _load(self) -> None:
        model_path = settings.resolve_path(settings.model_path)
        scaler_path = settings.resolve_path(settings.scaler_path)
        metadata_path = settings.resolve_path(settings.model_metadata_path)
        self.checksum = file_checksum(model_path) if model_path.exists() else None
        try:
            metadata = _load_json(metadata_path)
            if metadata.get("metadata_schema_version"):
                metadata = validate_model_metadata(metadata, artifact_root=metadata_path.parent, verify_files=True)
                if metadata.get("registry_status") != "active":
                    raise GovernanceError("Model metadata is not marked active by the registry")
                if metadata.get("model_type") != "transformer":
                    raise GovernanceError("Only a promoted transformer artifact can be loaded for runtime inference")
                if file_checksum(model_path) != metadata["artifact_checksums"]["model"]:
                    raise GovernanceError("Configured model artifact checksum does not match metadata")
                if file_checksum(scaler_path) != metadata["artifact_checksums"]["scaler"]:
                    raise GovernanceError("Configured scaler artifact checksum does not match metadata")
                self.metadata = metadata
                self.feature_names = list(metadata["feature_names"])
                self.class_mapping = {int(key): value for key, value in metadata["class_mapping"].items()}
                self.model_version = metadata["model_version"]
                self.model_name = metadata.get("model_type", "ThreatTransformer")
                self.sequence_length = int(metadata["sequence_length"])
                self.lifecycle_state = "active_trained"
            else:
                # Existing loose binary metadata remains supported, but is visible as compatibility mode.
                self.metadata = validate_model_metadata(metadata, allow_legacy=True)
                self.legacy_compatibility = True
                self.feature_names = list(metadata.get("feature_list") or LEGACY_FEATURES)
                class_mapping = metadata.get("class_mapping") or {"0": "BENIGN", "1": "ATTACK"}
                self.class_mapping = {int(key): value for key, value in class_mapping.items()}
                self.model_version = metadata.get("version", "legacy-binary")
                self.model_name = metadata.get("name", "ThreatTransformer")
                self.sequence_length = int(metadata.get("sequence_length", 10))
                self.lifecycle_state = "legacy_compatibility"

            if not model_path.exists() or not scaler_path.exists():
                self._set_fallback("Model or scaler artifact missing; heuristic fallback is active.")
                return
            self.scaler = joblib.load(scaler_path)
            state_dict = _load_transformer_state_dict(model_path)
            architecture = self.metadata.get("architecture", {})
            self.model = ThreatTransformer(
                len(self.feature_names) or 78,
                int(architecture.get("d_model", 128)),
                int(architecture.get("nhead", 8)),
                int(architecture.get("nlayers", 3)),
                num_classes=_infer_num_classes(state_dict),
            )
            self.model.load_state_dict(state_dict)
            self.model.eval()
        except Exception as exc:
            self._set_fallback(f"Model artifacts are incompatible or ungoverned; heuristic fallback is active: {exc}")

    @property
    def available(self) -> bool:
        return self.model is not None and self.scaler is not None

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "state": self.lifecycle_state,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "model_file_checksum": self.checksum,
            "feature_count": len(self.feature_names),
            "class_mapping": self.class_mapping,
            "model_mode": "binary" if len(self.class_mapping) == 2 else "multiclass",
            "metadata_schema_version": self.metadata.get("metadata_schema_version"),
            "registry_status": self.metadata.get("registry_status"),
            "dataset_identifier": self.metadata.get("dataset_identifier"),
            "split_strategy": (self.metadata.get("split") or {}).get("strategy"),
            "sequence_length": self.sequence_length,
            "legacy_compatibility": self.legacy_compatibility,
            "validation_metrics": self.metadata.get("validation_metrics", {}),
            "test_metrics": self.metadata.get("test_metrics", {}),
            "known_limitations": self.metadata.get("known_limitations", []),
            "fallback_reason": self.error,
            "drift": self.last_drift,
        }

    def evaluate_recent_drift(self, feature_rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        baseline = self.metadata.get("drift_baseline")
        if not self.available or not baseline:
            self.last_drift = {
                "status": "degraded",
                "model_version": self.model_version,
                "sample_window": len(feature_rows),
                "reason": "An active governed model with a drift baseline is required.",
            }
            return self.last_drift
        self.last_drift = evaluate_drift(
            baseline,
            pd.DataFrame(feature_rows),
            self.model_version,
        )
        return self.last_drift

    def _fallback(self, features: Dict[str, float], elapsed_ms: float) -> DetectorResult:
        outbound_bytes = features.get("totlen_fwd_pkts", 0.0)
        packets = features.get("tot_fwd_pkts", 0.0) + features.get("tot_bwd_pkts", 0.0)
        duration = features.get("flow_duration", 0.0)
        score = min(outbound_bytes / 50000.0, 1.0) * 0.45
        score += min(packets / 250.0, 1.0) * 0.35
        score += min(duration / 120000000.0, 1.0) * 0.2
        label = "ATTACK" if score >= 0.55 else "BENIGN"
        confidence = max(0.55, min(score, 0.98)) if label == "ATTACK" else max(0.55, 1.0 - score)
        return DetectorResult(
            source="ml_model",
            classification=label,
            confidence=float(confidence),
            severity=_severity_from_prediction(label, confidence),
            probabilities={"ATTACK": float(score), "BENIGN": float(1.0 - score)},
            model_name="heuristic_model_fallback",
            model_version="fallback-1",
            model_file_checksum=self.checksum,
            contributing_features=self._feature_explanations(features),
            recommended_actions=[
                "Review the raw flow fields and confirm the source asset owner.",
                "Compare this flow with recent connections from the same source.",
            ],
            latency_ms=elapsed_ms,
            metadata={"fallback_reason": self.error, "model_state": self.lifecycle_state},
        )

    def _feature_explanations(self, features: Dict[str, float]) -> List[Dict[str, Any]]:
        ranked = sorted(features.items(), key=lambda item: abs(float(item[1] or 0.0)), reverse=True)
        return [
            {
                "feature": name,
                "value": float(value or 0.0),
                "reason": "High absolute value relative to the available flow fields.",
            }
            for name, value in ranked[:5]
        ]

    def predict_features(self, features: Dict[str, float]) -> DetectorResult:
        started = time.perf_counter()
        if not self.available:
            return self._fallback(features, (time.perf_counter() - started) * 1000)
        input_df = pd.DataFrame([features])
        for column in self.feature_names:
            if column not in input_df.columns:
                input_df[column] = 0.0
        try:
            scaled_features = self.scaler.transform(input_df[self.feature_names])
            sequence = np.repeat(scaled_features[0][None, :], self.sequence_length, axis=0)
            with torch.no_grad():
                output = self.model(torch.tensor(np.array([sequence]), dtype=torch.float32))
                probability_values = torch.softmax(output, dim=1)[0].tolist()
            probabilities = {
                self.class_mapping.get(index, str(index)): float(value)
                for index, value in enumerate(probability_values)
            }
            selected_threshold = (self.metadata.get("threshold_selection") or {}).get("selected_threshold")
            if len(probability_values) == 2 and isinstance(selected_threshold, (int, float)):
                predicted_index = 1 if probability_values[1] >= float(selected_threshold) else 0
            else:
                predicted_index = int(np.argmax(probability_values))
            label = self.class_mapping.get(predicted_index, str(predicted_index))
            confidence = float(probability_values[predicted_index])
            return DetectorResult(
                source="ml_model",
                classification=label,
                confidence=confidence,
                severity=_severity_from_prediction(label, confidence),
                probabilities=probabilities,
                model_name=self.model_name,
                model_version=self.model_version,
                model_file_checksum=self.checksum,
                contributing_features=self._feature_explanations(features),
                recommended_actions=[
                    "Validate model output against rule and anomaly context.",
                    "Inspect high-contributing flow features before escalation.",
                ],
                latency_ms=(time.perf_counter() - started) * 1000,
                metadata={"model_state": self.lifecycle_state},
            )
        except Exception as exc:
            self.error = f"Inference failed; heuristic fallback returned instead: {exc}"
            return self._fallback(features, (time.perf_counter() - started) * 1000)

    def predict_event(self, event: NormalizedNetworkEvent) -> DetectorResult:
        return self.predict_features(features_from_event(event))


model_detector = ModelDetector()


def run_prediction(flow_dict: Dict[str, Any]) -> Tuple[str, float]:
    features = {name: float(flow_dict.get(name, 0.0) or 0.0) for name in LEGACY_FEATURES}
    result = model_detector.predict_features(features)
    return result.classification, result.confidence
