import hashlib
import json
import math
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from .config import settings
from .detection_types import DetectorResult
from .telemetry import LEGACY_FEATURES, NormalizedNetworkEvent, features_from_event


class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=5000):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        self.register_buffer("pe", pe)

    def forward(self, x):
        return x + self.pe[: x.size(0), :]


class ThreatTransformer(nn.Module):
    def __init__(self, input_dim, d_model, nhead, nlayers, num_classes=2):
        super().__init__()
        self.d_model = d_model
        self.encoder = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model)
        encoder_layers = nn.TransformerEncoderLayer(d_model, nhead, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, nlayers)
        self.decoder = nn.Linear(d_model, num_classes)

    def forward(self, src):
        src = self.encoder(src) * math.sqrt(self.d_model)
        src = self.pos_encoder(src)
        output = self.transformer_encoder(src)
        output = output[:, -1, :]
        return self.decoder(output)


def _file_checksum(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _infer_num_classes(state_dict: Dict[str, Any]) -> int:
    decoder_weight = state_dict.get("decoder.weight")
    if decoder_weight is not None and hasattr(decoder_weight, "shape"):
        return int(decoder_weight.shape[0])
    return 2


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
        self.checksum = None
        self.error: Optional[str] = None
        self._load()

    def _load(self) -> None:
        model_path = settings.resolve_path(settings.model_path)
        scaler_path = settings.resolve_path(settings.scaler_path)
        metadata_path = settings.resolve_path(settings.model_metadata_path)
        self.checksum = _file_checksum(model_path)
        try:
            self.metadata = _load_json(metadata_path)
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                if hasattr(self.scaler, "get_feature_names_out"):
                    self.feature_names = list(self.scaler.get_feature_names_out())
            self.feature_names = self.metadata.get("feature_list") or self.feature_names or LEGACY_FEATURES
            class_mapping = self.metadata.get("class_mapping") or {"0": "BENIGN", "1": "ATTACK"}
            self.class_mapping = {int(key): value for key, value in class_mapping.items()}
            self.model_version = self.metadata.get("version", "legacy-binary")
            self.model_name = self.metadata.get("name", "ThreatTransformer")

            if not model_path.exists() or not self.scaler:
                self.error = "Model or scaler artifact missing; heuristic fallback is active."
                return

            state_dict = torch.load(model_path, map_location="cpu")
            num_classes = _infer_num_classes(state_dict)
            input_dim = len(self.feature_names) or 78
            self.model = ThreatTransformer(input_dim, 128, 8, 3, num_classes=num_classes)
            self.model.load_state_dict(state_dict)
            self.model.eval()
        except Exception as exc:
            self.model = None
            self.scaler = None
            self.error = f"Model artifacts are incompatible; heuristic fallback is active: {exc}"

    @property
    def available(self) -> bool:
        return self.model is not None and self.scaler is not None

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "model_file_checksum": self.checksum,
            "feature_count": len(self.feature_names),
            "class_mapping": self.class_mapping,
            "fallback_reason": self.error,
        }

    def _fallback(self, features: Dict[str, float], elapsed_ms: float) -> DetectorResult:
        outbound_bytes = features.get("totlen_fwd_pkts", 0.0)
        packets = features.get("tot_fwd_pkts", 0.0) + features.get("tot_bwd_pkts", 0.0)
        duration = features.get("flow_duration", 0.0)
        score = 0.0
        score += min(outbound_bytes / 50000.0, 1.0) * 0.45
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
            metadata={"fallback_reason": self.error},
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
        for col in self.feature_names:
            if col not in input_df.columns:
                input_df[col] = 0.0
        input_df = input_df[self.feature_names]

        try:
            scaled_features = self.scaler.transform(input_df)
            sequence = np.array([scaled_features[0]] * 10)
            sequence_tensor = torch.tensor([sequence], dtype=torch.float32)
            with torch.no_grad():
                output = self.model(sequence_tensor)
                probabilities_tensor = torch.softmax(output, dim=1)[0]
                confidence_tensor, predicted_tensor = torch.max(probabilities_tensor, 0)
            predicted_index = int(predicted_tensor.item())
            label = self.class_mapping.get(predicted_index, str(predicted_index))
            probabilities = {
                self.class_mapping.get(index, str(index)): float(value)
                for index, value in enumerate(probabilities_tensor.tolist())
            }
            confidence = float(confidence_tensor.item())
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
