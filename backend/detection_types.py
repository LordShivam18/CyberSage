from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DetectorResult:
    source: str
    classification: str
    confidence: float
    severity: str = "low"
    triggered_rules: List[Dict[str, Any]] = field(default_factory=list)
    anomaly_score: Optional[float] = None
    probabilities: Dict[str, float] = field(default_factory=dict)
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    model_file_checksum: Optional[str] = None
    contributing_features: List[Dict[str, Any]] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    latency_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskResult:
    score: float
    severity: str
    components: Dict[str, float]
