import os
from dataclasses import dataclass
from pathlib import Path
from typing import List


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _list_env(name: str, default: str) -> List[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = "AI-Assisted Network Detection and Response Platform"
    environment: str = os.getenv("APP_ENV", "development")
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost/threatdb"
    )
    cors_origins: List[str] = None
    kafka_bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    raw_topic: str = os.getenv("RAW_NETWORK_EVENTS_TOPIC", "raw.network-events")
    legacy_topic: str = os.getenv("KAFKA_TOPIC", "network_traffic")
    normalized_topic: str = os.getenv(
        "NORMALIZED_NETWORK_EVENTS_TOPIC", "normalized.network-events"
    )
    detections_topic: str = os.getenv("DETECTIONS_TOPIC", "detections")
    dead_letter_topic: str = os.getenv("DEAD_LETTER_TOPIC", "dead-letter-events")
    worker_group_id: str = os.getenv("KAFKA_WORKER_GROUP_ID", "ndr-detection-worker")
    kafka_enabled: bool = _bool_env("KAFKA_ENABLED", True)
    auto_migrate: bool = _bool_env("AUTO_MIGRATE", True)
    repo_root: Path = Path(__file__).resolve().parent.parent
    model_path: Path = Path(
        os.getenv("MODEL_PATH", str(Path("results") / "model" / "transformer_model.pth"))
    )
    scaler_path: Path = Path(os.getenv("SCALER_PATH", str(Path("results") / "scaler.gz")))
    model_metadata_path: Path = Path(
        os.getenv("MODEL_METADATA_PATH", str(Path("results") / "model" / "metadata.json"))
    )
    anomaly_model_path: Path = Path(
        os.getenv("ANOMALY_MODEL_PATH", str(Path("results") / "anomaly" / "isolation_forest.joblib"))
    )
    anomaly_metadata_path: Path = Path(
        os.getenv("ANOMALY_METADATA_PATH", str(Path("results") / "anomaly" / "metadata.json"))
    )
    rules_path: Path = Path(
        os.getenv("DETECTION_RULES_PATH", str(Path("backend") / "rules" / "default_rules.json"))
    )
    mitre_mapping_path: Path = Path(
        os.getenv("MITRE_MAPPING_PATH", str(Path("backend") / "rules" / "mitre_mapping.json"))
    )
    local_indicator_path: Path = Path(
        os.getenv("LOCAL_INDICATOR_PATH", str(Path("backend") / "threat_intel" / "local_indicators.json"))
    )
    threat_intel_external_enabled: bool = _bool_env("THREAT_INTEL_EXTERNAL_ENABLED", False)
    threat_intel_timeout_seconds: float = float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "2"))
    threat_intel_cache_ttl_seconds: int = int(os.getenv("THREAT_INTEL_CACHE_TTL_SECONDS", "3600"))
    jwt_secret: str = os.getenv("JWT_SECRET", "development-only-change-me")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "ai-ndr-platform")
    access_token_minutes: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "480"))
    auth_rate_limit_per_minute: int = int(os.getenv("AUTH_RATE_LIMIT_PER_MINUTE", "10"))
    predict_rate_limit_per_minute: int = int(os.getenv("PREDICT_RATE_LIMIT_PER_MINUTE", "60"))

    def __post_init__(self):
        if self.cors_origins is None:
            object.__setattr__(
                self,
                "cors_origins",
                _list_env(
                    "CORS_ORIGINS",
                    "http://localhost:3000,http://127.0.0.1:3000",
                ),
            )

    def resolve_path(self, path: Path) -> Path:
        if path.is_absolute():
            return path
        return self.repo_root / path


settings = Settings()
