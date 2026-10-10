"""Versioned agent configuration files (single documented approach).

Precedence (explicit): built-in defaults < configuration file < environment
variables. Environment always wins so orchestrated deployments can override
files without editing them.

Secrets: files must never contain GUARDIAN_AUTH_TOKEN in plaintext. Use the
DPAPI-protected blob path (GUARDIAN_PROTECTED_TOKEN_PATH) or environment
injection from a secret store. Loaders redact secrets from every output.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

CONFIG_SCHEMA_VERSION = 1

# File key -> (environment variable, AgentConfig field). Only these keys are
# accepted in configuration files; unknown keys are rejected (fail closed).
FILE_KEYS: Dict[str, tuple] = {
    "agent_key": ("GUARDIAN_AGENT_KEY", "agent_key"),
    "host_id": ("GUARDIAN_HOST_ID", "host_id"),
    "host_hostname": ("GUARDIAN_HOSTNAME", "host_hostname"),
    "agent_version": ("GUARDIAN_AGENT_VERSION", "agent_version"),
    "backend_url": ("GUARDIAN_BACKEND_URL", "backend_url"),
    "data_dir": ("GUARDIAN_DATA_DIR", "data_dir"),
    "queue_db_path": ("GUARDIAN_QUEUE_DB_PATH", "queue_db_path"),
    "queue_max_size": ("GUARDIAN_QUEUE_MAX_SIZE", "queue_max_size"),
    "sync_interval_seconds": ("GUARDIAN_SYNC_INTERVAL", "sync_interval_seconds"),
    "sync_batch_size": ("GUARDIAN_SYNC_BATCH_SIZE", "sync_batch_size"),
    "sync_timeout_seconds": ("GUARDIAN_SYNC_TIMEOUT", "sync_timeout_seconds"),
    "sync_max_batch_bytes": ("GUARDIAN_SYNC_MAX_BATCH_BYTES", "sync_max_batch_bytes"),
    "sync_max_backoff_seconds": ("GUARDIAN_SYNC_MAX_BACKOFF", "sync_max_backoff_seconds"),
    "sending_lease_seconds": ("GUARDIAN_SENDING_LEASE_SECONDS", "sending_lease_seconds"),
    "etw_process_session": ("GUARDIAN_ETW_PROCESS_SESSION", "etw_process_session"),
    "etw_network_session": ("GUARDIAN_ETW_NETWORK_SESSION", "etw_network_session"),
    "etw_network_provider_guid": ("GUARDIAN_ETW_NETWORK_GUID", "etw_network_provider_guid"),
    "etw_network_provider_name": ("GUARDIAN_ETW_NETWORK_PROVIDER", "etw_network_provider_name"),
    "enable_network_collector": ("GUARDIAN_ENABLE_NETWORK", "enable_network_collector"),
    "service_name": ("GUARDIAN_SERVICE_NAME", "service_name"),
    "service_account": ("GUARDIAN_SERVICE_ACCOUNT", "service_account"),
    "service_dependencies": ("GUARDIAN_SERVICE_DEPENDENCIES", "service_dependencies"),
    "program_dir": ("GUARDIAN_PROGRAM_DIR", "program_dir"),
    "log_dir": ("GUARDIAN_LOG_DIR", "log_dir"),
    "shutdown_timeout_seconds": ("GUARDIAN_SHUTDOWN_TIMEOUT", "shutdown_timeout_seconds"),
    "heartbeat_interval_seconds": ("GUARDIAN_HEARTBEAT_INTERVAL", "heartbeat_interval_seconds"),
    "log_level": ("GUARDIAN_LOG_LEVEL", "log_level"),
}

SECRET_FIELDS = ("auth_token",)
SECRET_ENV_VARS = ("GUARDIAN_AUTH_TOKEN",)

# Settings that must be explicitly provided in production (no safe default).
PRODUCTION_REQUIRED = (
    "GUARDIAN_AGENT_KEY",
    "GUARDIAN_BACKEND_URL",
    "GUARDIAN_AUTH_TOKEN",
)

# Settings that change the security posture; every change must be reviewed.
SECURITY_POSTURE_SETTINGS = (
    "GUARDIAN_BACKEND_URL",
    "GUARDIAN_AUTH_TOKEN",
    "GUARDIAN_ENABLE_NETWORK",
    "GUARDIAN_ETW_NETWORK_GUID",
    "GUARDIAN_SERVICE_ACCOUNT",
    "GUARDIAN_DATA_DIR",
    "GUARDIAN_QUEUE_MAX_SIZE",
)


def load_config_file(path: str) -> Dict[str, Any]:
    """Load and validate a versioned configuration file (no secrets logged)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Configuration file must contain a JSON object")
    if data.get("schema_version", 1) != CONFIG_SCHEMA_VERSION:
        raise ValueError(f"Unsupported config schema_version (want {CONFIG_SCHEMA_VERSION})")
    unknown = [key for key in data if key not in FILE_KEYS and key != "schema_version"]
    if unknown:
        raise ValueError(f"Unknown configuration keys rejected: {', '.join(sorted(unknown))}")
    for key in SECRET_FIELDS:
        if key in data:
            raise ValueError("Configuration files must not contain plaintext secrets; "
                             "use GUARDIAN_PROTECTED_TOKEN_PATH or environment injection")
    return {key: data[key] for key in data if key in FILE_KEYS}


def load_effective_config(path: str | None = None):
    """Build AgentConfig with precedence defaults < file < environment."""
    from guardian.agent.config import AgentConfig

    file_values: Dict[str, Any] = {}
    if path:
        file_values = load_config_file(path)
    kwargs: Dict[str, Any] = dict(file_values)
    for file_key, (env_var, _field) in FILE_KEYS.items():
        if env_var in os.environ:
            kwargs.pop(file_key, None)
    config = AgentConfig(**kwargs) if kwargs else AgentConfig()
    config.validate()
    return config


def to_redacted_dict(config) -> Dict[str, Any]:
    """Serialize configuration with every secret redacted."""
    from dataclasses import asdict

    data = asdict(config)
    for field_name in SECRET_FIELDS:
        if field_name in data:
            data[field_name] = "***REDACTED***" if data[field_name] else "not-set"
    return data


def validate_production(config) -> List[str]:
    """Return missing production-required settings (empty = ready).

    Never downgrades security: callers must refuse production start when
    the list is non-empty.
    """
    import os as _os

    missing = []
    if not config.agent_key:
        missing.append("GUARDIAN_AGENT_KEY")
    if not config.backend_url or not config.backend_url.startswith("https://"):
        missing.append("GUARDIAN_BACKEND_URL (production requires https://)")
    if not _os.getenv("GUARDIAN_AUTH_TOKEN") and not getattr(config, "auth_token", ""):
        missing.append("GUARDIAN_AUTH_TOKEN")
    return missing


def migrate_config_dict(old: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate an older config dict to the current schema (explicit)."""
    data = dict(old)
    data["schema_version"] = CONFIG_SCHEMA_VERSION
    unknown = [key for key in data if key not in FILE_KEYS and key != "schema_version"]
    if unknown:
        raise ValueError(f"Cannot migrate unknown keys: {', '.join(sorted(unknown))}")
    return data
