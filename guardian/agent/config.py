"""Guardian agent configuration.

All configuration is explicit and environment/config-driven.
Secrets are never hardcoded or committed.
Dangerous configuration values are validated.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except (ValueError, TypeError):
        return default


def _str_env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


@dataclass(frozen=True)
class AgentConfig:
    """Guardian agent configuration.

    All fields are populated from environment variables with sensible defaults.
    """

    # ── Agent identity ────────────────────────────────────────────────
    agent_key: str = field(default_factory=lambda: _str_env("GUARDIAN_AGENT_KEY", ""))
    host_id: str = field(default_factory=lambda: _str_env("GUARDIAN_HOST_ID", ""))
    host_hostname: str = field(default_factory=lambda: _str_env("GUARDIAN_HOSTNAME", ""))
    agent_version: str = field(default_factory=lambda: _str_env("GUARDIAN_AGENT_VERSION", "2.0.0"))

    # ── Backend connection ────────────────────────────────────────────
    backend_url: str = field(default_factory=lambda: _str_env("GUARDIAN_BACKEND_URL", "http://localhost:8000"))
    auth_token: str = field(default_factory=lambda: _str_env("GUARDIAN_AUTH_TOKEN", ""))

    # ── Local storage / identity ────────────────────────────────────────
    data_dir: str = field(default_factory=lambda: _str_env("GUARDIAN_DATA_DIR", "guardian_data"))
    protected_token_path: str = field(default_factory=lambda: _str_env("GUARDIAN_PROTECTED_TOKEN_PATH", ""))

    # ── Queue settings ────────────────────────────────────────────────
    queue_db_path: str = field(default_factory=lambda: _str_env("GUARDIAN_QUEUE_DB_PATH", "guardian_queue.db"))
    queue_max_size: int = field(default_factory=lambda: _int_env("GUARDIAN_QUEUE_MAX_SIZE", 100_000))

    # ── Sync settings ─────────────────────────────────────────────────
    sync_interval_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_INTERVAL", 10))
    sync_batch_size: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_BATCH_SIZE", 100))
    sync_timeout_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_TIMEOUT", 30))
    sync_max_batch_bytes: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_MAX_BATCH_BYTES", 1_048_576))
    sync_max_backoff_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_MAX_BACKOFF", 300))
    sending_lease_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_SENDING_LEASE_SECONDS", 300))

    # ── ETW settings ──────────────────────────────────────────────────
    etw_process_session: str = field(default_factory=lambda: _str_env("GUARDIAN_ETW_PROCESS_SESSION", "GuardianProcessTrace"))
    etw_network_session: str = field(default_factory=lambda: _str_env("GUARDIAN_ETW_NETWORK_SESSION", "GuardianNetworkTrace"))
    etw_network_provider_guid: str = field(default_factory=lambda: _str_env("GUARDIAN_ETW_NETWORK_GUID", "{2F07E2EE-15DB-40F1-90EF-9D7ABA282188}"))
    etw_network_provider_name: str = field(default_factory=lambda: _str_env("GUARDIAN_ETW_NETWORK_PROVIDER", "Microsoft-Windows-TCPIP"))
    enable_network_collector: bool = field(default_factory=lambda: _bool_env("GUARDIAN_ENABLE_NETWORK", True))

    # ── Service settings ──────────────────────────────────────────────
    service_name: str = field(default_factory=lambda: _str_env("GUARDIAN_SERVICE_NAME", "CyberSageGuardian"))
    service_account: str = field(default_factory=lambda: _str_env("GUARDIAN_SERVICE_ACCOUNT", r"NT SERVICE\CyberSageGuardian"))
    service_dependencies: str = field(default_factory=lambda: _str_env("GUARDIAN_SERVICE_DEPENDENCIES", ""))
    program_dir: str = field(default_factory=lambda: _str_env("GUARDIAN_PROGRAM_DIR", ""))
    log_dir: str = field(default_factory=lambda: _str_env("GUARDIAN_LOG_DIR", ""))
    shutdown_timeout_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_SHUTDOWN_TIMEOUT", 30))

    # ── Heartbeat settings ────────────────────────────────────────────
    heartbeat_interval_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_HEARTBEAT_INTERVAL", 30))

    # ── Logging ───────────────────────────────────────────────────────
    log_level: str = field(default_factory=lambda: _str_env("GUARDIAN_LOG_LEVEL", "INFO"))

    def validate(self) -> None:
        """Validate configuration values.

        Raises ValueError for invalid configuration.
        """
        if not self.agent_key:
            raise ValueError("GUARDIAN_AGENT_KEY is required")
        if not self.host_id:
            raise ValueError("GUARDIAN_HOST_ID is required")
        if not self.backend_url:
            raise ValueError("GUARDIAN_BACKEND_URL is required")
        # Validate backend URL scheme before auth check
        if self.backend_url and not self.backend_url.startswith(("http://", "https://")):
            raise ValueError("GUARDIAN_BACKEND_URL must start with http:// or https://")
        if not self.auth_token:
            raise ValueError("GUARDIAN_AUTH_TOKEN is required")
        if self.queue_max_size < 1:
            raise ValueError("GUARDIAN_QUEUE_MAX_SIZE must be positive")
        if self.sync_interval_seconds < 1:
            raise ValueError("GUARDIAN_SYNC_INTERVAL must be positive")
        if self.sync_batch_size < 1:
            raise ValueError("GUARDIAN_SYNC_BATCH_SIZE must be positive")
        if self.sync_timeout_seconds < 1:
            raise ValueError("GUARDIAN_SYNC_TIMEOUT must be positive")
        if self.sync_max_batch_bytes < 4096 or self.sync_max_batch_bytes > 16_777_216:
            raise ValueError("GUARDIAN_SYNC_MAX_BATCH_BYTES must be 4096-16777216")
        if self.sync_max_backoff_seconds < 5 or self.sync_max_backoff_seconds > 3600:
            raise ValueError("GUARDIAN_SYNC_MAX_BACKOFF must be 5-3600 seconds")
        if self.sending_lease_seconds < 30 or self.sending_lease_seconds > 3600:
            raise ValueError("GUARDIAN_SENDING_LEASE_SECONDS must be 30-3600 seconds")
        if self.shutdown_timeout_seconds < 5 or self.shutdown_timeout_seconds > 300:
            raise ValueError("GUARDIAN_SHUTDOWN_TIMEOUT must be 5-300 seconds")
        for label, path in (("GUARDIAN_DATA_DIR", self.data_dir), ("GUARDIAN_QUEUE_DB_PATH", self.queue_db_path)):
            if not path or ".." in path.replace("\\", "/").split("/"):
                raise ValueError(f"{label} must not be empty or contain '..'")
            if "\x00" in path:
                raise ValueError(f"{label} must not contain NUL")
        if self.etw_network_provider_guid and (
            len(self.etw_network_provider_guid) > 64 or ".." in self.etw_network_provider_guid
        ):
            raise ValueError("GUARDIAN_ETW_NETWORK_GUID is invalid")
        if not self.service_name or len(self.service_name) > 64:
            raise ValueError("GUARDIAN_SERVICE_NAME must be 1-64 chars")
        if not self.service_account or len(self.service_account) > 128:
            raise ValueError("GUARDIAN_SERVICE_ACCOUNT must be 1-128 chars")
        if len(self.service_dependencies) > 512:
            raise ValueError("GUARDIAN_SERVICE_DEPENDENCIES must be at most 512 chars")
        for label, path in (("GUARDIAN_PROGRAM_DIR", self.program_dir), ("GUARDIAN_LOG_DIR", self.log_dir)):
            if path:
                if ".." in path.replace("\\", "/").split("/"):
                    raise ValueError(f"{label} must not contain '..'")
                if "\x00" in path:
                    raise ValueError(f"{label} must not contain NUL")
        if self.heartbeat_interval_seconds < 5:
            raise ValueError("GUARDIAN_HEARTBEAT_INTERVAL must be at least 5 seconds")

    @property
    def is_configured(self) -> bool:
        """Check if the agent has minimal required configuration."""
        return bool(self.agent_key and self.backend_url and self.auth_token)
