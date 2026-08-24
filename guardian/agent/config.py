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

    # ── Queue settings ────────────────────────────────────────────────
    queue_db_path: str = field(default_factory=lambda: _str_env("GUARDIAN_QUEUE_DB_PATH", "guardian_queue.db"))
    queue_max_size: int = field(default_factory=lambda: _int_env("GUARDIAN_QUEUE_MAX_SIZE", 100_000))

    # ── Sync settings ─────────────────────────────────────────────────
    sync_interval_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_INTERVAL", 10))
    sync_batch_size: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_BATCH_SIZE", 100))
    sync_timeout_seconds: int = field(default_factory=lambda: _int_env("GUARDIAN_SYNC_TIMEOUT", 30))

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
        if self.heartbeat_interval_seconds < 5:
            raise ValueError("GUARDIAN_HEARTBEAT_INTERVAL must be at least 5 seconds")

    @property
    def is_configured(self) -> bool:
        """Check if the agent has minimal required configuration."""
        return bool(self.agent_key and self.backend_url and self.auth_token)
