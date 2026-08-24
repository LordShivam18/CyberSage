"""Tests for Guardian agent configuration (Phase 1)."""

import os

import pytest

from guardian.agent.config import AgentConfig


class TestAgentConfig:
    def test_defaults(self):
        config = AgentConfig()
        assert config.agent_version == "2.0.0"
        assert config.queue_max_size == 100_000
        assert config.sync_interval_seconds == 10
        assert config.heartbeat_interval_seconds == 30
        assert config.log_level == "INFO"

    def test_validation_requires_agent_key(self):
        config = AgentConfig()
        with pytest.raises(ValueError, match="GUARDIAN_AGENT_KEY"):
            config.validate()

    def test_validation_requires_backend_url(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "test-key")
        monkeypatch.setenv("GUARDIAN_HOST_ID", "host-001")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "")
        config = AgentConfig()
        with pytest.raises(ValueError, match="GUARDIAN_BACKEND_URL"):
            config.validate()

    def test_validation_requires_auth_token(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "test-key")
        monkeypatch.setenv("GUARDIAN_HOST_ID", "host-001")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "http://localhost:8000")
        config = AgentConfig()
        with pytest.raises(ValueError, match="GUARDIAN_AUTH_TOKEN"):
            config.validate()

    def test_valid_config(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "test-key")
        monkeypatch.setenv("GUARDIAN_HOST_ID", "host-001")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "http://localhost:8000")
        monkeypatch.setenv("GUARDIAN_AUTH_TOKEN", "test-token")
        config = AgentConfig()
        config.validate()  # Should not raise

    def test_rejects_invalid_backend_url(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "test-key")
        monkeypatch.setenv("GUARDIAN_HOST_ID", "host-001")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "ftp://invalid")
        monkeypatch.setenv("GUARDIAN_AUTH_TOKEN", "test-token")
        config = AgentConfig()
        with pytest.raises(ValueError, match="http:// or https://"):
            config.validate()

    def test_rejects_negative_queue_size(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "test-key")
        monkeypatch.setenv("GUARDIAN_HOST_ID", "host-001")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "http://localhost:8000")
        monkeypatch.setenv("GUARDIAN_AUTH_TOKEN", "test-token")
        monkeypatch.setenv("GUARDIAN_QUEUE_MAX_SIZE", "-1")
        config = AgentConfig()
        with pytest.raises(ValueError, match="positive"):
            config.validate()

    def test_rejects_heartbeat_interval_too_low(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "test-key")
        monkeypatch.setenv("GUARDIAN_HOST_ID", "host-001")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "http://localhost:8000")
        monkeypatch.setenv("GUARDIAN_AUTH_TOKEN", "test-token")
        monkeypatch.setenv("GUARDIAN_HEARTBEAT_INTERVAL", "2")
        config = AgentConfig()
        with pytest.raises(ValueError, match="at least 5"):
            config.validate()

    def test_is_configured_property(self, monkeypatch):
        config = AgentConfig()
        assert config.is_configured is False

        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "k")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "http://x")
        monkeypatch.setenv("GUARDIAN_AUTH_TOKEN", "t")
        config2 = AgentConfig()
        assert config2.is_configured is True

    def test_env_var_loading(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_AGENT_KEY", "env-key")
        monkeypatch.setenv("GUARDIAN_HOST_ID", "env-host")
        monkeypatch.setenv("GUARDIAN_HOSTNAME", "env-hostname")
        monkeypatch.setenv("GUARDIAN_BACKEND_URL", "http://env-backend:9000")
        monkeypatch.setenv("GUARDIAN_SYNC_INTERVAL", "30")
        monkeypatch.setenv("GUARDIAN_QUEUE_MAX_SIZE", "50000")

        config = AgentConfig()
        assert config.agent_key == "env-key"
        assert config.host_id == "env-host"
        assert config.host_hostname == "env-hostname"
        assert config.backend_url == "http://env-backend:9000"
        assert config.sync_interval_seconds == 30
        assert config.queue_max_size == 50000
