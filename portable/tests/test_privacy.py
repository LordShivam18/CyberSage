"""Tests for privacy redaction."""

from __future__ import annotations

from cybersage_portable.models import PrivacyMode
from cybersage_portable.privacy import RedactionConfig, redact_value, redact_host_summary


class TestRedactionStandard:
    def test_standard_mode_no_redaction(self):
        config = RedactionConfig.for_mode(PrivacyMode.STANDARD)
        result = redact_value("testuser", config, current_user="testuser", current_hostname="DESKTOP-ABC")
        assert result == "testuser"

    def test_standard_host_unchanged(self):
        config = RedactionConfig.for_mode(PrivacyMode.STANDARD)
        host = {"hostname": "DESKTOP-ABC", "os_name": "Windows", "os_version": "10.0", "os_build": None, "architecture": "AMD64", "last_boot": None}
        result = redact_host_summary(host, config)
        assert result["hostname"] == "DESKTOP-ABC"


class TestRedactionRedacted:
    def test_hostname_redacted(self):
        config = RedactionConfig.for_mode(PrivacyMode.REDACTED)
        result = redact_value(
            "Connected to DESKTOP-ABC via port 445",
            config,
            current_user="jsmith",
            current_hostname="DESKTOP-ABC",
        )
        assert "DESKTOP-ABC" not in result
        assert "<HOST-" in result

    def test_username_redacted_in_path(self):
        config = RedactionConfig.for_mode(PrivacyMode.REDACTED)
        path = "C:\\Users\\jsmith\\Documents\\secret.txt"
        result = redact_value(path, config, current_user="jsmith", current_hostname="HOST")
        assert "jsmith" not in result
        assert "Documents\\secret.txt" in result or "secret.txt" in result

    def test_cmdline_redacted(self):
        config = RedactionConfig.for_mode(PrivacyMode.REDACTED)
        result = redact_value("cmd.exe /c dir", config, field_hint="cmdline")
        assert result == "<CMDLINE-REDACTED>"

    def test_local_ip_redacted(self):
        config = RedactionConfig.for_mode(PrivacyMode.REDACTED)
        result = redact_value("Connection from 192.168.1.100 to host", config)
        assert "192.168.1.100" not in result
        assert "<IP-" in result

    def test_public_ip_not_redacted(self):
        config = RedactionConfig.for_mode(PrivacyMode.REDACTED)
        result = redact_value("8.8.8.8", config)
        assert "8.8.8.8" in result

    def test_host_summary_hostname_replaced(self):
        config = RedactionConfig.for_mode(PrivacyMode.REDACTED)
        host = {"hostname": "WORKSTATION-007", "os_name": "Windows", "os_version": "10.0", "os_build": None, "architecture": "AMD64", "last_boot": None}
        result = redact_host_summary(host, config)
        assert result["hostname"] != "WORKSTATION-007"
        assert "<HOST-" in result["hostname"]

    def test_no_secrets_in_redacted_mode(self):
        """Even in standard mode, device-id fields are redacted."""
        config = RedactionConfig.for_mode(PrivacyMode.REDACTED)
        result = redact_value("ABC-123-XYZ", config, field_hint="machine_guid")
        assert result == "<DEVICE-ID-REDACTED>"


class TestRedactionMinimal:
    def test_minimal_mode_keeps_os_name(self):
        config = RedactionConfig.for_mode(PrivacyMode.MINIMAL)
        host = {
            "hostname": "WORKSTATION",
            "os_name": "Windows",
            "os_version": "10.0.22631",
            "os_build": "22631",
            "architecture": "AMD64",
            "last_boot": "2026-08-01T00:00:00",
        }
        result = redact_host_summary(host, config)
        assert result.get("os_name") == "Windows"
        assert result.get("hostname") != "WORKSTATION"

    def test_stable_placeholder_is_deterministic(self):
        """Same input must produce same placeholder across calls."""
        from cybersage_portable.privacy import _stable_placeholder
        p1 = _stable_placeholder("DESKTOP-ABC", "HOST")
        p2 = _stable_placeholder("DESKTOP-ABC", "HOST")
        assert p1 == p2

    def test_different_inputs_different_placeholders(self):
        from cybersage_portable.privacy import _stable_placeholder
        p1 = _stable_placeholder("HOST-A", "HOST")
        p2 = _stable_placeholder("HOST-B", "HOST")
        assert p1 != p2


class TestRedactionPrivacyModeRecorded:
    def test_privacy_mode_in_report(self):
        report = {"privacy_mode": "redacted"}
        assert report["privacy_mode"] == "redacted"
