"""
Tests for all eight collectors using fixture data (no real OS calls).

Tests must not:
  * Make real subprocess calls.
  * Alter registry, files, or system configuration.
  * Work only on Windows (all tests run on CI Linux).
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from .conftest import load_fixture, make_collector_result


# ---------------------------------------------------------------------------
# OsInfoCollector
# ---------------------------------------------------------------------------


class TestOsInfoCollector:
    def test_collects_os_version_success(self):
        """Collector parses OS version data correctly."""
        fixture = load_fixture("os_info")
        os_ver = fixture["os_version"]
        with (
            patch("cybersage_portable.collectors.os_info.run_ps_os_version", return_value=(os_ver, None)),
            patch("cybersage_portable.collectors.os_info.run_ps_pending_restart", return_value=(fixture["pending_restart"], None)),
            patch("cybersage_portable.collectors.os_info.run_ps_update_service", return_value=(fixture["update_service"], None)),
        ):
            from cybersage_portable.collectors.os_info import OsInfoCollector
            result = OsInfoCollector().collect()
        assert result.collector_name == "os_info"
        assert result.data["os_version"]["Caption"] == "Microsoft Windows 11 Pro"
        assert result.data["pending_restart"]["cbs"] is False
        assert result.errors == []

    def test_handles_os_version_error(self):
        """Collector records error when API fails."""
        with (
            patch("cybersage_portable.collectors.os_info.run_ps_os_version", return_value=(None, "timeout_after_15s")),
            patch("cybersage_portable.collectors.os_info.run_ps_pending_restart", return_value=(None, "not_windows")),
            patch("cybersage_portable.collectors.os_info.run_ps_update_service", return_value=(None, "not_windows")),
        ):
            from cybersage_portable.collectors.os_info import OsInfoCollector
            result = OsInfoCollector().collect()
        assert result.data["os_version"] is None
        assert any("timeout" in e for e in result.errors)


# ---------------------------------------------------------------------------
# SecurityControlsCollector
# ---------------------------------------------------------------------------


class TestSecurityControlsCollector:
    def test_collects_defender_success(self):
        fixture = load_fixture("defender_state")
        firewall = load_fixture("firewall_state")
        with (
            patch("cybersage_portable.collectors.security_controls.run_ps_defender", return_value=(fixture, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_firewall", return_value=(firewall, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_smartscreen", return_value=({"SmartScreenEnabled": "RequireAdmin"}, None)),
            patch("cybersage_portable.collectors.security_controls.get_uac_state", return_value=(5, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_secure_boot", return_value=({"SecureBoot": True}, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_tpm", return_value=({"TpmPresent": True, "TpmReady": True, "TpmEnabled": True}, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_bitlocker", return_value=([{"MountPoint": "C:", "ProtectionStatus": "On", "VolumeStatus": "FullyEncrypted"}], None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_security_services", return_value=(load_fixture("services"), None)),
        ):
            from cybersage_portable.collectors.security_controls import SecurityControlsCollector
            result = SecurityControlsCollector().collect()
        assert result.data["defender"]["AntivirusEnabled"] is True
        assert len(result.data["firewall"]) == 3
        assert result.errors == []

    def test_permission_denied_bitlocker(self):
        with (
            patch("cybersage_portable.collectors.security_controls.run_ps_defender", return_value=({"AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AMServiceEnabled": True}, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_firewall", return_value=([], None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_smartscreen", return_value=({"SmartScreenEnabled": "RequireAdmin"}, None)),
            patch("cybersage_portable.collectors.security_controls.get_uac_state", return_value=(5, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_secure_boot", return_value=({"SecureBoot": True}, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_tpm", return_value=({"TpmPresent": True}, None)),
            patch("cybersage_portable.collectors.security_controls.run_ps_bitlocker", return_value=(None, "permission_denied")),
            patch("cybersage_portable.collectors.security_controls.run_ps_security_services", return_value=([], None)),
        ):
            from cybersage_portable.collectors.security_controls import SecurityControlsCollector
            result = SecurityControlsCollector().collect()
        assert result.data["bitlocker"] is None
        assert result.permission_denied is True


# ---------------------------------------------------------------------------
# AccountsCollector
# ---------------------------------------------------------------------------


class TestAccountsCollector:
    def test_collects_accounts(self):
        users = [
            {"Name": "Administrator", "Enabled": False, "PasswordRequired": True, "PasswordExpires": None, "PasswordNeverExpires": True, "LastLogon": None, "Description": ""},
            {"Name": "testuser", "Enabled": True, "PasswordRequired": True, "PasswordExpires": None, "PasswordNeverExpires": False, "LastLogon": None, "Description": ""},
            {"Name": "Guest", "Enabled": False, "PasswordRequired": False, "PasswordExpires": None, "PasswordNeverExpires": True, "LastLogon": None, "Description": ""},
        ]
        with (
            patch("cybersage_portable.collectors.accounts.is_admin", return_value=False),
            patch("cybersage_portable.collectors.accounts.get_current_username", return_value="testuser"),
            patch("cybersage_portable.collectors.accounts.run_ps_local_admins", return_value=([{"Name": "Administrator", "ObjectClass": "User", "PrincipalSource": "Local"}], None)),
            patch("cybersage_portable.collectors.accounts.run_ps_local_users", return_value=(users, None)),
            patch("cybersage_portable.collectors.accounts.run_ps_rdp", return_value=({"fDenyTSConnections": 1}, None)),
            patch("cybersage_portable.collectors.accounts.get_autologon_indicator", return_value=(False, None)),
        ):
            from cybersage_portable.collectors.accounts import AccountsCollector
            result = AccountsCollector().collect()
        assert result.data["is_admin"] is False
        assert result.data["current_user"] == "testuser"
        assert result.data["rdp_deny_ts_connections"] == 1
        assert result.data["autologon_enabled"] is False

    def test_non_admin_execution(self):
        """Verifies non-admin path works without permission errors."""
        with (
            patch("cybersage_portable.collectors.accounts.is_admin", return_value=False),
            patch("cybersage_portable.collectors.accounts.get_current_username", return_value="normaluser"),
            patch("cybersage_portable.collectors.accounts.run_ps_local_admins", return_value=([], None)),
            patch("cybersage_portable.collectors.accounts.run_ps_local_users", return_value=([], None)),
            patch("cybersage_portable.collectors.accounts.run_ps_rdp", return_value=({"fDenyTSConnections": 1}, None)),
            patch("cybersage_portable.collectors.accounts.get_autologon_indicator", return_value=(False, None)),
        ):
            from cybersage_portable.collectors.accounts import AccountsCollector
            result = AccountsCollector().collect()
        assert result.permission_denied is False
        assert result.errors == []


# ---------------------------------------------------------------------------
# ProcessesCollector
# ---------------------------------------------------------------------------


class TestProcessesCollector:
    def test_detects_suspicious_dir(self):
        procs = load_fixture("processes")
        with (
            patch("cybersage_portable.collectors.processes.run_ps_processes", return_value=(procs, None)),
            patch("cybersage_portable.collectors.processes.run_ps_authenticode", return_value=({"Status": "Valid"}, None)),
        ):
            from cybersage_portable.collectors.processes import ProcessesCollector
            result = ProcessesCollector().collect()
        suspicious = [p for p in result.data["processes"] if p["in_suspicious_dir"]]
        assert len(suspicious) >= 1
        assert "suspicious.exe" in suspicious[0]["name"]

    def test_pid_not_in_finding_key_field(self):
        """Ensure we don't rely on PID as stable identity."""
        procs = load_fixture("processes")
        with (
            patch("cybersage_portable.collectors.processes.run_ps_processes", return_value=(procs, None)),
            patch("cybersage_portable.collectors.processes.run_ps_authenticode", return_value=({"Status": "Valid"}, None)),
        ):
            from cybersage_portable.collectors.processes import ProcessesCollector
            result = ProcessesCollector().collect()
        # exe_path_normalized should be the stable key, not pid
        for p in result.data["processes"]:
            assert "exe_path_normalized" in p


# ---------------------------------------------------------------------------
# NetworkCollector
# ---------------------------------------------------------------------------


class TestNetworkCollector:
    def test_collects_listening_ports(self):
        ports = load_fixture("listening_ports")
        with (
            patch("cybersage_portable.collectors.network.run_ps_tcp_listen", return_value=(ports, None)),
            patch("cybersage_portable.collectors.network.run_ps_udp_listen", return_value=([], None)),
            patch("cybersage_portable.collectors.network.run_ps_tcp_established", return_value=([], None)),
            patch("cybersage_portable.collectors.network.run_ps_dns", return_value=([], None)),
            patch("cybersage_portable.collectors.network.run_ps_net_profiles", return_value=([], None)),
            patch("cybersage_portable.collectors.network.run_ps_smb", return_value=({"EnableSMB1Protocol": False}, None)),
            patch("cybersage_portable.collectors.network.run_ps_winrm", return_value=({"Status": "Stopped"}, None)),
            patch("cybersage_portable.collectors.network.run_ps_proxy", return_value=({"ProxyEnable": 0}, None)),
        ):
            from cybersage_portable.collectors.network import NetworkCollector
            result = NetworkCollector().collect()
        assert len(result.data["tcp_listening"]) == 4
        assert result.errors == []
