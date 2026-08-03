"""Tests for security checks using fixture CollectorResults."""

from __future__ import annotations

from .conftest import load_fixture, make_collector_result
from cybersage_portable.models import FindingStatus, Severity


class TestOsChecks:
    def test_old_build_fails(self):
        from cybersage_portable.checks.os_checks import OsVersionCheck
        data = {
            "os_version": {
                "Caption": "Microsoft Windows 10",
                "Version": "10.0.14393",
                "BuildNumber": "14393",  # RS1, end of support
                "OSArchitecture": "64-bit",
                "LastBootUpTime": None,
            }
        }
        result = make_collector_result("os_info", data)
        findings = OsVersionCheck().evaluate(result)
        assert any(f.status == FindingStatus.FAIL for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_current_build_passes(self):
        from cybersage_portable.checks.os_checks import OsVersionCheck
        data = {
            "os_version": {
                "Caption": "Microsoft Windows 11 Pro",
                "Version": "10.0.22631",
                "BuildNumber": "22631",
                "OSArchitecture": "64-bit",
                "LastBootUpTime": None,
            }
        }
        result = make_collector_result("os_info", data)
        findings = OsVersionCheck().evaluate(result)
        assert any(f.status == FindingStatus.PASS for f in findings)

    def test_unavailable_when_data_missing(self):
        from cybersage_portable.checks.os_checks import OsVersionCheck
        result = make_collector_result("os_info", {})
        findings = OsVersionCheck().evaluate(result)
        assert any(f.status == FindingStatus.UNAVAILABLE for f in findings)

    def test_permission_required_state(self):
        from cybersage_portable.checks.os_checks import OsVersionCheck
        result = make_collector_result("os_info", {}, permission_denied=True)
        findings = OsVersionCheck().evaluate(result)
        assert findings[0].status == FindingStatus.PERMISSION_REQUIRED

    def test_pending_restart_warning(self):
        from cybersage_portable.checks.os_checks import PendingRestartCheck
        data = {"pending_restart": {"cbs": True, "wu": False}}
        result = make_collector_result("os_info", data)
        findings = PendingRestartCheck().evaluate(result)
        assert any(f.status == FindingStatus.WARNING for f in findings)


class TestSecurityControlChecks:
    def test_defender_disabled_fails(self):
        from cybersage_portable.checks.security_control_checks import DefenderCheck
        data = {
            "defender": {
                "AntivirusEnabled": False,
                "RealTimeProtectionEnabled": False,
                "AMServiceEnabled": True,
            }
        }
        result = make_collector_result("security_controls", data)
        findings = DefenderCheck().evaluate(result)
        assert any(f.status == FindingStatus.FAIL for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_defender_enabled_passes(self):
        from cybersage_portable.checks.security_control_checks import DefenderCheck
        data = load_fixture("defender_state")
        result = make_collector_result("security_controls", {"defender": data})
        findings = DefenderCheck().evaluate(result)
        assert any(f.status == FindingStatus.PASS for f in findings)

    def test_firewall_disabled_profile_fails(self):
        from cybersage_portable.checks.security_control_checks import FirewallCheck
        data = {
            "firewall": [
                {"Name": "Public", "Enabled": False},
                {"Name": "Private", "Enabled": True},
            ]
        }
        result = make_collector_result("security_controls", data)
        findings = FirewallCheck().evaluate(result)
        fail_findings = [f for f in findings if f.status == FindingStatus.FAIL]
        assert len(fail_findings) == 1
        assert "Public" in fail_findings[0].title

    def test_firewall_all_enabled_passes(self):
        from cybersage_portable.checks.security_control_checks import FirewallCheck
        data = {"firewall": load_fixture("firewall_state")}
        result = make_collector_result("security_controls", data)
        findings = FirewallCheck().evaluate(result)
        assert not any(f.status == FindingStatus.FAIL for f in findings)

    def test_uac_disabled_critical(self):
        from cybersage_portable.checks.security_control_checks import UacCheck
        data = {"uac_consent_level": 0}
        result = make_collector_result("security_controls", data)
        findings = UacCheck().evaluate(result)
        assert any(f.severity == Severity.CRITICAL and f.status == FindingStatus.FAIL for f in findings)

    def test_smbv1_enabled_fails(self):
        from cybersage_portable.checks.network_checks import SmbV1Check
        data = {"smb": {"EnableSMB1Protocol": True}}
        result = make_collector_result("network", data)
        findings = SmbV1Check().evaluate(result)
        assert any(f.status == FindingStatus.FAIL and f.severity == Severity.HIGH for f in findings)

    def test_security_services_stopped_fails(self):
        from cybersage_portable.checks.security_control_checks import SecurityServicesCheck
        data = {
            "security_services": [
                {"Name": "WinDefend", "Status": "Stopped", "StartType": "Automatic"},
            ]
        }
        result = make_collector_result("security_controls", data)
        findings = SecurityServicesCheck().evaluate(result)
        assert any(f.status == FindingStatus.FAIL for f in findings)


class TestProcessChecks:
    def test_suspicious_location_warning(self):
        from cybersage_portable.checks.process_checks import SuspiciousExecutionLocationCheck
        procs = load_fixture("processes")
        # Simulate collector data with pre-annotated suspicious flag
        for p in procs:
            exe = str(p.get("ExecutablePath") or "")
            p["exe_path"] = exe
            p["exe_path_normalized"] = exe.lower()
            p["in_suspicious_dir"] = "temp" in exe.lower() or "downloads" in exe.lower()
            p["name"] = str(p.get("Name") or "")
            p["signature"] = None
            p["cmdline_available"] = False
        result = make_collector_result("processes", {"processes": procs})
        findings = SuspiciousExecutionLocationCheck().evaluate(result)
        suspicious = [f for f in findings if f.status == FindingStatus.WARNING]
        assert len(suspicious) >= 1

    def test_finding_id_not_pid_based(self):
        """finding_id must be based on path, not PID."""
        from cybersage_portable.checks.process_checks import SuspiciousExecutionLocationCheck
        proc = {
            "pid": 99999,
            "exe_path": "C:\\Users\\Public\\test.exe",
            "exe_path_normalized": "c:\\users\\public\\test.exe",
            "in_suspicious_dir": True,
            "name": "test.exe",
            "signature": None,
            "cmdline_available": False,
        }
        result = make_collector_result("processes", {"processes": [proc]})
        findings = SuspiciousExecutionLocationCheck().evaluate(result)
        for f in findings:
            assert "99999" not in f.finding_id


class TestNetworkChecks:
    def test_smb1_disabled_passes(self):
        from cybersage_portable.checks.network_checks import SmbV1Check
        result = make_collector_result("network", {"smb": {"EnableSMB1Protocol": False}})
        findings = SmbV1Check().evaluate(result)
        assert any(f.status == FindingStatus.PASS for f in findings)

    def test_listening_port_risky_service(self):
        from cybersage_portable.checks.network_checks import ListeningPortsCheck
        ports = load_fixture("listening_ports")
        result = make_collector_result("network", {"tcp_listening": ports, "udp_listening": []})
        findings = ListeningPortsCheck().evaluate(result)
        warnings = [f for f in findings if f.status == FindingStatus.WARNING]
        # Port 5985 on 0.0.0.0 should be flagged
        assert any("5985" in str(f.evidence.get("port", "")) for f in warnings)


class TestCertificateChecks:
    def test_expired_cert_warning(self):
        from cybersage_portable.checks.certificate_checks import ExpiredCertificateCheck
        fixture = load_fixture("certificates")
        result = make_collector_result("certificates", fixture)
        findings = ExpiredCertificateCheck().evaluate(result)
        expired = [f for f in findings if f.status == FindingStatus.WARNING]
        assert len(expired) >= 1

    def test_recently_installed_always_unavailable(self):
        """Certificate recently_installed field must always be 'unavailable' in v1."""
        fixture = load_fixture("certificates")
        for cert in fixture["user_roots"]:
            assert cert["recently_installed"] == "unavailable"


class TestBrowserChecks:
    def test_unpacked_extension_warning(self):
        from cybersage_portable.checks.browser_checks import UnpackedExtensionCheck
        exts = load_fixture("browser_extensions")
        result = make_collector_result("browser", {"extensions": exts})
        findings = UnpackedExtensionCheck().evaluate(result)
        warnings = [f for f in findings if f.status == FindingStatus.WARNING]
        assert len(warnings) >= 1
        # finding_id should contain browser:extension_id, not PID
        for f in warnings:
            assert "chrome:" in f.finding_id


class TestPersistenceChecks:
    def test_scheduled_task_informational(self):
        from cybersage_portable.checks.persistence_checks import ScheduledTasksCheck
        tasks = load_fixture("scheduled_tasks")
        result = make_collector_result("persistence", {"scheduled_tasks": tasks})
        findings = ScheduledTasksCheck().evaluate(result)
        info = [f for f in findings if f.status == FindingStatus.INFORMATIONAL]
        assert len(info) >= 1
        # finding_id should be hash-based, not task index
        for f in info:
            assert "PERS-003:" in f.finding_id
