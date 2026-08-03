"""OS security checks (check IDs: OS-001 … OS-004)."""
from __future__ import annotations

from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck

# Minimum supported Windows build numbers.
# Build < 19041 (2004) is end-of-mainstream-support for Windows 10.
_MIN_SUPPORTED_BUILD = 19041
_WIN10_BASE_BUILD = 10240


class OsVersionCheck(SecurityCheck):
    """OS-001: Windows version and support status."""

    check_id = "OS-001"
    title = "Windows version and support status"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        os_info = data.get("os_version")
        if os_info is None:
            return [self._make_unavailable("os_version not collected", collected_at)]

        if isinstance(os_info, dict) and os_info.get("error"):
            return [self._make_unavailable(os_info["error"], collected_at)]

        caption = str(os_info.get("Caption") or "Unknown")
        version = str(os_info.get("Version") or "")
        build_str = str(os_info.get("BuildNumber") or "")
        arch = str(os_info.get("OSArchitecture") or "Unknown")

        try:
            build = int(build_str)
        except ValueError:
            build = 0

        evidence = {
            "caption": caption,
            "version": version,
            "build_number": build_str,
            "architecture": arch,
        }

        if build > 0 and build < _MIN_SUPPORTED_BUILD:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.OPERATING_SYSTEM,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation=(
                    f"Windows build {build} ({caption}) is older than the minimum "
                    f"supported build ({_MIN_SUPPORTED_BUILD}). End-of-support versions "
                    f"no longer receive security updates."
                ),
                remediation="Upgrade to a supported Windows version.",
                collected_at=collected_at,
                references=["https://learn.microsoft.com/windows/release-health/"],
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.OPERATING_SYSTEM,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation=f"Windows version appears supported: {caption} (build {build_str}).",
            remediation="Keep the system updated to maintain support status.",
            collected_at=collected_at,
        )]


class PendingRestartCheck(SecurityCheck):
    """OS-002: Pending restart indicators."""

    check_id = "OS-002"
    title = "Pending restart indicators"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        restart_info = data.get("pending_restart")
        if restart_info is None:
            return [self._make_unavailable("pending_restart not collected", collected_at)]

        cbs = restart_info.get("cbs")
        wu = restart_info.get("wu")

        if cbs is None and wu is None:
            return [self._make_unavailable("registry keys not accessible", collected_at)]

        pending = bool(cbs or wu)
        evidence = {"cbs_reboot_pending": cbs, "wu_reboot_required": wu}

        if pending:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.OPERATING_SYSTEM,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.WARNING,
                evidence=evidence,
                explanation="A restart is pending. Security updates may not be fully applied until the system is restarted.",
                remediation="Restart the system at the next available maintenance window.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.OPERATING_SYSTEM,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="No pending restart indicators detected in the checked registry keys.",
            remediation=(
                "Note: This check covers two common restart indicators. "
                "Other restart conditions may exist."
            ),
            collected_at=collected_at,
        )]


class UpdateServiceCheck(SecurityCheck):
    """OS-003: Windows Update service state."""

    check_id = "OS-003"
    title = "Windows Update service state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        wu = data.get("update_service")
        if wu is None:
            return [self._make_unavailable("update_service not collected", collected_at)]

        if isinstance(wu, dict) and wu.get("error"):
            return [self._make_unavailable(wu["error"], collected_at)]

        wu_data = wu if isinstance(wu, dict) else {}
        status_val = str(wu_data.get("Status") or "Unknown")
        start_type = str(wu_data.get("StartType") or "Unknown")

        evidence = {"status": status_val, "start_type": start_type}

        if status_val.lower() == "stopped":
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.OPERATING_SYSTEM,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.WARNING,
                evidence=evidence,
                explanation=(
                    "The Windows Update service (wuauserv) is stopped. This may prevent "
                    "automatic installation of security updates. "
                    "Note: A stopped service does not confirm patch levels."
                ),
                remediation="Investigate why the Windows Update service is stopped. Ensure updates are applied via alternative management mechanisms.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.OPERATING_SYSTEM,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation=(
                f"Windows Update service status: {status_val}. "
                "Service state alone does not confirm patch compliance."
            ),
            remediation="Verify update history separately to confirm patch compliance.",
            collected_at=collected_at,
        )]


class LastBootCheck(SecurityCheck):
    """OS-004: Last boot time (informational)."""

    check_id = "OS-004"
    title = "Last system boot time"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        os_info = data.get("os_version")
        if os_info is None:
            return [self._make_unavailable("os_version not collected", collected_at)]

        last_boot = None
        if isinstance(os_info, dict):
            last_boot = os_info.get("LastBootUpTime")

        evidence = {"last_boot": str(last_boot) if last_boot else "unknown"}

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.OPERATING_SYSTEM,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            evidence=evidence,
            explanation="Last system boot time recorded for reference.",
            remediation="No action required.",
            collected_at=collected_at,
        )]
