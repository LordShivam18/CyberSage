"""Account security checks (ACC-001 … ACC-005)."""
from __future__ import annotations

from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck


class CurrentPrivilegeCheck(SecurityCheck):
    """ACC-001: Current process privilege level."""

    check_id = "ACC-001"
    title = "Current user privilege level"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        is_admin = data.get("is_admin")
        user = str(data.get("current_user") or "unknown")
        evidence = {"is_administrator": is_admin, "username": user}

        if is_admin:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.ACCOUNTS,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.WARNING,
                evidence=evidence,
                explanation=(
                    "The scanner is running with administrator privileges. "
                    "Running as administrator increases the impact of any "
                    "attacker code that gains execution on this session."
                ),
                remediation="For routine use, run as a standard user. Elevation should be requested only when needed.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.ACCOUNTS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="Scanner is running as a standard user. Some checks may show PERMISSION_REQUIRED.",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class GuestAccountCheck(SecurityCheck):
    """ACC-002: Guest account enabled state."""

    check_id = "ACC-002"
    title = "Guest account state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        users = data.get("local_users")
        if users is None:
            return [self._make_unavailable("local_users not collected", collected_at)]

        findings = []
        for user in (users or []):
            if not isinstance(user, dict):
                continue
            name = str(user.get("Name") or "")
            enabled = user.get("Enabled")
            if name.lower() == "guest" and enabled:
                findings.append(self._make_finding(
                    finding_id=f"{self.check_id}:{name.lower()}",
                    title=self.title,
                    category=Category.ACCOUNTS,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.FAIL,
                    evidence={"account": name, "enabled": enabled},
                    explanation="The Guest account is enabled. This provides unauthenticated local access.",
                    remediation="Disable the Guest account.",
                    collected_at=collected_at,
                ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.ACCOUNTS,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.PASS,
                evidence={"guest_enabled": False},
                explanation="Guest account is disabled or not present.",
                remediation="No action required.",
                collected_at=collected_at,
            ))
        return findings


class LocalAccountsCheck(SecurityCheck):
    """ACC-003: Enabled local accounts inventory."""

    check_id = "ACC-003"
    title = "Enabled local accounts"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        users = data.get("local_users")
        if users is None:
            return [self._make_unavailable("local_users not collected", collected_at)]

        enabled = [u for u in (users or []) if isinstance(u, dict) and u.get("Enabled")]
        findings = [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.ACCOUNTS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            evidence={"enabled_count": len(enabled),
                      "enabled_accounts": [str(u.get("Name", ""))[:64] for u in enabled]},
            explanation=f"{len(enabled)} enabled local account(s) found.",
            remediation="Review the account list and disable any accounts that are no longer needed.",
            collected_at=collected_at,
        )]
        return findings


class RdpExposureCheck(SecurityCheck):
    """ACC-004: Remote Desktop Protocol exposure."""

    check_id = "ACC-004"
    title = "Remote Desktop (RDP) exposure"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        deny = data.get("rdp_deny_ts_connections")
        if deny is None:
            return [self._make_unavailable("RDP registry value not accessible", collected_at)]

        rdp_enabled = str(deny) == "0"
        evidence = {"fDenyTSConnections": deny, "rdp_enabled": rdp_enabled}

        if rdp_enabled:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.ACCOUNTS,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.WARNING,
                evidence=evidence,
                explanation=(
                    "Remote Desktop (RDP) is enabled on this device. "
                    "RDP exposure increases the attack surface for brute-force and lateral movement attacks."
                ),
                remediation="Disable RDP if not required. If required, restrict access via firewall rules and enable Network Level Authentication.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.ACCOUNTS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="Remote Desktop (RDP) appears disabled.",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class AutoLogonCheck(SecurityCheck):
    """ACC-005: Auto-logon configuration indicator."""

    check_id = "ACC-005"
    title = "Auto-logon indicator"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        autologon = data.get("autologon_enabled")
        if autologon is None:
            return [self._make_unavailable("auto-logon registry value not accessible", collected_at)]

        evidence = {"autologon_enabled": autologon}

        if autologon:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.ACCOUNTS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation=(
                    "Auto-logon is configured on this device (AutoAdminLogon=1). "
                    "This allows automatic sign-in, bypassing the login screen. "
                    "No stored credentials have been read."
                ),
                remediation="Disable auto-logon unless required for a specific documented use case. Restrict physical access.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.ACCOUNTS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="Auto-logon does not appear to be configured.",
            remediation="No action required.",
            collected_at=collected_at,
        )]
