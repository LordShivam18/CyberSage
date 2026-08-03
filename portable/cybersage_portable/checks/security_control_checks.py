"""Security control checks (SC-001 … SC-008)."""
from __future__ import annotations

from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck


class DefenderCheck(SecurityCheck):
    """SC-001: Microsoft Defender availability and real-time protection."""

    check_id = "SC-001"
    title = "Microsoft Defender state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        defender = data.get("defender")
        if defender is None:
            return [self._make_unavailable("defender status not collected", collected_at)]
        if isinstance(defender, dict) and defender.get("error"):
            return [self._make_unavailable(defender["error"], collected_at)]

        d = defender if isinstance(defender, dict) else {}
        av_enabled = d.get("AntivirusEnabled")
        rtp_enabled = d.get("RealTimeProtectionEnabled")
        am_service = d.get("AMServiceEnabled")
        evidence = {
            "AntivirusEnabled": av_enabled,
            "RealTimeProtectionEnabled": rtp_enabled,
            "AMServiceEnabled": am_service,
        }

        if av_enabled is False or rtp_enabled is False:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.SECURITY_CONTROLS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation=(
                    "Microsoft Defender antivirus or real-time protection is disabled. "
                    "This significantly increases exposure to malware. "
                    "Note: A third-party security product may be active."
                ),
                remediation=(
                    "Enable Microsoft Defender real-time protection or ensure a "
                    "supported third-party security product is active."
                ),
                collected_at=collected_at,
                references=["https://learn.microsoft.com/microsoft-365/security/defender-endpoint/"],
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.SECURITY_CONTROLS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="Microsoft Defender antivirus and real-time protection appear active.",
            remediation="Keep definitions updated.",
            collected_at=collected_at,
        )]


class FirewallCheck(SecurityCheck):
    """SC-002: Windows Firewall profile states."""

    check_id = "SC-002"
    title = "Windows Firewall profiles"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        profiles = data.get("firewall")
        if profiles is None:
            return [self._make_unavailable("firewall profiles not collected", collected_at)]

        findings = []
        if not profiles:
            findings.append(self._make_unavailable("no firewall profiles returned", collected_at))
            return findings

        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            name = str(profile.get("Name") or "Unknown")
            enabled = profile.get("Enabled")
            finding_id = f"{self.check_id}:{name.lower()}"
            if enabled is False:
                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Windows Firewall disabled — {name} profile",
                    category=Category.SECURITY_CONTROLS,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.FAIL,
                    evidence={"profile": name, "enabled": enabled},
                    explanation=f"The Windows Firewall {name} profile is disabled. This removes inbound connection filtering for that network category.",
                    remediation=f"Enable the Windows Firewall {name} profile.",
                    collected_at=collected_at,
                ))
            else:
                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Windows Firewall — {name} profile",
                    category=Category.SECURITY_CONTROLS,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.PASS,
                    evidence={"profile": name, "enabled": enabled},
                    explanation=f"Windows Firewall {name} profile is enabled.",
                    remediation="No action required.",
                    collected_at=collected_at,
                ))
        return findings


class UacCheck(SecurityCheck):
    """SC-003: User Account Control consent level."""

    check_id = "SC-003"
    title = "User Account Control (UAC) state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        level = data.get("uac_consent_level")
        if level is None:
            return [self._make_unavailable("UAC registry key not accessible", collected_at)]

        evidence = {"ConsentPromptBehaviorAdmin": level}

        if level == 0:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.SECURITY_CONTROLS,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation="UAC is disabled (ConsentPromptBehaviorAdmin=0). Privilege escalation does not require consent.",
                remediation="Enable UAC via Security Policy or Group Policy.",
                collected_at=collected_at,
                references=["https://learn.microsoft.com/windows/security/identity-protection/user-account-control/"],
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.SECURITY_CONTROLS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation=f"UAC is enabled (ConsentPromptBehaviorAdmin={level}).",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class SecureBootCheck(SecurityCheck):
    """SC-004: Secure Boot state."""

    check_id = "SC-004"
    title = "Secure Boot state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        sb = data.get("secure_boot")
        if sb is None:
            return [self._make_unavailable("Secure Boot state not collected", collected_at)]

        secure_boot_val = None
        if isinstance(sb, dict):
            secure_boot_val = sb.get("SecureBoot")

        if secure_boot_val is None:
            return [self._make_unavailable("Secure Boot value unavailable (may require UEFI firmware)", collected_at)]

        evidence = {"SecureBoot": secure_boot_val}

        if secure_boot_val is False:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.SECURITY_CONTROLS,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation="Secure Boot is disabled or not supported. Boot integrity cannot be verified.",
                remediation="Enable Secure Boot in UEFI firmware settings if supported.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.SECURITY_CONTROLS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="Secure Boot is enabled.",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class TpmCheck(SecurityCheck):
    """SC-005: TPM availability and readiness."""

    check_id = "SC-005"
    title = "TPM availability"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        tpm = data.get("tpm")
        if tpm is None:
            return [self._make_unavailable("TPM state not collected", collected_at)]

        t = tpm if isinstance(tpm, dict) else {}
        present = t.get("TpmPresent")
        ready = t.get("TpmReady")
        enabled = t.get("TpmEnabled")

        if present is None:
            return [self._make_unavailable("TPM information unavailable", collected_at)]

        evidence = {"TpmPresent": present, "TpmReady": ready, "TpmEnabled": enabled}

        if not present:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.SECURITY_CONTROLS,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation="No TPM (Trusted Platform Module) detected. TPM is required for BitLocker, Windows Hello, and other security features.",
                remediation="Check BIOS/UEFI for a TPM option or verify hardware support.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.SECURITY_CONTROLS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation=f"TPM present={present}, ready={ready}, enabled={enabled}.",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class BitLockerCheck(SecurityCheck):
    """SC-006: BitLocker or device-encryption state."""

    check_id = "SC-006"
    title = "BitLocker / device-encryption state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        volumes = data.get("bitlocker")
        if volumes is None:
            return [self._make_unavailable("BitLocker state not collected", collected_at)]

        findings = []
        if not volumes:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:no_volumes",
                title=self.title,
                category=Category.SECURITY_CONTROLS,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                status=FindingStatus.WARNING,
                evidence={"volumes": []},
                explanation="No BitLocker-managed volumes detected. Drive encryption may not be active.",
                remediation="Enable BitLocker encryption on sensitive volumes.",
                collected_at=collected_at,
            ))
            return findings

        for vol in volumes:
            if not isinstance(vol, dict):
                continue
            mount = str(vol.get("MountPoint") or "unknown")
            protection = str(vol.get("ProtectionStatus") or "Unknown")
            mount_key = mount.strip("/\\:").lower() or "volume"
            finding_id = f"{self.check_id}:{mount_key}"
            is_protected = protection.lower() in {"on", "1", "protected"}
            findings.append(self._make_finding(
                finding_id=finding_id,
                title=f"BitLocker — {mount}",
                category=Category.SECURITY_CONTROLS,
                severity=Severity.MEDIUM if not is_protected else Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL if not is_protected else FindingStatus.PASS,
                evidence={"mount_point": mount, "protection_status": protection, "volume_status": vol.get("VolumeStatus")},
                explanation=(
                    f"Volume {mount}: BitLocker protection status = {protection}."
                    if not is_protected else
                    f"Volume {mount}: BitLocker protection is active."
                ),
                remediation="Enable BitLocker protection on unprotected volumes containing sensitive data." if not is_protected else "No action required.",
                collected_at=collected_at,
            ))
        return findings


class SmartScreenCheck(SecurityCheck):
    """SC-007: SmartScreen state."""

    check_id = "SC-007"
    title = "SmartScreen state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        ss = data.get("smartscreen")
        if ss is None:
            return [self._make_unavailable("SmartScreen data not collected", collected_at)]

        value = None
        if isinstance(ss, dict):
            value = ss.get("SmartScreenEnabled")

        if value is None:
            return [self._make_unavailable("SmartScreen registry value unavailable", collected_at)]

        evidence = {"SmartScreenEnabled": value}
        enabled_values = {"requireadmin", "warn", "on", "1", "true"}
        is_enabled = str(value).lower() in enabled_values

        if not is_enabled:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.SECURITY_CONTROLS,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation="SmartScreen appears to be disabled. SmartScreen helps prevent execution of unrecognized malicious files.",
                remediation="Enable SmartScreen in Windows Security settings.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.SECURITY_CONTROLS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation=f"SmartScreen is enabled (value={value}).",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class SecurityServicesCheck(SecurityCheck):
    """SC-008: Critical Windows Security services state."""

    check_id = "SC-008"
    title = "Windows Security services state"

    _EXPECTED_RUNNING = {"WinDefend", "wscsvc", "SecurityHealthService"}

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        services = data.get("security_services")
        if services is None:
            return [self._make_unavailable("security services not collected", collected_at)]

        findings = []
        for svc in (services or []):
            if not isinstance(svc, dict):
                continue
            name = str(svc.get("Name") or "")
            status_val = str(svc.get("Status") or "")
            finding_id = f"{self.check_id}:{name.lower()}"
            is_running = status_val.lower() in {"running", "4"}

            if name in self._EXPECTED_RUNNING and not is_running:
                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Security service stopped — {name}",
                    category=Category.SECURITY_CONTROLS,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.FAIL,
                    evidence={"service": name, "status": status_val, "start_type": svc.get("StartType")},
                    explanation=f"Security service '{name}' is not running. This may indicate tampered or disabled security controls.",
                    remediation=f"Investigate why '{name}' is stopped and restart if appropriate.",
                    collected_at=collected_at,
                ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.SECURITY_CONTROLS,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.PASS,
                evidence={"services_checked": [s.get("Name") for s in (services or []) if isinstance(s, dict)]},
                explanation="All checked Windows Security services appear to be running.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings
