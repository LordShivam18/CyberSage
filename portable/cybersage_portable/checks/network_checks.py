"""Network security checks (NET-001 … NET-004)."""
from __future__ import annotations

from ipaddress import AddressValueError, IPv4Address
from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck

# Ports that indicate risky or legacy services.
_RISKY_PORTS: dict[int, str] = {
    23: "Telnet (plaintext)",
    21: "FTP control (plaintext)",
    139: "NetBIOS Session Service",
    445: "SMB (Windows file sharing)",
    3389: "Remote Desktop Protocol (RDP)",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    5432: "PostgreSQL",
}


def _is_public_ip(addr: str) -> bool:
    """Return True if the address is not loopback/private/link-local."""
    try:
        ip = IPv4Address(addr)
        return not (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified)
    except AddressValueError:
        return False


class ListeningPortsCheck(SecurityCheck):
    """NET-001: Listening port inventory and risky-service detection."""

    check_id = "NET-001"
    title = "Listening ports and risky services"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        tcp_ports = data.get("tcp_listening") or []
        udp_ports = data.get("udp_listening") or []

        if tcp_ports is None and udp_ports is None:
            return [self._make_unavailable("listening ports not collected", collected_at)]

        findings = []

        for port_entry in tcp_ports:
            if not isinstance(port_entry, dict):
                continue
            local_addr = str(port_entry.get("LocalAddress") or "")
            local_port = port_entry.get("LocalPort")
            if local_port is None:
                continue
            port_num = int(local_port)
            finding_id = f"{self.check_id}:tcp:{port_num}"

            risky_label = _RISKY_PORTS.get(port_num)
            publicly_exposed = _is_public_ip(local_addr) or local_addr in {"0.0.0.0", "::"}

            if risky_label and publicly_exposed:
                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Risky service listening: TCP/{port_num} ({risky_label})",
                    category=Category.NETWORK,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.WARNING,
                    evidence={"protocol": "tcp", "port": port_num, "address": local_addr, "service": risky_label},
                    explanation=f"TCP port {port_num} ({risky_label}) is listening on {local_addr}, which may be publicly reachable.",
                    remediation=f"Restrict access to TCP/{port_num} via firewall rules or disable the service if not required.",
                    collected_at=collected_at,
                ))
            elif port_num > 0:
                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Listening port TCP/{port_num}",
                    category=Category.NETWORK,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.INFORMATIONAL,
                    evidence={"protocol": "tcp", "port": port_num, "address": local_addr},
                    explanation=f"TCP port {port_num} is listening on {local_addr}.",
                    remediation="No action required unless this port is unexpected.",
                    collected_at=collected_at,
                ))

        return findings or [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.NETWORK,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence={"tcp_ports": len(tcp_ports)},
            explanation="No risky services detected on publicly-accessible listening ports.",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class SmbV1Check(SecurityCheck):
    """NET-002: SMBv1 protocol state."""

    check_id = "NET-002"
    title = "SMBv1 protocol state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        smb = data.get("smb")
        if smb is None:
            return [self._make_unavailable("SMB configuration not collected", collected_at)]

        smb1 = None
        if isinstance(smb, dict):
            smb1 = smb.get("EnableSMB1Protocol")

        if smb1 is None:
            return [self._make_unavailable("SMBv1 state not determinable", collected_at)]

        evidence = {"EnableSMB1Protocol": smb1}

        if smb1 is True or str(smb1).lower() in {"true", "1"}:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.NETWORK,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                status=FindingStatus.FAIL,
                evidence=evidence,
                explanation=(
                    "SMBv1 is enabled. SMBv1 is a deprecated protocol exploited by WannaCry and "
                    "NotPetya ransomware. It should be disabled on all modern Windows systems."
                ),
                remediation="Disable SMBv1 via: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                collected_at=collected_at,
                references=["https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.NETWORK,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="SMBv1 is disabled.",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class WinRmCheck(SecurityCheck):
    """NET-003: WinRM remote management exposure."""

    check_id = "NET-003"
    title = "WinRM remote management state"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        winrm = data.get("winrm")
        if winrm is None:
            return [self._make_unavailable("WinRM service state not collected", collected_at)]

        w = winrm if isinstance(winrm, dict) else {}
        status_val = str(w.get("Status") or "Unknown")
        start_type = str(w.get("StartType") or "Unknown")
        evidence = {"status": status_val, "start_type": start_type}

        if status_val.lower() in {"running", "4"}:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.NETWORK,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                status=FindingStatus.WARNING,
                evidence=evidence,
                explanation="WinRM (Windows Remote Management) service is running. This enables remote PowerShell and scripting interfaces.",
                remediation="Disable WinRM if remote management is not required for this device.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.NETWORK,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation=f"WinRM service is not running (status={status_val}).",
            remediation="No action required.",
            collected_at=collected_at,
        )]


class ProxyConfigCheck(SecurityCheck):
    """NET-004: Proxy configuration."""

    check_id = "NET-004"
    title = "Proxy configuration"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        proxy = data.get("proxy")
        if proxy is None:
            return [self._make_unavailable("proxy configuration not collected", collected_at)]

        p = proxy if isinstance(proxy, dict) else {}
        enabled = p.get("ProxyEnable")
        server = str(p.get("ProxyServer") or "")[:256]

        evidence = {"ProxyEnable": enabled, "ProxyServer": server if server else None}

        if enabled and server:
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.NETWORK,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                evidence=evidence,
                explanation=f"A proxy server is configured: {server}. All HTTP/HTTPS traffic may pass through this proxy.",
                remediation="Verify the proxy configuration matches organizational policy.",
                collected_at=collected_at,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.NETWORK,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence=evidence,
            explanation="No proxy configuration detected.",
            remediation="No action required.",
            collected_at=collected_at,
        )]
