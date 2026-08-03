"""Process security checks (PROC-001 … PROC-003)."""
from __future__ import annotations

import os
from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck

_SUSPICIOUS_DIRS = frozenset({
    "temp", "tmp", "appdata\\local\\temp", "downloads",
    "desktop", "users\\public", "programdata",
})

# Well-known security process names expected to be running.
_SECURITY_PROCESS_NAMES = frozenset({
    "msmpeng.exe", "mssense.exe", "mpcmdrun.exe",
    "csrss.exe", "lsass.exe", "services.exe",
})


def _in_suspicious_dir(path: str) -> bool:
    lower = (path or "").lower().replace("/", "\\")
    return any(sus in lower for sus in _SUSPICIOUS_DIRS)


class SuspiciousExecutionLocationCheck(SecurityCheck):
    """PROC-001: Executables running from suspicious directories."""

    check_id = "PROC-001"
    title = "Suspicious execution location"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        processes = data.get("processes")
        if processes is None:
            return [self._make_unavailable("process list not collected", collected_at)]

        findings = []
        seen_paths: set[str] = set()

        for proc in (processes or []):
            if not isinstance(proc, dict):
                continue
            exe = str(proc.get("exe_path") or "")
            norm = str(proc.get("exe_path_normalized") or "").lower()
            if not exe or not norm or norm in seen_paths:
                continue
            if not proc.get("in_suspicious_dir"):
                continue
            seen_paths.add(norm)

            # Stable finding_id: normalized path, NOT pid.
            finding_id = f"{self.check_id}:{norm[:200]}"

            findings.append(self._make_finding(
                finding_id=finding_id,
                title=f"Execution from suspicious directory: {os.path.basename(exe)}",
                category=Category.PROCESSES,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                status=FindingStatus.WARNING,
                evidence={
                    "exe_path": exe[:512],
                    "process_name": str(proc.get("name") or "")[:128],
                },
                explanation=(
                    f"A process is running from a directory commonly used to stage malicious files: {exe}. "
                    "Being unsigned or in a suspicious location is not conclusive evidence of malice."
                ),
                remediation="Investigate the executable. Verify its legitimacy with your IT or security team.",
                collected_at=collected_at,
                device_impact="Low — check only; no action taken.",
            ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.PROCESSES,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.LOW,
                status=FindingStatus.PASS,
                evidence={"processes_checked": len(processes or [])},
                explanation="No processes found running from high-risk directories.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings


class UnsignedProcessCheck(SecurityCheck):
    """PROC-002: Unsigned executables with Authenticode status."""

    check_id = "PROC-002"
    title = "Unsigned executables in running processes"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        processes = data.get("processes")
        if processes is None:
            return [self._make_unavailable("process list not collected", collected_at)]

        findings = []
        seen_paths: set[str] = set()

        for proc in (processes or []):
            if not isinstance(proc, dict):
                continue
            sig = proc.get("signature")
            if not sig or not isinstance(sig, dict):
                continue
            norm = str(proc.get("exe_path_normalized") or "")
            if not norm or norm in seen_paths:
                continue
            sig_status = str(sig.get("status") or "")
            if sig_status.lower() not in {"notsiged", "notsigned", "hashincompatible", "nottrustprovider"}:
                continue

            seen_paths.add(norm)
            exe = str(proc.get("exe_path") or norm)
            finding_id = f"{self.check_id}:{norm[:200]}"

            # Note: unsigned is not malicious — only informational.
            findings.append(self._make_finding(
                finding_id=finding_id,
                title=f"Unsigned executable: {os.path.basename(exe)}",
                category=Category.PROCESSES,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                evidence={
                    "exe_path": exe[:512],
                    "signature_status": sig_status,
                    "process_name": str(proc.get("name") or "")[:128],
                },
                explanation=(
                    f"Executable '{os.path.basename(exe)}' has Authenticode status '{sig_status}'. "
                    "Unsigned executables are not necessarily malicious but warrant review, "
                    "especially in sensitive startup contexts."
                ),
                remediation="Verify the executable is legitimate. Prefer signed software.",
                collected_at=collected_at,
            ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.PROCESSES,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.PASS,
                evidence={"signature_checks": data.get("signature_checks_performed", 0)},
                explanation="All checked running executables have valid Authenticode signatures or signatures could not be checked.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings


class ProcessInventoryCheck(SecurityCheck):
    """PROC-003: Process inventory summary (informational)."""

    check_id = "PROC-003"
    title = "Running process inventory"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        processes = data.get("processes") or []
        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.PROCESSES,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.INFORMATIONAL,
            evidence={"process_count": len(processes)},
            explanation=f"{len(processes)} running processes inventoried.",
            remediation="No action required.",
            collected_at=collected_at,
        )]
