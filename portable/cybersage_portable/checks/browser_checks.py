"""Browser security checks (BRWS-001 … BRWS-003)."""
from __future__ import annotations

from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck

# Minimum versions considered "not obviously outdated".
# These are approximate — always verify with the vendor's support lifecycle.
_MIN_VERSIONS: dict[str, tuple[int, ...]] = {
    "chrome": (120, 0),
    "edge": (120, 0),
    "firefox": (122, 0),
}


def _parse_version(version_str: str) -> tuple[int, ...]:
    try:
        parts = version_str.split(".")
        return tuple(int(p) for p in parts[:2] if p.isdigit())
    except Exception:  # noqa: BLE001
        return (0,)


class BrowserVersionCheck(SecurityCheck):
    """BRWS-001: Installed browser version check."""

    check_id = "BRWS-001"
    title = "Browser version — unsupported or old"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        browsers = data.get("browsers") or []
        if not browsers:
            return [self._make_unavailable("browser data not collected", collected_at)]

        findings = []
        for browser_info in browsers:
            if not isinstance(browser_info, dict):
                continue
            name = str(browser_info.get("browser") or "")
            version = str(browser_info.get("version") or "")
            detected = bool(browser_info.get("detected"))

            if not detected:
                continue

            finding_id = f"{self.check_id}:{name}"
            parsed = _parse_version(version)
            min_ver = _MIN_VERSIONS.get(name, (0,))

            if parsed < min_ver:
                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Outdated browser: {name} {version}",
                    category=Category.BROWSER,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.WARNING,
                    evidence={"browser": name, "version": version, "minimum_checked": ".".join(str(x) for x in min_ver)},
                    explanation=(
                        f"{name.capitalize()} version {version} may be outdated. "
                        "Older browsers may lack security patches. "
                        "This check uses approximate thresholds — consult vendor documentation."
                    ),
                    remediation=f"Update {name.capitalize()} to the latest stable release.",
                    collected_at=collected_at,
                ))
            else:
                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Browser version: {name} {version}",
                    category=Category.BROWSER,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    status=FindingStatus.PASS,
                    evidence={"browser": name, "version": version},
                    explanation=f"{name.capitalize()} version {version} appears current.",
                    remediation="No action required.",
                    collected_at=collected_at,
                ))

        return findings or [self._make_unavailable("no browsers detected", collected_at)]


class UnpackedExtensionCheck(SecurityCheck):
    """BRWS-002: Developer-mode or unpacked browser extensions."""

    check_id = "BRWS-002"
    title = "Unpacked or developer-mode browser extensions"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        extensions = data.get("extensions") or []
        if extensions is None:
            return [self._make_unavailable("extension data not collected", collected_at)]

        findings = []
        for ext in extensions:
            if not isinstance(ext, dict):
                continue
            if not ext.get("unpacked"):
                continue
            browser = str(ext.get("browser") or "")
            ext_id = str(ext.get("extension_id") or "")[:256]
            name = str(ext.get("name") or "")[:256]
            finding_id = f"{self.check_id}:{browser}:{ext_id}"

            findings.append(self._make_finding(
                finding_id=finding_id,
                title=f"Unpacked extension: {name or ext_id} ({browser})",
                category=Category.BROWSER,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.WARNING,
                evidence={
                    "browser": browser,
                    "extension_id": ext_id,
                    "name": name,
                    "version": str(ext.get("version") or "")[:64],
                    "permissions": ext.get("permissions") or [],
                },
                explanation=(
                    f"Browser extension '{name or ext_id}' in {browser} appears to be unpacked "
                    "(developer mode) or installed from a non-store source. "
                    "Unpacked extensions bypass browser store validation."
                ),
                remediation="Remove or review unpacked extensions. Install only from the official browser extension store.",
                collected_at=collected_at,
            ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.BROWSER,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.PASS,
                evidence={"extensions_checked": len(extensions)},
                explanation="No unpacked or developer-mode browser extensions detected.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings


class ExtensionInventoryCheck(SecurityCheck):
    """BRWS-003: Browser extension inventory (informational)."""

    check_id = "BRWS-003"
    title = "Browser extension inventory"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        extensions = data.get("extensions") or []
        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.BROWSER,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.INFORMATIONAL,
            evidence={"extension_count": len(extensions)},
            explanation=f"{len(extensions)} browser extension(s) found across all detected browsers.",
            remediation="Review the extension list and remove any you do not recognize.",
            collected_at=collected_at,
        )]
