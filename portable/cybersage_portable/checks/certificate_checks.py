"""Certificate security checks (CERT-001 … CERT-003)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck


class ExpiredCertificateCheck(SecurityCheck):
    """CERT-001: Expired trusted root certificates."""

    check_id = "CERT-001"
    title = "Expired trusted root certificates"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        findings = []

        for store_key in ("user_roots", "machine_roots"):
            certs = data.get(store_key) or []
            accessible_key = store_key.replace("_roots", "_roots_accessible")
            accessible = data.get(accessible_key, True)

            if not accessible:
                findings.append(self._make_unavailable(f"{store_key} not accessible", collected_at))
                continue

            for cert in certs:
                if not isinstance(cert, dict):
                    continue
                if not cert.get("expired"):
                    continue
                thumbprint = str(cert.get("thumbprint") or "")[:64]
                subject = str(cert.get("subject") or "")[:256]
                not_after = str(cert.get("not_after") or "unknown")
                finding_id = f"{self.check_id}:{thumbprint}"

                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Expired trusted root: {subject[:80]}",
                    category=Category.CERTIFICATES,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.WARNING,
                    evidence={
                        "store": store_key,
                        "thumbprint": thumbprint,
                        "subject": subject,
                        "not_after": not_after,
                    },
                    explanation=(
                        f"Trusted root certificate '{subject}' expired on {not_after}. "
                        "Expired certificates may cause validation failures but do not "
                        "automatically represent a security threat."
                    ),
                    remediation="Review expired root certificates and remove any that are no longer required.",
                    collected_at=collected_at,
                ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.CERTIFICATES,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.PASS,
                evidence={"user_roots": len(data.get("user_roots") or []), "machine_roots": len(data.get("machine_roots") or [])},
                explanation="No expired trusted root certificates found.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings


class SelfSignedRootCheck(SecurityCheck):
    """CERT-002: Self-signed certificates in trusted root stores."""

    check_id = "CERT-002"
    title = "Self-signed trusted root certificates"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        findings = []

        for store_key in ("user_roots", "machine_roots"):
            certs = data.get(store_key) or []
            for cert in certs:
                if not isinstance(cert, dict):
                    continue
                if not cert.get("self_signed"):
                    continue
                thumbprint = str(cert.get("thumbprint") or "")[:64]
                subject = str(cert.get("subject") or "")[:256]

                # Filter out well-known Microsoft self-signed roots (heuristic).
                if "microsoft" in subject.lower() or "windows" in subject.lower():
                    continue

                finding_id = f"{self.check_id}:{thumbprint}"

                findings.append(self._make_finding(
                    finding_id=finding_id,
                    title=f"Self-signed trusted root: {subject[:80]}",
                    category=Category.CERTIFICATES,
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    status=FindingStatus.INFORMATIONAL,
                    evidence={
                        "store": store_key,
                        "thumbprint": thumbprint,
                        "subject": subject,
                        "not_after": cert.get("not_after"),
                    },
                    explanation=(
                        f"Self-signed certificate '{subject}' is present in the {store_key} store. "
                        "Self-signed roots are not inherently malicious but warrant review. "
                        "This is identified by Subject == Issuer — not a cryptographic proof."
                    ),
                    remediation="Review self-signed root certificates. Remove any you do not recognize or that are not required.",
                    collected_at=collected_at,
                ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.CERTIFICATES,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.PASS,
                evidence={},
                explanation="No unexpected self-signed root certificates detected.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings


class CertStoreAccessCheck(SecurityCheck):
    """CERT-003: Certificate store access failures."""

    check_id = "CERT-003"
    title = "Certificate store access"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        user_ok = data.get("user_roots_accessible", True)
        machine_ok = data.get("machine_roots_accessible", True)

        if not user_ok or not machine_ok:
            which = []
            if not user_ok:
                which.append("user root store")
            if not machine_ok:
                which.append("machine root store")
            return [self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.CERTIFICATES,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                status=FindingStatus.PERMISSION_REQUIRED,
                evidence={"inaccessible_stores": which},
                explanation=f"Certificate store(s) not accessible: {', '.join(which)}.",
                remediation="Run the scanner as administrator for complete certificate inspection.",
                collected_at=collected_at,
                admin_required=True,
            )]

        return [self._make_finding(
            finding_id=f"{self.check_id}:host",
            title=self.title,
            category=Category.CERTIFICATES,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PASS,
            evidence={"user_accessible": user_ok, "machine_accessible": machine_ok},
            explanation="Both user and machine certificate stores are accessible.",
            remediation="No action required.",
            collected_at=collected_at,
        )]
