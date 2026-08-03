"""
Abstract SecurityCheck interface.

A SecurityCheck evaluates facts from a CollectorResult and produces
zero or more Finding objects.

Design rules
------------
* Checks are read-only evaluators — they produce findings but never
  perform remediation.
* Checks must not make OS calls — all facts come from CollectorResult.data.
* ``check_id`` follows the pattern ``{CATEGORY_PREFIX}-{NNN}`` where the
  prefix is a 2–4-character uppercase code (e.g. ``OS``, ``SC``, ``ACC``).
* ``finding_id`` is derived inside each check from stable entity keys
  (normalized paths, thumbprints, usernames, port numbers) — never from PIDs.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any

from ..collectors.base import COLLECTOR_VERSION
from ..models import CollectorResult, Finding, FindingStatus


class SecurityCheck(abc.ABC):
    """Abstract base class for all security checks."""

    #: Stable check definition identifier, e.g. ``SC-001``.
    check_id: str

    #: Human-readable check title.
    title: str

    def evaluate(self, result: CollectorResult) -> list[Finding]:
        """
        Evaluate collector data and return zero or more findings.

        If the collector itself had a permission error, return a single
        PERMISSION_REQUIRED finding.  If the collector errored entirely,
        return a single ERROR finding.  Never raise.
        """
        if result.permission_denied:
            return [self._make_permission_required()]
        if not result.data and result.errors:
            return [self._make_error("; ".join(result.errors))]
        try:
            return self._evaluate_impl(result.data, result.collected_at)
        except Exception as exc:  # noqa: BLE001
            return [self._make_error(str(exc))]

    @abc.abstractmethod
    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Finding]:
        """Perform evaluation. Must not make OS calls."""

    def _make_finding(
        self,
        *,
        finding_id: str,
        title: str,
        category: Any,
        severity: Any,
        confidence: Any,
        status: FindingStatus,
        evidence: dict,
        explanation: str,
        remediation: str,
        collected_at: str,
        admin_required: bool = False,
        may_disrupt: bool = False,
        references: list[str] | None = None,
        device_impact: str = "",
    ) -> Finding:
        return Finding(
            check_id=self.check_id,
            finding_id=finding_id,
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            status=status,
            evidence=evidence,
            explanation=explanation,
            remediation=remediation,
            admin_required=admin_required,
            may_disrupt=may_disrupt,
            references=references or [],
            collected_at=collected_at,
            collector_version=COLLECTOR_VERSION,
            device_impact=device_impact,
        )

    def _make_unavailable(self, reason: str = "", collected_at: str = "") -> Finding:
        from ..models import Severity, Confidence, Category
        cat_map = {
            "OS": Category.OPERATING_SYSTEM,
            "SC": Category.SECURITY_CONTROLS,
            "ACC": Category.ACCOUNTS,
            "PROC": Category.PROCESSES,
            "PERS": Category.PERSISTENCE,
            "NET": Category.NETWORK,
            "BRWS": Category.BROWSER,
            "CERT": Category.CERTIFICATES,
        }
        prefix = self.check_id.split("-")[0]
        cat = cat_map.get(prefix, Category.OPERATING_SYSTEM)
        ts = collected_at or datetime.now(timezone.utc).isoformat()
        return self._make_finding(
            finding_id=f"{self.check_id}:unavailable",
            title=self.title,
            category=cat,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.UNAVAILABLE,
            evidence={"reason": reason},
            explanation=f"Check '{self.check_id}' could not be performed: {reason}",
            remediation="No action required.",
            collected_at=ts,
        )

    def _make_permission_required(self, collected_at: str = "") -> Finding:
        from ..models import Severity, Confidence, Category
        cat_map = {
            "OS": Category.OPERATING_SYSTEM,
            "SC": Category.SECURITY_CONTROLS,
            "ACC": Category.ACCOUNTS,
            "PROC": Category.PROCESSES,
            "PERS": Category.PERSISTENCE,
            "NET": Category.NETWORK,
            "BRWS": Category.BROWSER,
            "CERT": Category.CERTIFICATES,
        }
        prefix = self.check_id.split("-")[0]
        cat = cat_map.get(prefix, Category.OPERATING_SYSTEM)
        ts = collected_at or datetime.now(timezone.utc).isoformat()
        return self._make_finding(
            finding_id=f"{self.check_id}:permission_required",
            title=self.title,
            category=cat,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.PERMISSION_REQUIRED,
            evidence={},
            explanation=f"Check '{self.check_id}' requires administrator privileges.",
            remediation="Run the scanner as administrator for complete results.",
            collected_at=ts,
            admin_required=True,
        )

    def _make_error(self, message: str, collected_at: str = "") -> Finding:
        from ..models import Severity, Confidence, Category
        cat_map = {
            "OS": Category.OPERATING_SYSTEM,
            "SC": Category.SECURITY_CONTROLS,
            "ACC": Category.ACCOUNTS,
            "PROC": Category.PROCESSES,
            "PERS": Category.PERSISTENCE,
            "NET": Category.NETWORK,
            "BRWS": Category.BROWSER,
            "CERT": Category.CERTIFICATES,
        }
        prefix = self.check_id.split("-")[0]
        cat = cat_map.get(prefix, Category.OPERATING_SYSTEM)
        ts = collected_at or datetime.now(timezone.utc).isoformat()
        return self._make_finding(
            finding_id=f"{self.check_id}:error",
            title=self.title,
            category=cat,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.LOW,
            status=FindingStatus.ERROR,
            evidence={"error": message[:512]},
            explanation=f"Check '{self.check_id}' encountered a collection error.",
            remediation="Review error details.  The check may require administrator access.",
            collected_at=ts,
        )
