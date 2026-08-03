"""
Assessment runner.

Orchestrates:
  1. Instantiate all collectors and checks.
  2. Run each collector (read-only).
  3. Pass CollectorResult to matching checks.
  4. Compute CoverageStats and PostureScore.
  5. Apply privacy redaction.
  6. Return an AssessmentRun ready for serialisation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from . import __version__, __schema_version__, __score_algorithm__
from .collectors.os_info import OsInfoCollector
from .collectors.security_controls import SecurityControlsCollector
from .collectors.accounts import AccountsCollector
from .collectors.processes import ProcessesCollector
from .collectors.persistence import PersistenceCollector
from .collectors.network import NetworkCollector
from .collectors.browser import BrowserCollector
from .collectors.certificates import CertificatesCollector

from .checks.os_checks import OsVersionCheck, PendingRestartCheck, UpdateServiceCheck, LastBootCheck
from .checks.security_control_checks import (
    DefenderCheck, FirewallCheck, UacCheck, SecureBootCheck,
    TpmCheck, BitLockerCheck, SmartScreenCheck, SecurityServicesCheck,
)
from .checks.account_checks import (
    CurrentPrivilegeCheck, GuestAccountCheck, LocalAccountsCheck,
    RdpExposureCheck, AutoLogonCheck,
)
from .checks.process_checks import (
    SuspiciousExecutionLocationCheck, UnsignedProcessCheck, ProcessInventoryCheck,
)
from .checks.persistence_checks import (
    RunKeyInventoryCheck, StartupFolderCheck, ScheduledTasksCheck,
)
from .checks.network_checks import (
    ListeningPortsCheck, SmbV1Check, WinRmCheck, ProxyConfigCheck,
)
from .checks.browser_checks import (
    BrowserVersionCheck, UnpackedExtensionCheck, ExtensionInventoryCheck,
)
from .checks.certificate_checks import (
    ExpiredCertificateCheck, SelfSignedRootCheck, CertStoreAccessCheck,
)

from .models import (
    AssessmentRun, CoverageStats, Finding, FindingStatus,
    PostureScore, PrivacyMode,
)
from .platform_abstraction import get_hostname, get_current_username, is_admin
from .privacy import RedactionConfig, redact_host_summary, redact_value


# ---------------------------------------------------------------------------
# Collector → Check mapping
# ---------------------------------------------------------------------------

_COLLECTOR_CHECKS: list[tuple] = [
    (OsInfoCollector, [
        OsVersionCheck(),
        PendingRestartCheck(),
        UpdateServiceCheck(),
        LastBootCheck(),
    ]),
    (SecurityControlsCollector, [
        DefenderCheck(),
        FirewallCheck(),
        UacCheck(),
        SecureBootCheck(),
        TpmCheck(),
        BitLockerCheck(),
        SmartScreenCheck(),
        SecurityServicesCheck(),
    ]),
    (AccountsCollector, [
        CurrentPrivilegeCheck(),
        GuestAccountCheck(),
        LocalAccountsCheck(),
        RdpExposureCheck(),
        AutoLogonCheck(),
    ]),
    (ProcessesCollector, [
        SuspiciousExecutionLocationCheck(),
        UnsignedProcessCheck(),
        ProcessInventoryCheck(),
    ]),
    (PersistenceCollector, [
        RunKeyInventoryCheck(),
        StartupFolderCheck(),
        ScheduledTasksCheck(),
    ]),
    (NetworkCollector, [
        ListeningPortsCheck(),
        SmbV1Check(),
        WinRmCheck(),
        ProxyConfigCheck(),
    ]),
    (BrowserCollector, [
        BrowserVersionCheck(),
        UnpackedExtensionCheck(),
        ExtensionInventoryCheck(),
    ]),
    (CertificatesCollector, [
        ExpiredCertificateCheck(),
        SelfSignedRootCheck(),
        CertStoreAccessCheck(),
    ]),
]


def _build_host_summary(privacy_config: RedactionConfig) -> dict:
    import platform
    import sys
    hostname = get_hostname()
    summary = {
        "hostname": hostname,
        "os_name": platform.system(),
        "os_version": platform.version()[:64],
        "os_build": platform.version().split(".")[-1][:16] if platform.version() else None,
        "architecture": platform.machine(),
        "last_boot": None,  # populated post-collection if available
    }
    return redact_host_summary(summary, privacy_config, current_user=get_current_username())


def _compute_coverage(findings: list[Finding]) -> CoverageStats:
    stats = CoverageStats(attempted=len(findings))
    for f in findings:
        if f.status == FindingStatus.PASS:
            stats.passed += 1
        elif f.status == FindingStatus.FAIL:
            stats.failed += 1
        elif f.status == FindingStatus.WARNING:
            stats.warned += 1
        elif f.status == FindingStatus.UNAVAILABLE:
            stats.unavailable += 1
        elif f.status == FindingStatus.PERMISSION_REQUIRED:
            stats.permission_required += 1
        elif f.status == FindingStatus.ERROR:
            stats.errors += 1
        # INFORMATIONAL counts as passed for coverage purposes
        elif f.status == FindingStatus.INFORMATIONAL:
            stats.passed += 1
    return stats


class AssessmentRunner:
    """Orchestrates collectors and checks for one assessment run."""

    def __init__(
        self,
        privacy_mode: PrivacyMode = PrivacyMode.STANDARD,
        assessment_id: Optional[str] = None,
    ) -> None:
        self.privacy_mode = privacy_mode
        self.assessment_id = assessment_id or str(uuid.uuid4())
        self._privacy_config = RedactionConfig.for_mode(privacy_mode)

    def run(self) -> AssessmentRun:
        started_at = datetime.now(timezone.utc).isoformat()
        username = get_current_username()
        hostname = get_hostname()
        privilege = "administrator" if is_admin() else "standard"

        host_summary = _build_host_summary(self._privacy_config)
        all_findings: list[Finding] = []

        for CollectorClass, checks in _COLLECTOR_CHECKS:
            collector = CollectorClass()
            result = collector.collect()

            for check in checks:
                findings = check.evaluate(result)
                # Apply privacy redaction to evidence fields.
                for finding in findings:
                    finding.evidence = redact_value(
                        finding.evidence,
                        self._privacy_config,
                        current_user=username,
                        current_hostname=hostname,
                    )
                all_findings.extend(findings)

        completed_at = datetime.now(timezone.utc).isoformat()
        coverage = _compute_coverage(all_findings)
        posture_score = PostureScore.compute(all_findings)

        return AssessmentRun(
            assessment_id=self.assessment_id,
            scanner_version=__version__,
            privacy_mode=self.privacy_mode,
            started_at=started_at,
            completed_at=completed_at,
            host=host_summary,
            privilege_level=privilege,
            checks_attempted=len(all_findings),
            coverage=coverage,
            posture_score=posture_score,
            findings=all_findings,
            schema_version=__schema_version__,
        )
