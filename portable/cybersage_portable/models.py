"""
Data contracts for CyberSage Portable Assessment.

This module contains ONLY dataclasses and enumerations — no OS calls,
no FastAPI, no SQLAlchemy, no Kafka.  All other modules import from here.

Design notes
------------
* ``check_id``  identifies the rule/check definition (e.g. ``SC-001``).
* ``finding_id`` identifies the specific affected entity within one assessment.
  It is computed as ``{check_id}:{normalized_entity_key}`` and is never derived
  from volatile data such as process IDs.
* ``assessment_id + finding_id`` is the idempotency key for import and alert
  deduplication.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Try to import from shared if it's available in PYTHONPATH
try:
    from shared.report_contract import (
        _SCORE_CAVEAT,
        compute_coverage,
        compute_posture_score,
        canonical_json_bytes,
        compute_checksum,
        verify_checksum
    )
except ImportError:
    # If installed via pip or PyInstaller, it might be at the root of the bundled dir
    # fallback or adjust PYTHONPATH
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
    from shared.report_contract import (
        _SCORE_CAVEAT,
        compute_coverage,
        compute_posture_score,
        canonical_json_bytes,
        compute_checksum,
        verify_checksum
    )

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    PASS = "pass"
    INFORMATIONAL = "informational"
    WARNING = "warning"
    FAIL = "fail"
    UNAVAILABLE = "unavailable"
    PERMISSION_REQUIRED = "permission_required"
    ERROR = "error"


class PrivacyMode(str, Enum):
    STANDARD = "standard"
    REDACTED = "redacted"
    MINIMAL = "minimal"


class Category(str, Enum):
    OPERATING_SYSTEM = "operating_system"
    SECURITY_CONTROLS = "security_controls"
    ACCOUNTS = "accounts"
    PROCESSES = "processes"
    PERSISTENCE = "persistence"
    NETWORK = "network"
    BROWSER = "browser"
    CERTIFICATES = "certificates"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single observation from one security check.

    ``finding_id`` is a stable, normalized key that identifies the specific
    entity being observed (e.g. a port, an executable path, a certificate
    thumbprint).  It must never be derived from a PID or other volatile value.
    """

    check_id: str
    """Rule/check definition identifier, e.g. ``SC-001``."""

    finding_id: str
    """
    Stable entity identifier.  Format: ``{check_id}:{normalized_entity_key}``.
    Must be stable across runs on the same host.
    """

    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    evidence: dict[str, Any]
    explanation: str
    remediation: str
    admin_required: bool
    may_disrupt: bool
    references: list[str]
    collected_at: str          # ISO 8601 UTC
    collector_version: str
    device_impact: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "device_impact": self.device_impact,
            "admin_required": self.admin_required,
            "may_disrupt": self.may_disrupt,
            "references": self.references,
            "collected_at": self.collected_at,
            "collector_version": self.collector_version,
        }


# ---------------------------------------------------------------------------
# Collector result
# ---------------------------------------------------------------------------


@dataclass
class CollectorResult:
    """Raw facts gathered by one collector before check evaluation."""

    collector_name: str
    collector_version: str
    collected_at: str   # ISO 8601 UTC
    data: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    permission_denied: bool = False


# ---------------------------------------------------------------------------
# Coverage and posture score
# ---------------------------------------------------------------------------


@dataclass
class CoverageStats:
    """
    Coverage statistics.

    ``unavailable``, ``permission_required``, and ``errors`` reduce coverage
    but do NOT reduce the posture score.  The score reflects only findings that
    reached a definitive result.
    """

    attempted: int = 0
    passed: int = 0
    failed: int = 0
    warned: int = 0
    unavailable: int = 0
    permission_required: int = 0
    errors: int = 0

    @property
    def coverage_pct(self) -> float:
        return compute_coverage(
            self.attempted,
            self.unavailable,
            self.permission_required,
            self.errors
        )

    def to_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "passed": self.passed,
            "failed": self.failed,
            "warned": self.warned,
            "unavailable": self.unavailable,
            "permission_required": self.permission_required,
            "errors": self.errors,
            "coverage_pct": self.coverage_pct,
        }


@dataclass
class PostureScore:
    """
    Posture score computed by the scanner (posture_score_v1).
    The backend recomputes and verifies this value on import.
    """

    score: int         # 0–100, lower is worse
    algorithm: str     # always "posture_score_v1"
    components: dict[str, int]
    caveat: str        # always the canonical caveat string

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "algorithm": self.algorithm,
            "components": self.components,
            "caveat": self.caveat,
        }

    @staticmethod
    def compute(findings: list[Finding]) -> "PostureScore":
        """
        Compute posture_score_v1 from a list of findings using the shared contract.
        """
        # Convert findings to dicts for the shared compute function
        finding_dicts = [f.to_dict() for f in findings]
        result = compute_posture_score(finding_dicts)

        return PostureScore(
            score=result["score"],
            algorithm=result["algorithm"],
            components=result["components"],
            caveat=result["caveat"],
        )


# ---------------------------------------------------------------------------
# Assessment run (in-memory, pre-serialisation)
# ---------------------------------------------------------------------------


@dataclass
class AssessmentRun:
    """Complete in-memory result of one portable scan."""

    assessment_id: str
    scanner_version: str
    privacy_mode: PrivacyMode
    started_at: str
    completed_at: str
    host: dict[str, Any]
    privilege_level: str          # "standard" | "administrator"
    checks_attempted: int
    coverage: CoverageStats
    posture_score: PostureScore
    findings: list[Finding]
    schema_version: str = "assessment.v1"
    checksum_algorithm: str = "sha256"
    checksum: str = ""            # set by report.py after serialisation



