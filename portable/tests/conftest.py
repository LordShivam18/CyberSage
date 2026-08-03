"""
Test fixtures and helpers for portable tests.

All tests must:
  * Not alter the developer's machine.
  * Not disable security controls.
  * Not create persistence.
  * Not execute suspicious programs.
  * Work on non-Windows platforms (Linux/macOS CI).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict | list:
    """Load a JSON fixture by filename (without extension)."""
    path = FIXTURES_DIR / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Shared CollectorResult builders
# ---------------------------------------------------------------------------


def make_collector_result(
    collector_name: str = "test",
    data: dict | None = None,
    errors: list[str] | None = None,
    permission_denied: bool = False,
) -> "CollectorResult":
    from cybersage_portable.models import CollectorResult
    return CollectorResult(
        collector_name=collector_name,
        collector_version="1.0.0",
        collected_at="2026-08-03T00:00:00+00:00",
        data=data or {},
        errors=errors or [],
        permission_denied=permission_denied,
    )


# ---------------------------------------------------------------------------
# Minimal report fixture for import/schema tests
# ---------------------------------------------------------------------------


def minimal_valid_report(assessment_id: str | None = None) -> dict:
    """Return a minimal valid report dict with a correct checksum."""
    from cybersage_portable.models import compute_checksum
    import uuid

    aid = assessment_id or str(uuid.uuid4())
    report = {
        "schema_version": "assessment.v1",
        "assessment_id": aid,
        "scanner_version": "1.0.0",
        "score_algorithm": "posture_score_v1",
        "privacy_mode": "standard",
        "started_at": "2026-08-03T10:00:00+00:00",
        "completed_at": "2026-08-03T10:01:00+00:00",
        "host": {
            "hostname": "test-host",
            "os_name": "Windows",
            "os_version": "10.0.22631",
            "os_build": "22631",
            "architecture": "AMD64",
            "last_boot": None,
        },
        "privilege_level": "standard",
        "checks_attempted": 1,
        "coverage": {
            "attempted": 1,
            "passed": 1,
            "failed": 0,
            "warned": 0,
            "unavailable": 0,
            "permission_required": 0,
            "errors": 0,
            "coverage_pct": 100.0,
        },
        "posture_score": {
            "score": 100,
            "algorithm": "posture_score_v1",
            "components": {
                "fail_critical": 0,
                "fail_high": 0,
                "fail_medium": 0,
                "fail_low": 0,
                "deduction_critical": 0,
                "deduction_high": 0,
                "deduction_medium": 0,
                "deduction_low": 0,
                "total_deduction": 0,
            },
            "caveat": "Posture score is a prioritization aid only.",
        },
        "findings": [],
        "checksum_algorithm": "sha256",
        "checksum": "",
    }
    report["checksum"] = compute_checksum(report)
    return report
