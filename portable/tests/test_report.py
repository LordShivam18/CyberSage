"""Tests for report generation, checksum, and schema validation."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from .conftest import minimal_valid_report
from cybersage_portable.models import compute_checksum, verify_checksum


class TestChecksum:
    def test_checksum_computed_correctly(self):
        report = minimal_valid_report()
        assert verify_checksum(report)

    def test_checksum_excludes_checksum_field(self):
        """The checksum field itself must not be part of the hashed payload."""
        report = minimal_valid_report()
        # If checksum were included in the hash, changing it would change the hash,
        # making it impossible to compute. Verify that we can round-trip.
        original_checksum = report["checksum"]
        recomputed = compute_checksum(report)
        assert recomputed == original_checksum

    def test_tampered_report_fails_checksum(self):
        """Any change to the payload must invalidate the checksum."""
        report = minimal_valid_report()
        report["privilege_level"] = "administrator"  # tamper
        assert not verify_checksum(report)

    def test_checksum_uses_sorted_keys_compact_separators(self):
        """Verify canonical JSON format: sorted keys, compact separators."""
        from cybersage_portable.models import canonical_json_bytes
        report = minimal_valid_report()
        canon = canonical_json_bytes(report).decode("utf-8")
        # No spaces after colon or comma (compact separators)
        assert ": " not in canon
        assert ", " not in canon
        # Keys should be sorted: 'assessment_id' before 'checks_attempted'
        assert canon.index('"assessment_id"') < canon.index('"checks_attempted"')

    def test_same_content_same_checksum(self):
        """Same payload must produce identical checksum across calls."""
        report = minimal_valid_report(assessment_id="11111111-1111-4111-a111-111111111111")
        c1 = compute_checksum(report)
        c2 = compute_checksum(report)
        assert c1 == c2

    def test_checksum_is_sha256_hex(self):
        report = minimal_valid_report()
        assert len(report["checksum"]) == 64
        int(report["checksum"], 16)  # Must be valid hex


class TestJsonReport:
    def test_json_report_written(self):
        from unittest.mock import patch, MagicMock
        from cybersage_portable.models import AssessmentRun, CoverageStats, PostureScore, PrivacyMode
        from cybersage_portable.report import write_json_report

        run = AssessmentRun(
            assessment_id="22222222-2222-4222-a222-222222222222",
            scanner_version="1.0.0",
            privacy_mode=PrivacyMode.STANDARD,
            started_at="2026-08-03T10:00:00+00:00",
            completed_at="2026-08-03T10:01:00+00:00",
            host={"hostname": "test-host", "os_name": "Windows", "os_version": "10.0", "os_build": None, "architecture": "AMD64", "last_boot": None},
            privilege_level="standard",
            checks_attempted=0,
            coverage=CoverageStats(),
            posture_score=PostureScore(score=100, algorithm="posture_score_v1", components={}, caveat="Test caveat"),
            findings=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = write_json_report(run, Path(tmpdir))
            assert path.exists()
            content = json.loads(path.read_text(encoding="utf-8"))
            assert content["schema_version"] == "assessment.v1"
            assert content["assessment_id"] == run.assessment_id
            assert len(content["checksum"]) == 64
            assert verify_checksum(content)

    def test_json_report_checksum_valid(self):
        report = minimal_valid_report()
        assert verify_checksum(report)

    def test_schema_version_present(self):
        report = minimal_valid_report()
        assert report["schema_version"] == "assessment.v1"

    def test_score_algorithm_present(self):
        report = minimal_valid_report()
        assert report["score_algorithm"] == "posture_score_v1"

    def test_coverage_separate_from_score(self):
        """Coverage and posture score must be stored in separate fields."""
        report = minimal_valid_report()
        assert "coverage" in report
        assert "posture_score" in report
        assert "coverage_pct" in report["coverage"]
        assert "score" in report["posture_score"]

    def test_privacy_mode_recorded(self):
        report = minimal_valid_report()
        assert report["privacy_mode"] == "standard"


class TestHtmlReport:
    def test_html_report_written(self):
        from unittest.mock import patch
        from cybersage_portable.models import AssessmentRun, CoverageStats, PostureScore, PrivacyMode
        from cybersage_portable.report import write_html_report, serialise_run

        run = AssessmentRun(
            assessment_id="33333333-3333-4333-a333-333333333333",
            scanner_version="1.0.0",
            privacy_mode=PrivacyMode.REDACTED,
            started_at="2026-08-03T10:00:00+00:00",
            completed_at="2026-08-03T10:01:00+00:00",
            host={"hostname": "<HOST-redacted>", "os_name": "Windows", "os_version": "10.0", "os_build": None, "architecture": "AMD64", "last_boot": None},
            privilege_level="standard",
            checks_attempted=0,
            coverage=CoverageStats(),
            posture_score=PostureScore(score=90, algorithm="posture_score_v1", components={}, caveat="Test"),
            findings=[],
        )
        rd = serialise_run(run)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = write_html_report(run, Path(tmpdir), report_dict=rd)
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            assert "<script" not in content.lower(), "HTML must not contain script tags"
            assert "Content-Security-Policy" in content
            assert "http://" not in content  # No external resources
            assert "https://fonts." not in content
            # All injected values must be escaped
            assert "<HOST-redacted>" in content or "&lt;HOST-redacted&gt;" in content

    def test_html_no_external_resources(self):
        """HTML report must not reference external scripts, fonts, or analytics."""
        from cybersage_portable.models import AssessmentRun, CoverageStats, PostureScore, PrivacyMode
        from cybersage_portable.report import write_html_report, serialise_run

        run = AssessmentRun(
            assessment_id="44444444-4444-4444-a444-444444444444",
            scanner_version="1.0.0",
            privacy_mode=PrivacyMode.MINIMAL,
            started_at="2026-08-03T10:00:00+00:00",
            completed_at="2026-08-03T10:01:00+00:00",
            host={"hostname": "test", "os_name": "Windows", "os_version": "10.0", "os_build": None, "architecture": "AMD64", "last_boot": None},
            privilege_level="standard",
            checks_attempted=0,
            coverage=CoverageStats(),
            posture_score=PostureScore(score=100, algorithm="posture_score_v1", components={}, caveat="Test"),
            findings=[],
        )
        rd = serialise_run(run)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = write_html_report(run, Path(tmpdir), report_dict=rd)
            content = path.read_text(encoding="utf-8")
            for banned in ["googleapis.com", "cloudflare.com", "cdn.jsdelivr", "google-analytics", "gtm.js"]:
                assert banned not in content

    def test_xss_evidence_escaped(self):
        """Evidence values containing HTML must be escaped, not rendered."""
        from cybersage_portable.report import _e
        xss_val = '<script>alert("xss")</script>'
        escaped = _e(xss_val)
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped


class TestPostureScore:
    def test_posture_score_v1_computation(self):
        from cybersage_portable.models import PostureScore, Finding, FindingStatus, Severity, Confidence, Category
        findings = [
            Finding(
                check_id="SC-001", finding_id="SC-001:host", title="t",
                category=Category.SECURITY_CONTROLS, severity=Severity.CRITICAL,
                confidence=Confidence.HIGH, status=FindingStatus.FAIL,
                evidence={}, explanation="", remediation="",
                admin_required=False, may_disrupt=False, references=[],
                collected_at="2026-08-03T00:00:00+00:00", collector_version="1.0.0",
            ),
            Finding(
                check_id="SC-002", finding_id="SC-002:host", title="t",
                category=Category.SECURITY_CONTROLS, severity=Severity.HIGH,
                confidence=Confidence.HIGH, status=FindingStatus.FAIL,
                evidence={}, explanation="", remediation="",
                admin_required=False, may_disrupt=False, references=[],
                collected_at="2026-08-03T00:00:00+00:00", collector_version="1.0.0",
            ),
            Finding(
                check_id="OS-001", finding_id="OS-001:unavailable", title="t",
                category=Category.OPERATING_SYSTEM, severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH, status=FindingStatus.UNAVAILABLE,
                evidence={}, explanation="", remediation="",
                admin_required=False, may_disrupt=False, references=[],
                collected_at="2026-08-03T00:00:00+00:00", collector_version="1.0.0",
            ),
        ]
        score = PostureScore.compute(findings)
        # critical=1 → 25, high=1 → 10, total deduction = 35
        assert score.score == 65
        assert score.components["fail_critical"] == 1
        assert score.components["fail_high"] == 1
        assert score.components["total_deduction"] == 35

    def test_unavailable_does_not_reduce_score(self):
        """UNAVAILABLE/PERMISSION_REQUIRED/ERROR findings must not reduce score."""
        from cybersage_portable.models import PostureScore, Finding, FindingStatus, Severity, Confidence, Category
        findings = [
            Finding(
                check_id="SC-001", finding_id="SC-001:permission_required", title="t",
                category=Category.SECURITY_CONTROLS, severity=Severity.HIGH,
                confidence=Confidence.HIGH, status=FindingStatus.PERMISSION_REQUIRED,
                evidence={}, explanation="", remediation="",
                admin_required=True, may_disrupt=False, references=[],
                collected_at="2026-08-03T00:00:00+00:00", collector_version="1.0.0",
            ),
        ]
        score = PostureScore.compute(findings)
        assert score.score == 100  # permission_required does not deduct

    def test_caveat_always_present(self):
        from cybersage_portable.models import PostureScore
        score = PostureScore.compute([])
        assert len(score.caveat) > 0
        assert "100%" not in score.caveat.lower() or "not" in score.caveat.lower()
