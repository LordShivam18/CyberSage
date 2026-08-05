"""
Tests for portable/ci/verify_smoke_report.py and shared/report_contract.validate_report.

Loaded via importlib.util so portable/ci/ does not need to be a Python package.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Load the CLI script as a module without adding sys.path mutations.
# ---------------------------------------------------------------------------
_CI_SCRIPT = Path(__file__).parent.parent / "ci" / "verify_smoke_report.py"


def _load_verifier() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("verify_smoke_report", _CI_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


from shared.report_contract import (
    compute_checksum,
    validate_report,
    verify_checksum,
)


# ---------------------------------------------------------------------------
# Canonical valid fixture matching the full contract schema
# ---------------------------------------------------------------------------

def _make_valid_report() -> dict:
    report = {
        "assessment_id": "a" * 36,
        "scanner_version": "1.0.0",
        "schema_version": "assessment.v1",
        "score_algorithm": "posture_score_v1",
        "privacy_mode": "minimal",
        "privilege_level": "standard",
        "started_at": "2023-01-01T00:00:00Z",
        "completed_at": "2023-01-01T00:00:01Z",
        "host": {
            "hostname": "test-pc",
            "os_name": "Windows",
            "os_version": "10",
            "os_build": "19045",
            "architecture": "64-bit",
        },
        "checks_attempted": 0,
        "coverage": {
            "coverage_pct": 100.0,
            "attempted": 0,
            "passed": 0,
            "failed": 0,
            "warned": 0,
            "unavailable": 0,
            "permission_required": 0,
            "errors": 0,
        },
        "posture_score": {
            "score": 100,
            "algorithm": "posture_score_v1",
            "components": {},
            "caveat": "test caveat",
        },
        "findings": [],
        "checksum_algorithm": "sha256",
        "checksum": "",  # filled below
    }
    report["checksum"] = compute_checksum(report)
    return report


# ===========================================================================
# Tests for shared.report_contract.validate_report
# ===========================================================================

class TestValidateReport:
    def test_valid_canonical_report_passes(self):
        assert validate_report(_make_valid_report()) is True

    def test_valid_checksum_passes(self):
        report = _make_valid_report()
        assert verify_checksum(report) is True

    def test_altered_checksum_fails(self):
        report = _make_valid_report()
        report["checksum"] = "a" * 64
        assert verify_checksum(report) is False

    def test_missing_required_field_fails(self):
        report = _make_valid_report()
        del report["assessment_id"]
        assert validate_report(report) is False

    def test_unknown_field_fails(self):
        report = _make_valid_report()
        report["totally_unknown"] = "bad"
        assert validate_report(report) is False

    def test_unsupported_schema_version_fails(self):
        report = _make_valid_report()
        report["schema_version"] = "assessment.v99"
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_malformed_coverage_missing_field_fails(self):
        report = _make_valid_report()
        del report["coverage"]["passed"]
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_malformed_coverage_negative_count_fails(self):
        report = _make_valid_report()
        report["coverage"]["failed"] = -1
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_coverage_pct_out_of_range_fails(self):
        report = _make_valid_report()
        report["coverage"]["coverage_pct"] = 150.0
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_malformed_posture_score_missing_field_fails(self):
        report = _make_valid_report()
        del report["posture_score"]["algorithm"]
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_posture_score_out_of_range_fails(self):
        report = _make_valid_report()
        report["posture_score"]["score"] = 200
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_invalid_finding_status_fails(self):
        report = _make_valid_report()
        report["findings"] = [{
            "check_id": "OS-001",
            "finding_id": "OS-001:host",
            "title": "Test",
            "category": "operating_system",
            "severity": "high",
            "confidence": "high",
            "status": "invalid_status",
        }]
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_invalid_severity_fails(self):
        report = _make_valid_report()
        report["findings"] = [{
            "check_id": "OS-001",
            "finding_id": "OS-001:host",
            "title": "Test",
            "category": "operating_system",
            "severity": "catastrophic",
            "confidence": "high",
            "status": "fail",
        }]
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_nan_in_posture_score_fails(self):
        report = _make_valid_report()
        report["posture_score"]["score"] = float("nan")
        # NaN in dict — update checksum for structural path
        assert validate_report(report) is False

    def test_infinity_in_coverage_pct_fails(self):
        report = _make_valid_report()
        report["coverage"]["coverage_pct"] = float("inf")
        assert validate_report(report) is False

    def test_excessive_evidence_depth_fails(self):
        # Build a deeply nested dict that exceeds MAX_EVIDENCE_DEPTH (4)
        nested: dict = {"v": 1}
        for _ in range(6):
            nested = {"child": nested}

        report = _make_valid_report()
        report["findings"] = [{
            "check_id": "OS-001",
            "finding_id": "OS-001:host",
            "title": "Test",
            "category": "operating_system",
            "severity": "high",
            "confidence": "high",
            "status": "fail",
            "evidence": nested,
        }]
        report["checksum"] = compute_checksum(report)
        assert validate_report(report) is False

    def test_prohibited_password_key_is_not_a_schema_failure(self):
        # validate_report is structural-only; prohibited key inspection is in the verifier.
        # A report with a key called 'password' in findings evidence is still structurally valid
        # as long as evidence depth / key rules pass.
        report = _make_valid_report()
        report["findings"] = [{
            "check_id": "OS-001",
            "finding_id": "OS-001:host",
            "title": "Test",
            "category": "operating_system",
            "severity": "high",
            "confidence": "high",
            "status": "pass",
            "evidence": {"password_field": "redacted"},
        }]
        report["checksum"] = compute_checksum(report)
        # Structural validation passes; secret detection is a separate CI step
        assert validate_report(report) is True


# ===========================================================================
# Tests for the CI verifier script
# ===========================================================================

class TestVerifierScript:
    def test_verifier_accepts_valid_report(self, tmp_path):
        verifier = _load_verifier()
        report = _make_valid_report()
        report_path = tmp_path / "assessment_test.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")

        with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
            with pytest.raises(SystemExit) as exc:
                verifier.main()
        assert exc.value.code == 0

    def test_verifier_rejects_tampered_checksum(self, tmp_path):
        verifier = _load_verifier()
        report = _make_valid_report()
        report["checksum"] = "b" * 64  # wrong checksum
        report_path = tmp_path / "assessment_tampered.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")

        with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
            with pytest.raises(SystemExit) as exc:
                verifier.main()
        assert exc.value.code == 1

    def test_verifier_rejects_malformed_report(self, tmp_path):
        verifier = _load_verifier()
        bad = {"random": "data"}
        report_path = tmp_path / "assessment_bad.json"
        report_path.write_text(json.dumps(bad), encoding="utf-8")

        with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
            with pytest.raises(SystemExit) as exc:
                verifier.main()
        assert exc.value.code == 1

    def test_verifier_rejects_prohibited_structured_key(self, tmp_path):
        verifier = _load_verifier()
        report = _make_valid_report()
        # Inject a prohibited key into findings evidence
        report["findings"] = [{
            "check_id": "OS-001",
            "finding_id": "OS-001:host",
            "title": "Test",
            "category": "os",
            "severity": "high",
            "confidence": "high",
            "status": "pass",
            "evidence": {"PasswordValue": "exposed"},
        }]
        report["checksum"] = compute_checksum(report)
        report_path = tmp_path / "assessment_secret.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")

        with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
            with pytest.raises(SystemExit) as exc:
                verifier.main()
        assert exc.value.code == 1

    def test_verifier_rejects_cookie_key(self, tmp_path):
        verifier = _load_verifier()
        report = _make_valid_report()
        report["findings"] = [{
            "check_id": "OS-001",
            "finding_id": "OS-001:host",
            "title": "Test",
            "category": "os",
            "severity": "high",
            "confidence": "high",
            "status": "pass",
            "evidence": {"SessionCookie": "secret-value"},
        }]
        report["checksum"] = compute_checksum(report)
        report_path = tmp_path / "assessment_cookie.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")

        with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
            with pytest.raises(SystemExit) as exc:
                verifier.main()
        assert exc.value.code == 1

    def test_verifier_missing_path_argument_fails(self):
        verifier = _load_verifier()
        with mock.patch("sys.argv", ["verify_smoke_report.py"]):
            with pytest.raises(SystemExit) as exc:
                verifier.main()
        assert exc.value.code == 1


# ===========================================================================
# Workflow regression assertions (no local execution)
# ===========================================================================

def test_workflow_does_not_contain_sys_path_insert():
    workflow = Path(__file__).parent.parent.parent / ".github" / "workflows" / "portable-build.yml"
    content = workflow.read_text(encoding="utf-8")
    assert "sys.path.insert" not in content

def test_workflow_does_not_reference_requirements_txt():
    workflow = Path(__file__).parent.parent.parent / ".github" / "workflows" / "portable-build.yml"
    content = workflow.read_text(encoding="utf-8")
    assert "portable/requirements.txt" not in content

def test_workflow_executes_verifier_from_repository_root():
    workflow = Path(__file__).parent.parent.parent / ".github" / "workflows" / "portable-build.yml"
    content = workflow.read_text(encoding="utf-8")
    assert "python portable/ci/verify_smoke_report.py" in content

def test_workflow_cleanup_runs_always():
    workflow = Path(__file__).parent.parent.parent / ".github" / "workflows" / "portable-build.yml"
    content = workflow.read_text(encoding="utf-8")
    assert "if: always()" in content

def test_pyproject_uses_correct_build_backend():
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    content = pyproject.read_text(encoding="utf-8")
    assert "setuptools.build_meta" in content
    assert "setuptools.backends.legacy" not in content
