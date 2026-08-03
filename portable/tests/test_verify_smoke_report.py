import os
import pytest
import json
import subprocess
from unittest import mock
import portable.ci.verify_smoke_report as verifier

def test_verifier_accepts_valid_report(tmp_path):
    report_path = tmp_path / "valid_report.json"
    valid_data = {
        "assessment_id": "test-id",
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
            "architecture": "64-bit"
        },
        "checks_attempted": 0,
        "coverage": {
            "coverage_pct": 100.0,
            "attempted": 0,
            "failed": 0,
            "unavailable": 0,
            "permission_required": 0,
            "errors": 0
        },
        "posture_score": {
            "score": 100,
            "components": {},
            "caveat": ""
        },
        "findings": [],
        "checksum_algorithm": "sha256",
        "checksum": ""
    }
    # Create valid checksum
    from shared.report_contract import _canonical_json
    import hashlib
    digest = hashlib.sha256(_canonical_json(valid_data).encode("utf-8")).hexdigest()
    valid_data["checksum"] = digest
    
    report_path.write_text(json.dumps(valid_data))
    
    with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
        with pytest.raises(SystemExit) as e:
            verifier.main()
        assert e.value.code == 0

def test_verifier_rejects_checksum_tampering(tmp_path):
    report_path = tmp_path / "invalid_checksum.json"
    invalid_data = {
        "assessment_id": "test-id",
        "scanner_version": "1.0.0",
        "schema_version": "assessment.v1",
        "checksum_algorithm": "sha256",
        "checksum": "badchecksum"
    }
    report_path.write_text(json.dumps(invalid_data))
    
    with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
        with mock.patch("portable.ci.verify_smoke_report.validate_report", return_value=True):
            with pytest.raises(SystemExit) as e:
                verifier.main()
            assert e.value.code == 1

def test_verifier_rejects_malformed_schema(tmp_path):
    report_path = tmp_path / "invalid_schema.json"
    invalid_data = {"random": "data"}
    report_path.write_text(json.dumps(invalid_data))
    
    with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
        with pytest.raises(SystemExit) as e:
            verifier.main()
        assert e.value.code == 1

def test_verifier_rejects_prohibited_structured_keys(tmp_path):
    report_path = tmp_path / "prohibited_keys.json"
    invalid_data = {"field1": {"MyPasswordKey": "secret"}}
    report_path.write_text(json.dumps(invalid_data))
    
    with mock.patch("sys.argv", ["verify_smoke_report.py", str(report_path)]):
        # Patching validation and checksum so we can reach the secrets check
        with mock.patch("portable.ci.verify_smoke_report.validate_report", return_value=True):
            with mock.patch("portable.ci.verify_smoke_report.verify_checksum", return_value=True):
                with pytest.raises(SystemExit) as e:
                    verifier.main()
                assert e.value.code == 1

def test_workflow_packaging_assertions():
    workflow_path = os.path.join(os.path.dirname(__file__), "..", "..", ".github", "workflows", "portable-build.yml")
    with open(workflow_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "sys.path.insert" not in content, "Workflow must not contain sys.path.insert"
    assert "portable/requirements.txt" not in content, "Workflow must not reference portable/requirements.txt"
    assert "python portable/ci/verify_smoke_report.py" in content, "Workflow must execute verifier from repository root"
    assert "if: always()" in content, "Cleanup must run with if: always()"
