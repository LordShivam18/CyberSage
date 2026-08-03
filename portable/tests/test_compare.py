"""Tests for differential comparison of assessment reports."""

from __future__ import annotations

from .conftest import minimal_valid_report
from cybersage_portable.compare import compare_reports


def _make_report_with_finding(assessment_id: str, finding_id: str, status: str, severity: str) -> dict:
    report = minimal_valid_report(assessment_id)
    report["findings"] = [
        {
            "check_id": finding_id.split(":")[0],
            "finding_id": finding_id,
            "title": f"Test finding {finding_id}",
            "category": "network",
            "severity": severity,
            "confidence": "high",
            "status": status,
            "evidence": {"port": 445},
            "explanation": "test",
            "remediation": "test",
            "device_impact": "",
            "admin_required": False,
            "may_disrupt": False,
            "references": [],
            "collected_at": "2026-08-03T00:00:00+00:00",
            "collector_version": "1.0.0",
        }
    ]
    from cybersage_portable.models import compute_checksum
    report["checksum"] = compute_checksum(report)
    return report


class TestCompareReports:
    def test_new_finding_detected(self):
        old = minimal_valid_report("aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
        new = _make_report_with_finding(
            "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
            "NET-001:tcp:445", "warning", "medium"
        )
        diff = compare_reports(old, new)
        assert diff["summary"]["new_findings"] == 1
        assert diff["new_findings"][0]["finding_id"] == "NET-001:tcp:445"

    def test_resolved_finding_detected(self):
        old = _make_report_with_finding(
            "cccccccc-cccc-4ccc-cccc-cccccccccccc",
            "SC-001:host", "fail", "high"
        )
        new = minimal_valid_report("dddddddd-dddd-4ddd-dddd-dddddddddddd")
        diff = compare_reports(old, new)
        assert diff["summary"]["resolved_findings"] == 1
        assert diff["resolved_findings"][0]["finding_id"] == "SC-001:host"

    def test_severity_change_detected(self):
        old = _make_report_with_finding(
            "eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee",
            "SC-002:public", "fail", "medium"
        )
        new = _make_report_with_finding(
            "ffffffff-ffff-4fff-ffff-ffffffffffff",
            "SC-002:public", "fail", "high"
        )
        diff = compare_reports(old, new)
        assert diff["summary"]["severity_changes"] == 1
        assert diff["severity_changes"][0]["old_severity"] == "medium"
        assert diff["severity_changes"][0]["new_severity"] == "high"

    def test_posture_score_delta(self):
        old = minimal_valid_report("11111111-1111-4111-b111-111111111111")
        old["posture_score"]["score"] = 80
        new = minimal_valid_report("22222222-2222-4222-b222-222222222222")
        new["posture_score"]["score"] = 95
        diff = compare_reports(old, new)
        assert diff["posture_score_delta"]["delta"] == 15

    def test_new_exposed_port_detected(self):
        old = minimal_valid_report("33333333-3333-4333-b333-333333333333")
        new = _make_report_with_finding(
            "44444444-4444-4444-b444-444444444444",
            "NET-001:tcp:5985", "warning", "medium"
        )
        diff = compare_reports(old, new)
        assert diff["summary"]["new_exposed_ports"] == 1

    def test_identity_note_present(self):
        """Differential must document that identity is path-based, not PID-based."""
        diff = compare_reports(minimal_valid_report(), minimal_valid_report())
        assert "pid" in diff.get("note", "").lower() or "path" in diff.get("note", "").lower()
