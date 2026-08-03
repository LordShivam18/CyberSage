"""
Differential assessment comparison.

Compare two assessment JSON reports and produce:
  * New findings (in new report but not in old)
  * Resolved findings (in old report but not in new)
  * Severity changes (same finding_id, different severity)
  * Security-control state changes
  * Newly exposed listening ports
  * New persistence entries

Identity rules
--------------
* Findings are matched by ``finding_id`` across reports.
* ``finding_id`` is stable and entity-based (never PID-based).
* Process finding identity MUST NOT be compared by PID.
"""

from __future__ import annotations

from typing import Any


def _index_findings(report: dict) -> dict[str, dict]:
    """Return {finding_id: finding} for all findings in a report."""
    return {f["finding_id"]: f for f in (report.get("findings") or []) if f.get("finding_id")}


def _finding_summary(f: dict) -> dict:
    return {
        "finding_id": f.get("finding_id"),
        "check_id": f.get("check_id"),
        "title": f.get("title"),
        "category": f.get("category"),
        "severity": f.get("severity"),
        "status": f.get("status"),
    }


def compare_reports(old_report: dict, new_report: dict) -> dict[str, Any]:
    """
    Compare two report dicts and return a structured differential.

    Parameters
    ----------
    old_report:
        Previously collected assessment report dict.
    new_report:
        More-recent assessment report dict.

    Returns
    -------
    Differential dict suitable for serialisation.
    """
    old_idx = _index_findings(old_report)
    new_idx = _index_findings(new_report)

    old_ids = set(old_idx.keys())
    new_ids = set(new_idx.keys())

    # New findings
    new_findings = [_finding_summary(new_idx[fid]) for fid in sorted(new_ids - old_ids)]

    # Resolved findings
    resolved_findings = [_finding_summary(old_idx[fid]) for fid in sorted(old_ids - new_ids)]

    # Severity changes (same finding_id present in both)
    severity_changes = []
    status_changes = []
    for fid in sorted(old_ids & new_ids):
        old_f = old_idx[fid]
        new_f = new_idx[fid]
        if old_f.get("severity") != new_f.get("severity"):
            severity_changes.append({
                "finding_id": fid,
                "check_id": new_f.get("check_id"),
                "title": new_f.get("title"),
                "old_severity": old_f.get("severity"),
                "new_severity": new_f.get("severity"),
            })
        if old_f.get("status") != new_f.get("status"):
            status_changes.append({
                "finding_id": fid,
                "check_id": new_f.get("check_id"),
                "title": new_f.get("title"),
                "old_status": old_f.get("status"),
                "new_status": new_f.get("status"),
            })

    # Newly exposed ports (NET-001 findings)
    old_ports = {fid for fid in old_ids if fid.startswith("NET-001:tcp:")}
    new_ports = {fid for fid in new_ids if fid.startswith("NET-001:tcp:")}
    new_exposed_ports = [
        _finding_summary(new_idx[fid]) for fid in sorted(new_ports - old_ports)
    ]

    # New persistence entries
    old_persist = {fid for fid in old_ids if any(fid.startswith(p) for p in ("PERS-001:", "PERS-002:", "PERS-003:"))}
    new_persist = {fid for fid in new_ids if any(fid.startswith(p) for p in ("PERS-001:", "PERS-002:", "PERS-003:"))}
    new_persistence = [
        _finding_summary(new_idx[fid]) for fid in sorted(new_persist - old_persist)
    ]

    # Security control changes (SC-* checks)
    sc_changes = [c for c in status_changes if c.get("check_id", "").startswith("SC-")]

    # Score delta
    old_score = (old_report.get("posture_score") or {}).get("score")
    new_score = (new_report.get("posture_score") or {}).get("score")

    return {
        "old_assessment_id": old_report.get("assessment_id"),
        "new_assessment_id": new_report.get("assessment_id"),
        "old_completed_at": old_report.get("completed_at"),
        "new_completed_at": new_report.get("completed_at"),
        "posture_score_delta": {
            "old_score": old_score,
            "new_score": new_score,
            "delta": (new_score - old_score) if (new_score is not None and old_score is not None) else None,
        },
        "summary": {
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "severity_changes": len(severity_changes),
            "status_changes": len(status_changes),
            "new_exposed_ports": len(new_exposed_ports),
            "new_persistence_entries": len(new_persistence),
            "security_control_changes": len(sc_changes),
        },
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "severity_changes": severity_changes,
        "status_changes": status_changes,
        "new_exposed_ports": new_exposed_ports,
        "new_persistence_entries": new_persistence,
        "security_control_changes": sc_changes,
        "note": (
            "Identity is based on finding_id (stable entity key). "
            "Process findings are matched by executable path, not PID."
        ),
    }
