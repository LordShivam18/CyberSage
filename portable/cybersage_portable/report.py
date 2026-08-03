"""
Report generation: JSON, HTML (no external resources), and terminal summary.

Safety rules
------------
* Every collected value written to HTML is escaped via html.escape().
* No dangerouslySetInnerHTML or equivalent.
* No external scripts, fonts, stylesheets, analytics, or network resources.
* Evidence fields are NOT rendered as clickable URLs or file:// links.
* A Content-Security-Policy meta tag is included in all HTML reports.
* The SHA-256 checksum is computed over the canonical JSON payload
  (sorted keys, compact separators, checksum field excluded, UTF-8).

Checksum note
-------------
A checksum detects modification.
It does not prove who produced the report or executable.
Reports and portable builds are unsigned/self-asserted until a future code-signing and key-management design exists.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, DISCLAIMER
from .models import AssessmentRun, FindingStatus, Severity, compute_checksum


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------


def _run_to_dict(run: AssessmentRun) -> dict[str, Any]:
    """Convert AssessmentRun to a dict matching the canonical JSON schema."""
    return {
        "schema_version": run.schema_version,
        "assessment_id": run.assessment_id,
        "scanner_version": run.scanner_version,
        "score_algorithm": run.posture_score.algorithm,
        "privacy_mode": run.privacy_mode.value,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "host": run.host,
        "privilege_level": run.privilege_level,
        "checks_attempted": run.checks_attempted,
        "coverage": run.coverage.to_dict(),
        "posture_score": run.posture_score.to_dict(),
        "findings": [f.to_dict() for f in run.findings],
        "checksum_algorithm": run.checksum_algorithm,
        "checksum": "",  # placeholder — replaced below
    }


def serialise_run(run: AssessmentRun) -> dict[str, Any]:
    """Produce the final report dict with computed checksum."""
    d = _run_to_dict(run)
    d["checksum"] = compute_checksum(d)
    return d


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------


def write_json_report(run: AssessmentRun, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_dict = serialise_run(run)
    filename = f"assessment_{run.assessment_id[:8]}_{_timestamp_slug()}.json"
    path = output_dir / filename
    with path.open("w", encoding="utf-8") as fh:
        json.dump(report_dict, fh, indent=2, ensure_ascii=True, sort_keys=True)
    return path


# ---------------------------------------------------------------------------
# HTML report — no external resources, all values escaped
# ---------------------------------------------------------------------------


_SEVERITY_COLORS = {
    "critical": "#d32f2f",
    "high": "#f57c00",
    "medium": "#fbc02d",
    "low": "#388e3c",
    "informational": "#0288d1",
}

_STATUS_ICONS = {
    "pass": "✅",
    "fail": "❌",
    "warning": "⚠️",
    "informational": "ℹ️",
    "unavailable": "➖",
    "permission_required": "🔒",
    "error": "⚡",
}

_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "script-src 'none'; "
    "img-src data: 'self'; "
    "connect-src 'none'; "
    "font-src 'none'; "
    "frame-src 'none';"
)


def _e(value: Any) -> str:
    """Escape a value for safe HTML inclusion."""
    return html.escape(str(value) if value is not None else "", quote=True)


def _severity_badge(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity.lower(), "#757575")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.75em;font-weight:bold">'
        f'{_e(severity.upper())}</span>'
    )


def _evidence_table(evidence: dict) -> str:
    if not evidence:
        return "<em>No evidence recorded.</em>"
    rows = "".join(
        f"<tr><td style='padding:3px 8px;font-weight:bold;white-space:nowrap'>{_e(k)}</td>"
        f"<td style='padding:3px 8px;font-family:monospace;word-break:break-all'>{_e(v)}</td></tr>"
        for k, v in evidence.items()
    )
    return f"<table style='border-collapse:collapse;font-size:0.85em'>{rows}</table>"


def _build_html(report_dict: dict[str, Any]) -> str:
    host = report_dict.get("host") or {}
    posture = report_dict.get("posture_score") or {}
    coverage = report_dict.get("coverage") or {}
    findings = report_dict.get("findings") or []

    fail_count = sum(1 for f in findings if f.get("status") == "fail")
    warn_count = sum(1 for f in findings if f.get("status") == "warning")

    score = posture.get("score", "N/A")
    caveat = _e(posture.get("caveat", ""))

    # Group findings by category
    by_category: dict[str, list] = {}
    for f in findings:
        cat = f.get("category", "other")
        by_category.setdefault(cat, []).append(f)

    findings_html = ""
    for cat, cat_findings in sorted(by_category.items()):
        rows = ""
        for f in sorted(cat_findings, key=lambda x: (
            ["critical", "high", "medium", "low", "informational"].index(x.get("severity", "informational"))
            if x.get("severity") in ["critical", "high", "medium", "low", "informational"] else 99
        )):
            icon = _STATUS_ICONS.get(f.get("status", ""), "")
            rows += (
                f"<tr style='border-bottom:1px solid #eee'>"
                f"<td style='padding:6px'>{icon} {_e(f.get('status', ''))}</td>"
                f"<td style='padding:6px'>{_severity_badge(f.get('severity', ''))}</td>"
                f"<td style='padding:6px'><strong>{_e(f.get('title', ''))}</strong><br>"
                f"<small style='color:#555'>{_e(f.get('check_id', ''))}</small></td>"
                f"<td style='padding:6px;font-size:0.85em'>{_e(f.get('explanation', ''))}</td>"
                f"<td style='padding:6px;font-size:0.85em'>{_e(f.get('remediation', ''))}</td>"
                f"<td style='padding:6px'>{_evidence_table(f.get('evidence') or {})}</td>"
                f"<td style='padding:6px;text-align:center'>{'🔒' if f.get('admin_required') else ''}</td>"
                f"</tr>"
            )
        findings_html += (
            f"<h3 style='margin-top:1.5em;text-transform:capitalize'>"
            f"{_e(cat.replace('_', ' '))}</h3>"
            f"<table style='width:100%;border-collapse:collapse;font-size:0.9em'>"
            f"<thead><tr style='background:#f5f5f5'>"
            f"<th style='padding:6px;text-align:left'>Status</th>"
            f"<th style='padding:6px;text-align:left'>Severity</th>"
            f"<th style='padding:6px;text-align:left'>Finding</th>"
            f"<th style='padding:6px;text-align:left'>Explanation</th>"
            f"<th style='padding:6px;text-align:left'>Remediation</th>"
            f"<th style='padding:6px;text-align:left'>Evidence</th>"
            f"<th style='padding:6px;text-align:center'>🔒 Admin</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="{_CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberSage Portable Assessment — {_e(host.get('hostname', 'Unknown'))}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:0;padding:20px;background:#fafafa;color:#212121}}
h1{{color:#1565c0}}h2{{color:#283593;margin-top:1.5em}}
.meta{{background:#fff;border:1px solid #e0e0e0;border-radius:6px;padding:16px;margin-bottom:16px}}
.score{{font-size:3em;font-weight:bold;color:#1565c0;display:inline-block}}
.caveat{{background:#fff3e0;border-left:4px solid #f57c00;padding:8px 12px;margin:12px 0;font-size:0.85em}}
.disclaimer{{background:#e3f2fd;border-left:4px solid #1565c0;padding:8px 12px;margin:12px 0;font-size:0.8em}}
table{{font-size:0.9em}}
</style>
</head>
<body>
<h1>CyberSage Portable Security Assessment</h1>
<div class="disclaimer">{_e(DISCLAIMER)}</div>

<div class="meta">
<strong>Host:</strong> {_e(host.get('hostname', 'Unknown'))} &nbsp;|&nbsp;
<strong>OS:</strong> {_e(host.get('os_name', ''))} {_e(host.get('os_version', ''))} &nbsp;|&nbsp;
<strong>Arch:</strong> {_e(host.get('architecture', ''))} &nbsp;|&nbsp;
<strong>Privileges:</strong> {_e(report_dict.get('privilege_level', ''))} &nbsp;|&nbsp;
<strong>Privacy mode:</strong> {_e(report_dict.get('privacy_mode', ''))}
</div>

<div class="meta">
<strong>Assessment ID:</strong> {_e(report_dict.get('assessment_id', ''))} &nbsp;|&nbsp;
<strong>Scanner:</strong> {_e(report_dict.get('scanner_version', ''))} &nbsp;|&nbsp;
<strong>Started:</strong> {_e(report_dict.get('started_at', ''))} &nbsp;|&nbsp;
<strong>Completed:</strong> {_e(report_dict.get('completed_at', ''))}
</div>

<h2>Posture Score</h2>
<div class="meta">
<span class="score">{_e(score)}</span><span style="font-size:1.5em">/100</span>
<div class="caveat">{caveat}</div>
<strong>Coverage:</strong> {_e(coverage.get('coverage_pct', 0))}% of checks produced definitive results
({_e(coverage.get('unavailable', 0))} unavailable,
{_e(coverage.get('permission_required', 0))} permission required,
{_e(coverage.get('errors', 0))} errors — these reduce coverage, not score)
<br><strong>Fail:</strong> {fail_count} &nbsp;|&nbsp; <strong>Warning:</strong> {warn_count}
</div>

<h2>Findings</h2>
{findings_html}

<hr>
<small style="color:#757575">
Report checksum (SHA-256, integrity only — detects modification, unsigned/self-asserted): {_e(report_dict.get('checksum', ''))}
<br>Generated by CyberSage Portable Assessment v{_e(__version__)} | {_e(report_dict.get('completed_at', ''))}
</small>
</body>
</html>"""


def write_html_report(run: AssessmentRun, output_dir: Path, report_dict: dict | None = None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    if report_dict is None:
        report_dict = serialise_run(run)
    html_content = _build_html(report_dict)
    filename = f"assessment_{run.assessment_id[:8]}_{_timestamp_slug()}.html"
    path = output_dir / filename
    with path.open("w", encoding="utf-8") as fh:
        fh.write(html_content)
    return path


# ---------------------------------------------------------------------------
# Terminal summary
# ---------------------------------------------------------------------------


def print_terminal_summary(run: AssessmentRun, report_dict: dict | None = None) -> None:
    if report_dict is None:
        report_dict = serialise_run(run)

    findings = report_dict.get("findings") or []
    posture = report_dict.get("posture_score") or {}
    coverage = report_dict.get("coverage") or {}
    host = report_dict.get("host") or {}

    fail_count = sum(1 for f in findings if f.get("status") == "fail")
    warn_count = sum(1 for f in findings if f.get("status") == "warning")
    perm_count = sum(1 for f in findings if f.get("status") == "permission_required")
    unavail_count = sum(1 for f in findings if f.get("status") == "unavailable")

    SEP = "=" * 72
    print(f"\n{SEP}")
    print("  CyberSage Portable Security Assessment")
    print(SEP)
    print(f"  Host     : {host.get('hostname', 'Unknown')}")
    print(f"  OS       : {host.get('os_name', '')} {host.get('os_version', '')}")
    print(f"  Privileges: {run.privilege_level}")
    print(f"  Privacy   : {run.privacy_mode.value}")
    print(f"  Score    : {posture.get('score', 'N/A')}/100  (see caveat below)")
    print(f"  Coverage : {coverage.get('coverage_pct', 0)}%")
    print(SEP)
    print(f"  Findings: {len(findings)} total | {fail_count} fail | {warn_count} warning | {perm_count} permission-required | {unavail_count} unavailable")
    print()

    # Top fails
    fails = [f for f in findings if f.get("status") == "fail"]
    if fails:
        print("  FAILURES:")
        for f in fails[:20]:
            print(f"    [{f.get('severity', '?').upper():12}] {f.get('check_id', '?')} — {f.get('title', '')}")
    else:
        print("  No failures detected in this scan.")

    # Permission-required
    if perm_count:
        print(f"\n  {perm_count} check(s) require administrator privileges — run as admin for complete results.")

    print(f"\n  CAVEAT: {posture.get('caveat', '')}")
    print(f"\n  Assessment ID: {run.assessment_id}")
    print(f"  Checksum  (SHA-256, integrity only - unsigned/self-asserted): {report_dict.get('checksum', '')}")
    print(SEP)
    print(f"  {DISCLAIMER}")
    print(f"{SEP}\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _timestamp_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
