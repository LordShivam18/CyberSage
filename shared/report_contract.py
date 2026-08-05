"""
Shared report contract for CyberSage Portable Assessment.

This module contains the canonical JSON serialization, checksum calculation,
report schema constants, supported schema versions, score algorithm, penalty table,
and coverage calculation. It has no dependencies on FastAPI, SQLAlchemy, Windows APIs,
or other external systems. Both the scanner and the backend use this module.
"""

import hashlib
import json
from typing import Any, Dict, List

SUPPORTED_SCHEMA_VERSIONS = {"assessment.v1"}
SUPPORTED_CHECKSUM_ALGORITHMS = {"sha256"}
MAX_REPORT_SIZE_BYTES = 2 * 1024 * 1024  # 2MB
MAX_FINDINGS = 1000

# Constants for lengths
MAX_ASSESSMENT_ID_LEN = 128
MAX_FINDING_ID_LEN = 256
MAX_CHECK_ID_LEN = 128
MAX_LABEL_LEN = 256
MAX_TITLE_LEN = 256
MAX_EXPLANATION_LEN = 2048
MAX_REMEDIATION_LEN = 2048
MAX_EVIDENCE_KEYS = 50
MAX_EVIDENCE_KEY_LEN = 128
MAX_EVIDENCE_VAL_LEN = 4096

_SCORE_V1_WEIGHTS: Dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
}

_SCORE_CAVEAT = (
    "Posture score is a prioritization aid only.  It does not represent a "
    "complete security assessment.  Checks that could not run (unavailable, "
    "permission_required, error) are excluded from the score.  A high score "
    "does not mean the device is fully secure."
)


def canonical_json_bytes(report_dict: dict) -> bytes:
    """
    Produce canonical UTF-8 JSON for SHA-256 checksum computation.

    Rules:
    * The ``checksum`` field is excluded from the hashed payload.
    * Keys are sorted (``sort_keys=True``).
    * Compact separators: ``(',', ':')``.
    * Encoded as UTF-8.
    """
    payload = {k: v for k, v in report_dict.items() if k != "checksum"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_checksum(report_dict: dict) -> str:
    """Return the SHA-256 hex digest of the canonical JSON payload."""
    return hashlib.sha256(canonical_json_bytes(report_dict)).hexdigest()


def verify_checksum(report_dict: dict) -> bool:
    """Return True if the checksum field matches the recomputed canonical digest."""
    stored = report_dict.get("checksum", "")
    return stored == compute_checksum(report_dict)


def compute_coverage(attempted: int, unavailable: int, permission_required: int, errors: int) -> float:
    """Compute coverage percentage."""
    effective = attempted - unavailable - permission_required - errors
    if attempted <= 0:
        return 0.0
    return round(max(0.0, effective / attempted * 100), 1)


def compute_posture_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recompute posture_score_v1 from a list of raw finding dicts.
    Only `status=fail` findings contribute to the deduction.
    Repeated findings are capped naturally by the fact that `finding_id` is distinct.
    """
    counts: Dict[str, int] = {s: 0 for s in _SCORE_V1_WEIGHTS}
    
    for f in findings:
        status = f.get("status", "")
        severity = f.get("severity", "")
        if status == "fail" and severity in counts:
            counts[severity] += 1

    deductions = {
        f"deduction_{sev}": counts[sev] * weight
        for sev, weight in _SCORE_V1_WEIGHTS.items()
    }
    total_deduction = sum(deductions.values())
    score = max(0, 100 - total_deduction)

    components = {f"fail_{sev}": counts[sev] for sev in _SCORE_V1_WEIGHTS}
    components.update(deductions)
    components["total_deduction"] = total_deduction

    return {
        "score": score,
        "algorithm": "posture_score_v1",
        "components": components,
        "caveat": _SCORE_CAVEAT,
    }


# ---------------------------------------------------------------------------
# Structural report validation
# ---------------------------------------------------------------------------

_ALLOWED_CATEGORIES = {
    "operating_system", "security_controls", "accounts", "processes",
    "persistence", "network", "browser", "certificates", "other",
}
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_ALLOWED_CONFIDENCES = {"high", "medium", "low"}
_ALLOWED_STATUSES = {
    "pass", "fail", "warning", "unavailable",
    "permission_required", "informational", "error",
}
_REQUIRED_TOP_LEVEL = {
    "assessment_id", "scanner_version", "schema_version", "score_algorithm",
    "privacy_mode", "privilege_level", "started_at", "completed_at",
    "host", "checks_attempted", "coverage", "posture_score",
    "findings", "checksum_algorithm", "checksum",
}
_ALLOWED_TOP_LEVEL = _REQUIRED_TOP_LEVEL | {"html_report_path"}
_REQUIRED_HOST = {"hostname", "os_name", "os_version", "os_build", "architecture"}
_REQUIRED_COVERAGE = {
    "coverage_pct", "attempted", "passed", "failed",
    "warned", "unavailable", "permission_required", "errors",
}
_REQUIRED_POSTURE_SCORE = {"score", "algorithm", "components", "caveat"}
_REQUIRED_FINDING = {
    "check_id", "finding_id", "title", "category",
    "severity", "confidence", "status",
}
_MAX_EVIDENCE_DEPTH = 4
_MAX_EVIDENCE_ITEMS = 100
_HEX64_LEN = 64


def _check_finite(value: Any, name: str) -> None:
    import math
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise _ValidationError(f"{name} must be a finite number, got {value}")


class _ValidationError(Exception):
    pass


def _validate_evidence(obj: Any, depth: int = 0) -> None:
    if depth > _MAX_EVIDENCE_DEPTH:
        raise _ValidationError(f"Evidence exceeds maximum nesting depth ({_MAX_EVIDENCE_DEPTH})")
    if isinstance(obj, dict):
        if len(obj) > MAX_EVIDENCE_KEYS:
            raise _ValidationError(f"Evidence dict exceeds {MAX_EVIDENCE_KEYS} keys")
        for k, v in obj.items():
            if not isinstance(k, str) or len(k) > MAX_EVIDENCE_KEY_LEN:
                raise _ValidationError(f"Evidence key too long or not a string: {k!r}")
            if isinstance(v, str) and len(v) > MAX_EVIDENCE_VAL_LEN:
                raise _ValidationError(f"Evidence value too long for key {k!r}")
            _validate_evidence(v, depth + 1)
    elif isinstance(obj, list):
        if len(obj) > _MAX_EVIDENCE_ITEMS:
            raise _ValidationError(f"Evidence list exceeds {_MAX_EVIDENCE_ITEMS} items")
        for item in obj:
            _validate_evidence(item, depth + 1)
    elif isinstance(obj, float):
        _check_finite(obj, "evidence numeric value")


def validate_report(report: dict) -> bool:
    """
    Validate the structural integrity of an assessment report dictionary.

    Returns True when the report conforms to the canonical schema.
    Returns False on any structural violation.

    This function does NOT verify the SHA-256 checksum; call verify_checksum()
    separately for integrity checking.

    No external dependencies (no FastAPI, Pydantic, SQLAlchemy, Windows APIs).
    """
    try:
        if not isinstance(report, dict):
            raise _ValidationError("Report must be a dictionary")

        # Top-level field presence
        missing = _REQUIRED_TOP_LEVEL - report.keys()
        if missing:
            raise _ValidationError(f"Missing required fields: {missing}")

        unknown = report.keys() - _ALLOWED_TOP_LEVEL
        if unknown:
            raise _ValidationError(f"Unknown top-level fields: {unknown}")

        # Schema and checksum algorithm
        sv = report.get("schema_version", "")
        if sv not in SUPPORTED_SCHEMA_VERSIONS:
            raise _ValidationError(f"Unsupported schema_version: {sv!r}")

        ca = report.get("checksum_algorithm", "")
        if ca not in SUPPORTED_CHECKSUM_ALGORITHMS:
            raise _ValidationError(f"Unsupported checksum_algorithm: {ca!r}")

        # Checksum field is a hex string of correct length
        chk = report.get("checksum", "")
        if not isinstance(chk, str) or len(chk) != _HEX64_LEN:
            raise _ValidationError(f"checksum must be a {_HEX64_LEN}-char hex string")
        if not all(c in "0123456789abcdef" for c in chk):
            raise _ValidationError("checksum must be a lowercase hex string")

        # Host structure
        host = report.get("host")
        if not isinstance(host, dict):
            raise _ValidationError("host must be a dict")
        missing_host = _REQUIRED_HOST - host.keys()
        if missing_host:
            raise _ValidationError(f"host missing fields: {missing_host}")

        # checks_attempted
        ca_count = report.get("checks_attempted")
        if not isinstance(ca_count, int) or ca_count < 0:
            raise _ValidationError("checks_attempted must be a non-negative integer")

        # Coverage structure
        cov = report.get("coverage")
        if not isinstance(cov, dict):
            raise _ValidationError("coverage must be a dict")
        missing_cov = _REQUIRED_COVERAGE - cov.keys()
        if missing_cov:
            raise _ValidationError(f"coverage missing fields: {missing_cov}")
        cov_pct = cov.get("coverage_pct")
        if not isinstance(cov_pct, (int, float)):
            raise _ValidationError("coverage.coverage_pct must be numeric")
        _check_finite(float(cov_pct), "coverage.coverage_pct")
        if not (0.0 <= cov_pct <= 100.0):
            raise _ValidationError(f"coverage.coverage_pct out of range: {cov_pct}")
        for field in ("attempted", "passed", "failed", "warned",
                      "unavailable", "permission_required", "errors"):
            val = cov.get(field)
            if not isinstance(val, int) or val < 0:
                raise _ValidationError(f"coverage.{field} must be a non-negative integer")

        # Posture score
        ps = report.get("posture_score")
        if not isinstance(ps, dict):
            raise _ValidationError("posture_score must be a dict")
        missing_ps = _REQUIRED_POSTURE_SCORE - ps.keys()
        if missing_ps:
            raise _ValidationError(f"posture_score missing fields: {missing_ps}")
        score_val = ps.get("score")
        if not isinstance(score_val, (int, float)):
            raise _ValidationError("posture_score.score must be numeric")
        _check_finite(float(score_val), "posture_score.score")
        if not (0 <= score_val <= 100):
            raise _ValidationError(f"posture_score.score out of range: {score_val}")
        if not isinstance(ps.get("components"), dict):
            raise _ValidationError("posture_score.components must be a dict")

        # Findings
        findings = report.get("findings")
        if not isinstance(findings, list):
            raise _ValidationError("findings must be a list")
        if len(findings) > MAX_FINDINGS:
            raise _ValidationError(f"findings exceeds maximum ({MAX_FINDINGS})")

        for i, f in enumerate(findings):
            if not isinstance(f, dict):
                raise _ValidationError(f"findings[{i}] must be a dict")
            missing_f = _REQUIRED_FINDING - f.keys()
            if missing_f:
                raise _ValidationError(f"findings[{i}] missing fields: {missing_f}")
            cat = f.get("category", "")
            if cat not in _ALLOWED_CATEGORIES:
                raise _ValidationError(f"findings[{i}] invalid category: {cat!r}")
            sev = f.get("severity", "")
            if sev not in _ALLOWED_SEVERITIES:
                raise _ValidationError(f"findings[{i}] invalid severity: {sev!r}")
            conf = f.get("confidence", "")
            if conf not in _ALLOWED_CONFIDENCES:
                raise _ValidationError(f"findings[{i}] invalid confidence: {conf!r}")
            stat = f.get("status", "")
            if stat not in _ALLOWED_STATUSES:
                raise _ValidationError(f"findings[{i}] invalid status: {stat!r}")
            title = f.get("title", "")
            if not isinstance(title, str) or len(title) > MAX_TITLE_LEN:
                raise _ValidationError(f"findings[{i}] title too long or not a string")
            evidence = f.get("evidence")
            if evidence is not None:
                _validate_evidence(evidence)

        return True

    except _ValidationError:
        return False
