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
