"""Pilot metric definitions and exact calculations (no measurement runs).

Every function consumes RECORDED evidence (lists/dicts supplied by the
operator's later evidence collection) and returns a value plus its
provenance. Precision/recall require valid labeling; otherwise the result
is explicitly inconclusive instead of a fabricated score. Latency uses
distributions with censored attempts counted, never dropped to flatter
performance. Resource thresholds are pilot configuration decisions.
"""

from __future__ import annotations

from statistics import mean, median
from typing import Any, Dict, List, Optional


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[index]


def detection_quality(*, true_detections: int, false_positives: int,
                      false_negatives: int, labeling_valid: bool,
                      denominator_note: str = "") -> Dict[str, Any]:
    """Precision/recall from independently labeled scenarios only."""
    if not labeling_valid:
        return {"precision": None, "recall": None, "verdict": "inconclusive",
                "reason": "labeling invalid or denominator unknown; no score claimed",
                "denominator_note": denominator_note}
    precision = (true_detections / (true_detections + false_positives)
                 if (true_detections + false_positives) > 0 else None)
    recall = (true_detections / (true_detections + false_negatives)
              if (true_detections + false_negatives) > 0 else None)
    return {"precision": precision, "recall": recall, "verdict": "computed",
            "true_detections": true_detections, "false_positives": false_positives,
            "false_negatives": false_negatives, "denominator_note": denominator_note}


def latency_distribution(samples_seconds: List[float], *, censored: int = 0,
                         stage: str = "") -> Dict[str, Any]:
    """Distribution over completed attempts; censored attempts counted openly."""
    if not samples_seconds:
        return {"stage": stage, "count": 0, "censored": censored,
                "note": "no completed attempts; censored attempts reported, not imputed"}
    return {"stage": stage, "count": len(samples_seconds), "censored": censored,
            "min": min(samples_seconds), "p50": median(samples_seconds),
            "p95": _percentile(samples_seconds, 95), "max": max(samples_seconds),
            "mean": mean(samples_seconds)}


def resource_summary(*, cpu_pct: List[float], memory_mb: List[float],
                     disk_mb: List[float], provenance: str = "") -> Dict[str, Any]:
    """Summarize resource samples with provenance (hardware/conditions noted by caller)."""
    def _summarize(values: List[float]) -> Dict[str, Any]:
        if not values:
            return {"count": 0}
        return {"count": len(values), "min": min(values),
                "p50": median(values), "p95": _percentile(values, 95), "max": max(values)}
    return {"cpu_pct": _summarize(cpu_pct), "memory_mb": _summarize(memory_mb),
            "disk_mb": _summarize(disk_mb), "provenance": provenance,
            "note": "thresholds are pilot configuration decisions, not universal limits"}


def queue_reliability(*, depth_series: List[int], ack_lag_seconds: List[float],
                      lost_or_dropped: int, retried: int) -> Dict[str, Any]:
    """Queue/retry/ack-lag summary. Any loss is reported, never imputed as delivered."""
    return {"max_depth": max(depth_series) if depth_series else 0,
            "ack_lag": latency_distribution(ack_lag_seconds, stage="acknowledgement_lag"),
            "lost_or_dropped": lost_or_dropped, "retried": retried,
            "verdict": "lossy" if lost_or_dropped > 0 else "no observed loss"}


def action_safety_ledger(*, blocked: int, awaiting_approval: int, executed: int,
                         verified_ok: int, verified_failed: int,
                         rollbacks_attempted: int, rollbacks_ok: int,
                         revoked_or_stale_denied: int) -> Dict[str, Any]:
    """Action outcomes ledger. API success alone never counts as verified."""
    return {"blocked_by_safety_gates": blocked, "awaiting_approval": awaiting_approval,
            "approved_executed": executed, "verified_ok": verified_ok,
            "verified_failed": verified_failed,
            "rollbacks_attempted": rollbacks_attempted, "rollbacks_ok": rollbacks_ok,
            "revoked_expired_stale_denied": revoked_or_stale_denied,
            "note": "verified_ok requires independent verification evidence, not API 200"}


def workload_observations(*, alerts_reviewed: int, triage_minutes: List[float],
                          duplicates_or_low_value: int, escalations: int,
                          blocked_workflows: int,
                          understanding_notes: str = "") -> Dict[str, Any]:
    """Operator workload evidence. No invented times or survey scores."""
    return {"alerts_reviewed": alerts_reviewed,
            "triage_minutes": latency_distribution(triage_minutes, stage="triage"),
            "duplicates_or_low_value": duplicates_or_low_value,
            "escalations": escalations, "blocked_workflows": blocked_workflows,
            "understanding_notes": understanding_notes}
