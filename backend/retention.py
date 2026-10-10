"""Backend retention policies (explicit, bounded, auditable).

Referential-integrity rule: audit and authorization evidence outlives
telemetry. Cleanup order runs telemetry first and audit last, in bounded
batches, with dry-run planning and per-category audit events on failure.
Organization-specific periods are configuration decisions, not legal
claims. Destructive cleanup defaults to dry-run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

DEFAULT_BATCH_LIMIT = 1000

# Category -> (model attribute, timestamp column, default days, preserves-evidence note).
# Audit-family tables are intentionally last with the longest defaults.
RETENTION_POLICIES: Dict[str, Dict[str, Any]] = {
    "guardian_heartbeats": {"model": "GuardianHeartbeat", "column": "timestamp",
                            "default_days": 30, "audit_family": False},
    "guardian_collector_health": {"model": "GuardianCollectorHealth", "column": "updated_at",
                                  "default_days": 90, "audit_family": False},
    "guardian_events": {"model": "GuardianEvent", "column": "created_at",
                        "default_days": 180, "audit_family": False},
    "detections": {"model": "Detection", "column": "created_at",
                   "default_days": 365, "audit_family": False},
    "incidents": {"model": "Incident", "column": "created_at",
                  "default_days": 730, "audit_family": False},
    "guardian_detections": {"model": "GuardianDetection", "column": "created_at",
                            "default_days": 365, "audit_family": False},
    "guardian_incidents": {"model": "GuardianIncident", "column": "created_at",
                           "default_days": 730, "audit_family": False},
    "guardian_policy_evaluations": {"model": "GuardianPolicyEvaluation", "column": "created_at",
                                    "default_days": 730, "audit_family": True},
    "guardian_envelope_runs": {"model": "GuardianEnvelopeRun", "column": "created_at",
                               "default_days": 1095, "audit_family": True},
    "guardian_action_audit": {"model": "GuardianActionAudit", "column": "created_at",
                              "default_days": 1095, "audit_family": True},
    "audit_events": {"model": "AuditEvent", "column": "created_at",
                     "default_days": 1095, "audit_family": True},
}


@dataclass
class CleanupResult:
    category: str
    eligible: int
    deleted: int
    dry_run: bool
    error: str = ""


def validate_retention_config(config: Dict[str, Any]) -> Dict[str, int]:
    """Validate per-category day counts. Returns effective days."""
    if not isinstance(config, dict):
        raise ValueError("Retention config must be an object")
    effective: Dict[str, int] = {}
    for category, policy in RETENTION_POLICIES.items():
        days = config.get(category, policy["default_days"])
        if not isinstance(days, int) or days < 7 or days > 3650:
            raise ValueError(f"Retention for {category} must be an integer 7-3650 days")
        effective[category] = days
    unknown = [key for key in config if key not in RETENTION_POLICIES]
    if unknown:
        raise ValueError(f"Unknown retention categories rejected: {', '.join(sorted(unknown))}")
    return effective


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def plan_cleanup(session, days: Dict[str, int]) -> List[CleanupResult]:
    """Count eligible rows per category. Never deletes (dry-run core)."""
    import backend.models as _models

    results: List[CleanupResult] = []
    for category, policy in RETENTION_POLICIES.items():
        try:
            model = getattr(_models, policy["model"])
            column = getattr(model, policy["column"])
            cutoff = _now_utc() - timedelta(days=days.get(category, policy["default_days"]))
            eligible = session.query(model).filter(column < cutoff).count()
            results.append(CleanupResult(category, eligible, 0, True))
        except Exception as exc:  # noqa: BLE001 - per-category errors are explicit
            results.append(CleanupResult(category, 0, 0, True, error=str(exc)[:300]))
    return results


def execute_cleanup(session, days: Dict[str, int], *, batch_limit: int = DEFAULT_BATCH_LIMIT,
                    actor: str = "retention") -> List[CleanupResult]:
    """Bounded deletion in dependency-safe order with audit events."""
    import backend.models as _models
    from backend.auth import audit_event

    order = [name for name in RETENTION_POLICIES if not RETENTION_POLICIES[name]["audit_family"]]
    order += [name for name in RETENTION_POLICIES if RETENTION_POLICIES[name]["audit_family"]]
    results: List[CleanupResult] = []
    for category in order:
        policy = RETENTION_POLICIES[category]
        try:
            model = getattr(_models, policy["model"])
            column = getattr(model, policy["column"])
            cutoff = _now_utc() - timedelta(days=days.get(category, policy["default_days"]))
            eligible = session.query(model).filter(column < cutoff).count()
            rows = session.query(model).filter(column < cutoff).limit(batch_limit).all()
            deleted = 0
            for row in rows:
                session.delete(row)
                deleted += 1
            audit_event(session, "retention_cleanup", "retention", category,
                        {"deleted": deleted, "eligible": eligible, "actor": actor})
            session.commit()
            results.append(CleanupResult(category, eligible, deleted, False))
        except Exception as exc:  # noqa: BLE001 - explicit per-category failure
            session.rollback()
            try:
                audit_event(session, "retention_cleanup_failed", "retention", category,
                            {"error": str(exc)[:300], "actor": actor})
                session.commit()
            except Exception:  # noqa: BLE001
                session.rollback()
            results.append(CleanupResult(category, 0, 0, False, error=str(exc)[:300]))
    return results


def main(argv=None) -> int:
    """CLI. Defaults to dry-run; --apply performs bounded cleanup."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Backend retention planner/cleaner")
    parser.add_argument("--config", default="", help="JSON file with per-category days")
    parser.add_argument("--apply", action="store_true", help="Execute bounded cleanup (default is dry-run)")
    parser.add_argument("--batch-limit", type=int, default=DEFAULT_BATCH_LIMIT)
    args = parser.parse_args(argv)
    try:
        raw = json.loads(open(args.config, encoding="utf-8").read()) if args.config else {}
        days = validate_retention_config(raw)
    except (ValueError, OSError) as exc:
        print(f"REJECTED: {exc}")
        return 2
    from backend.database import SessionLocal

    session = SessionLocal()
    try:
        if not args.apply:
            for result in plan_cleanup(session, days):
                print(f"{result.category}: eligible={result.eligible} (dry-run){' ERROR ' + result.error if result.error else ''}")
            print("Dry-run only: re-run with --apply to execute bounded cleanup.")
            return 0
        for result in execute_cleanup(session, days, batch_limit=args.batch_limit):
            print(f"{result.category}: eligible={result.eligible} deleted={result.deleted}"
                  f"{' ERROR ' + result.error if result.error else ''}")
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
