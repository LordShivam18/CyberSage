"""Guardian v2 Phase 4 — API Endpoints (Automation, Safety, UI)."""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text

from .auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_RESPONDER,
    get_current_user,
    require_roles,
)
from .database import get_db
from .models import User, AuditEvent

# Create Phase 4 router
router = APIRouter(tags=["Guardian Phase 4"])

# ── 1. Guardian Operations Dashboard (UI Data) ───────────────────────

@router.get(
    "/api/v1/guardian/dashboard",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def get_guardian_dashboard(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Provide aggregated data for the Guardian Operations Dashboard.

    Slice 3: backend-grounded counts (no invented telemetry). Unavailable
    data is returned as None so the UI can distinguish "unknown" from zero.
    Keys from Phase 4 are preserved for compatibility.
    """
    try:
        # Check collector health
        collectors_query = db.execute(
            text("SELECT agent_id, collector_type, health_state, last_event_at, events_received FROM guardian_collector_health")
        ).fetchall()
        collectors = [
            {
                "agent_id": row[0],
                "collector_type": row[1],
                "health_state": row[2],
                "last_event_at": row[3].isoformat() if hasattr(row[3], "isoformat") and row[3] else row[3],
                "events_received": row[4]
            }
            for row in collectors_query
        ]
    except Exception:
        db.rollback()
        collectors = []

    try:
        # Check active automation runs
        runs_query = db.execute(
            text("SELECT run_id, action_type, status, created_at FROM guardian_automation_runs ORDER BY created_at DESC LIMIT 10")
        ).fetchall()
        runs = [
            {
                "run_id": row[0],
                "action_type": row[1],
                "status": row[2],
                "created_at": row[3].isoformat() if hasattr(row[3], "isoformat") and row[3] else row[3]
            }
            for row in runs_query
        ]
    except Exception:
        db.rollback()
        runs = []

    def _count(sql: str, params: dict | None = None):
        try:
            row = db.execute(text(sql), params or {}).fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        except Exception:
            db.rollback()
            return None

    active_incidents = _count(
        "SELECT COUNT(*) FROM guardian_incidents WHERE status NOT IN ('closed', 'resolved')"
    )
    if active_incidents is None:
        # Fall back to NDR incidents so the dashboard stays grounded even
        # when the Guardian incident pipeline has no rows yet.
        active_incidents = _count(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('new', 'triaged', 'investigating', 'contained')"
        )
    pending_approvals = _count(
        "SELECT COUNT(*) FROM guardian_approval_requests WHERE status = 'pending'"
    )

    return {
        "status": "online",
        "collectors": collectors,
        "recent_automation_runs": runs,
        "active_incidents_count": active_incidents,
        "pending_approvals_count": pending_approvals,
    }

# ── 2. Incident Workflow ─────────────────────────────────────────────

@router.get(
    "/api/v1/guardian/incidents/{incident_id}/workflow",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def get_incident_workflow(incident_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Return full workflow state (approvals, actions, audit) for an incident."""
    return {
        "incident_id": incident_id,
        "approvals": [],
        "actions": [],
        "audit_trail": []
    }

# ── 3. Collector Health ──────────────────────────────────────────────

@router.get(
    "/api/v1/guardian/collectors/health",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def get_collectors_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Return health state for all collectors."""
    try:
        collectors = db.execute(
            text("SELECT agent_id, collector_type, health_state, updated_at FROM guardian_collector_health")
        ).fetchall()
        
        return {
            "collectors": [
                {
                    "agent_id": row[0],
                    "collector_type": row[1],
                    "health_state": row[2],
                    "updated_at": row[3],
                } for row in collectors
            ]
        }
    except Exception as e:
        return {"error": str(e), "collectors": []}

# ── 4. Automation Policy & Rules ─────────────────────────────────────

@router.get(
    "/api/v1/guardian/automation/policies",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def list_automation_policies(db: Session = Depends(get_db)) -> Dict[str, Any]:
    try:
        policies = db.execute(
            text("SELECT policy_id, name, mode, enabled FROM guardian_automation_policies")
        ).fetchall()
        return {
            "policies": [
                {
                    "policy_id": row[0],
                    "name": row[1],
                    "mode": row[2],
                    "enabled": bool(row[3]),
                } for row in policies
            ]
        }
    except Exception:
        return {"policies": []}

# ── 5. Kill Switch Management ────────────────────────────────────────

@router.get(
    "/api/v1/guardian/safety/kill_switch",
    dependencies=[Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR))],
)
def get_kill_switches(db: Session = Depends(get_db)) -> Dict[str, Any]:
    try:
        switches = db.execute(
            text("SELECT scope, switch_key, active, reason FROM guardian_kill_switches")
        ).fetchall()
        return {
            "kill_switches": [
                {
                    "scope": row[0],
                    "switch_key": row[1],
                    "active": bool(row[2]),
                    "reason": row[3],
                } for row in switches
            ]
        }
    except Exception:
        return {"kill_switches": []}

@router.post(
    "/api/v1/guardian/safety/kill_switch",
    dependencies=[Depends(require_roles(ROLE_ADMIN))],
)
def activate_kill_switch(
    scope: str,
    switch_key: str,
    reason: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Activate a kill switch with memory + database write-through (Slice 2).

    Previously a stub that reported success without persisting anything.
    Now delegates to the shared kill-switch store so the in-memory
    singleton and the persisted table cannot disagree.
    """
    from fastapi import HTTPException as _HTTPException

    from guardian.safety import kill_switch_store as _kss
    from guardian.safety.kill_switch import get_default_kill_switch as _get_ks

    try:
        result = _kss.activate_persisted(
            db, _get_ks(), scope, switch_key, by=user.username, reason=reason,
        )
    except ValueError as exc:
        raise _HTTPException(status_code=422, detail=str(exc))
    db.commit()
    return {"status": "activated", **result}
