"""Guardian v2 Phase 3 — Backend API endpoints.

Provides:
    POST /api/v1/guardian/approvals                   — Create approval request
    GET  /api/v1/guardian/approvals                   — List approval requests
    GET  /api/v1/guardian/approvals/{approval_id}     — Get approval request
    POST /api/v1/guardian/approvals/{approval_id}/approve — Approve request
    POST /api/v1/guardian/approvals/{approval_id}/reject  — Reject request
    POST /api/v1/guardian/actions/{action_id}/execute     — Execute approved action
    POST /api/v1/guardian/actions/{action_id}/rollback    — Request rollback
    GET  /api/v1/guardian/actions                       — List action attempts
    GET  /api/v1/guardian/actions/{action_id}            — Get action detail
    GET  /api/v1/guardian/audit                          — List audit records

All endpoints require authentication.
RBAC enforced per endpoint.

Security invariants:
- No endpoint executes without valid approved approval record
- No approval bypass
- No auto-approval based on severity
- All actions authenticated and audited
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .auth import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_RESPONDER,
    audit_event,
    get_current_user,
    require_roles,
)
from .database import get_db
from .models import (
    GuardianActionAttempt,
    GuardianActionAudit,
    GuardianActionRollback,
    GuardianActionSnapshot,
    GuardianActionVerification,
    GuardianApprovalRequest,
    User,
    utcnow,
)

from guardian.actions.base import (
    ActionStatus,
    ApprovalStatus,
    RollbackStatus,
    compute_action_id,
    compute_audit_id,
    compute_rollback_id,
    compute_snapshot_id,
    validate_state_transition,
)
from guardian.actions.registry import get_action, is_registered, list_actions
from guardian.actions.snapshot import SnapshotManager
from guardian.actions.verification import VerificationManager
from guardian.actions.rollback import RollbackManager
from guardian.approval.manager import ApprovalManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/guardian", tags=["guardian-phase3"])

# ── Rate limiting ──────────────────────────────────────────────────────
from .auth import RateLimiter

guardian_action_limiter = RateLimiter(60)  # 60 action requests per minute


# ── Request / Response schemas ─────────────────────────────────────────


class ApprovalCreateRequest(BaseModel):
    incident_id: Optional[int] = None
    decision_id: str = Field(..., max_length=128)
    requested_action: str = Field(..., max_length=64)
    action_type: str = Field(..., max_length=64)
    target: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2048)
    risk: Optional[Dict[str, Any]] = None
    ttl_minutes: int = Field(default=30, ge=1, le=1440)


class ApprovalActionRequest(BaseModel):
    notes: Optional[str] = Field(None, max_length=2048)


class ActionExecuteRequest(BaseModel):
    parameters: Optional[Dict[str, Any]] = None


class ActionRollbackRequest(BaseModel):
    notes: Optional[str] = Field(None, max_length=2048)


# ── Serialization helpers ──────────────────────────────────────────────


def _approval_request_to_dict(req: GuardianApprovalRequest) -> Dict[str, Any]:
    return {
        "id": req.id,
        "approval_id": req.approval_id,
        "incident_id": req.incident_id,
        "decision_id": req.decision_id,
        "requested_action": req.requested_action,
        "action_type": req.action_type,
        "target": req.target,
        "rationale": req.rationale,
        "risk": req.risk,
        "status": req.status,
        "requested_by": req.requested_by,
        "expires_at": req.expires_at.isoformat() if req.expires_at else None,
        "created_at": req.created_at.isoformat() if req.created_at else None,
        "updated_at": req.updated_at.isoformat() if req.updated_at else None,
    }


def _action_attempt_to_dict(attempt: GuardianActionAttempt) -> Dict[str, Any]:
    return {
        "id": attempt.id,
        "action_id": attempt.action_id,
        "approval_id": attempt.approval_id,
        "incident_id": attempt.incident_id,
        "decision_id": attempt.decision_id,
        "action_type": attempt.action_type,
        "action_name": attempt.action_name,
        "target": attempt.target,
        "parameters": attempt.parameters,
        "status": attempt.status,
        "execution_started_at": attempt.execution_started_at.isoformat() if attempt.execution_started_at else None,
        "execution_finished_at": attempt.execution_finished_at.isoformat() if attempt.execution_finished_at else None,
        "result": attempt.result,
        "error": attempt.error,
        "snapshot_id": attempt.snapshot_id,
        "verification_id": attempt.verification_id,
        "rollback_id": attempt.rollback_id,
        "created_at": attempt.created_at.isoformat() if attempt.created_at else None,
    }


def _audit_to_dict(audit: GuardianActionAudit) -> Dict[str, Any]:
    return {
        "id": audit.id,
        "audit_id": audit.audit_id,
        "incident_id": audit.incident_id,
        "approval_id": audit.approval_id,
        "action_id": audit.action_id,
        "actor": audit.actor,
        "action_type": audit.action_type,
        "target": audit.target,
        "snapshot_id": audit.snapshot_id,
        "execution_started_at": audit.execution_started_at.isoformat() if audit.execution_started_at else None,
        "execution_finished_at": audit.execution_finished_at.isoformat() if audit.execution_finished_at else None,
        "verification_passed": audit.verification_passed,
        "verification_result": audit.verification_result,
        "rollback_result": audit.rollback_result,
        "status": audit.status,
        "error": audit.error,
        "created_at": audit.created_at.isoformat() if audit.created_at else None,
    }


# ── Approval Endpoints ─────────────────────────────────────────────────


@router.post(
    "/approvals",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER)),
    ],
)
def create_approval_request(
    request: ApprovalCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create an approval request for a Guardian response action.

    The approval request is created in 'pending' status.
    It must be explicitly approved before any action can execute.
    """
    # Validate action type is registered
    if not is_registered(request.action_type, request.requested_action):
        raise HTTPException(
            status_code=422,
            detail=f"Action '{request.action_type}:{request.requested_action}' is not registered",
        )

    manager = ApprovalManager()
    result = manager.create_approval_request(
        db,
        incident_id=request.incident_id,
        decision_id=request.decision_id,
        requested_action=request.requested_action,
        action_type=request.action_type,
        target=request.target,
        rationale=request.rationale,
        risk=request.risk,
        requested_by=user.username,
        ttl_minutes=request.ttl_minutes,
    )

    audit_event(
        db, "guardian_approval_requested", "guardian_approval",
        result["approval_id"], {"action_type": request.action_type}, user=user,
    )
    db.commit()

    return result


@router.get(
    "/approvals",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def list_approval_requests(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    action_type: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List approval requests with pagination and filtering."""
    query = db.query(GuardianApprovalRequest)
    if status:
        query = query.filter(GuardianApprovalRequest.status == status)
    if action_type:
        query = query.filter(GuardianApprovalRequest.action_type == action_type)

    total = query.count()
    rows = query.order_by(GuardianApprovalRequest.created_at.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_approval_request_to_dict(row) for row in rows],
    }


@router.get(
    "/approvals/{approval_id}",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def get_approval_request(
    approval_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get details for a specific approval request."""
    req = db.query(GuardianApprovalRequest).filter(
        GuardianApprovalRequest.approval_id == approval_id,
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return _approval_request_to_dict(req)


@router.post(
    "/approvals/{approval_id}/approve",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER)),
    ],
)
def approve_request(
    approval_id: str,
    request: ApprovalActionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Approve a pending approval request.

    Only users with analyst, responder, or admin roles can approve.
    """
    manager = ApprovalManager()

    # RBAC check
    if not manager.check_rbac(user.role, "approve"):
        raise HTTPException(status_code=403, detail="Role not authorized to approve actions")

    try:
        result = manager.approve_request(
            db,
            approval_id=approval_id,
            approver=user.username,
            notes=request.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    audit_event(
        db, "guardian_approval_approved", "guardian_approval",
        approval_id, {"approver": user.username}, user=user,
    )
    db.commit()

    return result


@router.post(
    "/approvals/{approval_id}/reject",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER)),
    ],
)
def reject_request(
    approval_id: str,
    request: ApprovalActionRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Reject a pending approval request."""
    manager = ApprovalManager()

    if not manager.check_rbac(user.role, "reject"):
        raise HTTPException(status_code=403, detail="Role not authorized to reject actions")

    try:
        result = manager.reject_request(
            db,
            approval_id=approval_id,
            approver=user.username,
            notes=request.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    audit_event(
        db, "guardian_approval_rejected", "guardian_approval",
        approval_id, {"approver": user.username}, user=user,
    )
    db.commit()

    return result


# ── Action Execution Endpoints ─────────────────────────────────────────


@router.post(
    "/actions/{action_id}/execute",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_RESPONDER)),
    ],
)
def execute_action(
    action_id: str,
    request: ActionExecuteRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Execute an approved Guardian response action.

    Security invariants:
    - approval exists and is approved
    - approval is not expired
    - decision still matches the approved action
    - target still matches
    - action is allowed
    - action preconditions pass
    - execution is idempotent (same request returns same result)

    Never allows execution without a valid approved approval record.
    """
    # Find the action attempt
    attempt = db.query(GuardianActionAttempt).filter(
        GuardianActionAttempt.action_id == action_id,
    ).first()

    if not attempt:
        raise HTTPException(status_code=404, detail="Action attempt not found")

    # Idempotency: if already succeeded, return prior result
    if attempt.status == ActionStatus.SUCCEEDED:
        return {
            "action_id": attempt.action_id,
            "status": attempt.status,
            "result": attempt.result,
            "idempotent": True,
        }

    # If currently executing, reject to prevent concurrent execution
    if attempt.status == ActionStatus.EXECUTING:
        raise HTTPException(
            status_code=409,
            detail="Action is currently executing",
        )

    # Must be in approved status
    if attempt.status != ActionStatus.APPROVED:
        raise HTTPException(
            status_code=422,
            detail=f"Action status is '{attempt.status}'; must be 'approved' to execute",
        )

    # Validate approval is still valid
    approval_manager = ApprovalManager()
    is_valid, error_msg = approval_manager.validate_for_execution(
        db,
        approval_id=attempt.approval_id,
        decision_id=attempt.decision_id,
        target=attempt.target,
        action_type=attempt.action_type,
    )
    if not is_valid:
        # Transition to stale
        attempt.status = ActionStatus.STALE
        attempt.updated_at = utcnow()
        db.commit()
        raise HTTPException(status_code=422, detail=f"Stale decision: {error_msg}")

    # Get the registered action
    action = get_action(attempt.action_type, attempt.action_name)
    if not action:
        raise HTTPException(
            status_code=422,
            detail=f"Action '{attempt.action_type}:{attempt.action_name}' is not registered",
        )

    # Validate action preconditions
    validation = action.validate(attempt.target, attempt.parameters)
    if not validation.valid:
        attempt.status = ActionStatus.BLOCKED
        attempt.error = "; ".join(validation.errors)
        attempt.updated_at = utcnow()
        db.commit()
        raise HTTPException(
            status_code=422,
            detail=f"Action validation failed: {'; '.join(validation.errors)}",
        )

    # Transition to executing
    if not validate_state_transition(attempt.status, ActionStatus.EXECUTING):
        raise HTTPException(
            status_code=422,
            detail=f"Cannot transition from '{attempt.status}' to 'executing'",
        )
    attempt.status = ActionStatus.EXECUTING
    attempt.execution_started_at = utcnow()
    attempt.updated_at = utcnow()

    # Create snapshot if needed
    snapshot_data = None
    snapshot_manager = SnapshotManager()
    if action.requires_snapshot:
        raw_snapshot = action.snapshot(attempt.target, action_id)
        if raw_snapshot:
            raw_snapshot.snapshot_id = compute_snapshot_id(action_id)
            snapshot_data = raw_snapshot

            # Persist snapshot
            db_snapshot = GuardianActionSnapshot(
                snapshot_id=raw_snapshot.snapshot_id,
                action_id=action_id,
                action_type=attempt.action_type,
                target=raw_snapshot.target,
                prior_state=raw_snapshot.prior_state,
                snapshot_metadata=raw_snapshot.metadata,
                immutable=True,
                created_at=raw_snapshot.created_at,
            )
            db.add(db_snapshot)
            attempt.snapshot_id = raw_snapshot.snapshot_id

    db.commit()

    # Execute the action
    exec_result = action.execute(attempt.target, attempt.parameters, snapshot_data)

    # Transition to verifying
    if exec_result.success:
        attempt.status = ActionStatus.VERIFYING
    else:
        attempt.status = ActionStatus.EXECUTION_FAILED
        attempt.error = exec_result.error
    attempt.execution_finished_at = utcnow()
    attempt.result = exec_result.output
    attempt.updated_at = utcnow()
    db.commit()

    # Verify
    verification = None
    verification_id = None
    if exec_result.success:
        verify_manager = VerificationManager()
        verification = verify_manager.verify_action(
            action_id, attempt.target, exec_result, action.verify,
        )
        verification_id = compute_verification_id(action_id)

        # Persist verification
        db_verification = GuardianActionVerification(
            verification_id=verification_id,
            action_id=action_id,
            passed=verification.passed,
            checks=verification.checks,
            evidence=verification.evidence,
            observed_state=verification.observed_state,
            failure_reason=verification.failure_reason,
            created_at=utcnow(),
        )
        db.add(db_verification)
        attempt.verification_id = verification_id

        if verification.passed:
            attempt.status = ActionStatus.SUCCEEDED
        else:
            attempt.status = ActionStatus.VERIFICATION_FAILED
            attempt.error = verification.failure_reason

            # Offer rollback if supported
            rollback_mgr = RollbackManager()
            if rollback_mgr.is_rollback_needed(verification, action):
                rollback_id = compute_rollback_id(action_id)
                db_rollback = GuardianActionRollback(
                    rollback_id=rollback_id,
                    action_id=action_id,
                    snapshot_id=attempt.snapshot_id or "",
                    status=RollbackStatus.AVAILABLE,
                    created_at=utcnow(),
                )
                db.add(db_rollback)
                attempt.rollback_id = rollback_id
                attempt.status = ActionStatus.ROLLBACK_AVAILABLE

    attempt.updated_at = utcnow()
    db.commit()

    # Create audit record
    audit_id = compute_audit_id(action_id)
    db_audit = GuardianActionAudit(
        audit_id=audit_id,
        incident_id=attempt.incident_id,
        approval_id=attempt.approval_id,
        action_id=action_id,
        actor=user.username,
        action_type=attempt.action_type,
        target=attempt.target,
        snapshot_id=attempt.snapshot_id,
        execution_started_at=attempt.execution_started_at,
        execution_finished_at=attempt.execution_finished_at,
        verification_passed=verification.passed if verification else None,
        verification_result=verification.to_dict() if verification else None,
        status=attempt.status,
        error=attempt.error,
        created_at=utcnow(),
    )
    db.add(db_audit)

    audit_event(
        db, f"guardian_action_{attempt.status}", "guardian_action",
        action_id, {"status": attempt.status, "actor": user.username}, user=user,
    )
    db.commit()

    return {
        "action_id": action_id,
        "status": attempt.status,
        "execution_result": attempt.result,
        "verification": verification.to_dict() if verification else None,
        "error": attempt.error,
    }


@router.post(
    "/actions/{action_id}/rollback",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_RESPONDER)),
    ],
)
def request_rollback(
    action_id: str,
    request: ActionRollbackRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Request rollback for a failed action.

    Rollback is only available when:
    - Action verification failed
    - Action type supports rollback
    - Snapshot exists
    """
    attempt = db.query(GuardianActionAttempt).filter(
        GuardianActionAttempt.action_id == action_id,
    ).first()

    if not attempt:
        raise HTTPException(status_code=404, detail="Action attempt not found")

    if attempt.status not in (ActionStatus.ROLLBACK_AVAILABLE, ActionStatus.VERIFICATION_FAILED):
        raise HTTPException(
            status_code=422,
            detail=f"Rollback not available for action in status '{attempt.status}'",
        )

    if not attempt.snapshot_id:
        raise HTTPException(status_code=422, detail="No snapshot available for rollback")

    # Get the action
    action = get_action(attempt.action_type, attempt.action_name)
    if not action or not action.rollback_supported:
        raise HTTPException(status_code=422, detail="Action does not support rollback")

    # Get the snapshot
    snapshot_record = db.query(GuardianActionSnapshot).filter(
        GuardianActionSnapshot.snapshot_id == attempt.snapshot_id,
    ).first()

    if not snapshot_record:
        raise HTTPException(status_code=422, detail="Snapshot not found")

    # Update rollback status
    rollback_id = attempt.rollback_id or compute_rollback_id(action_id)
    rollback_record = db.query(GuardianActionRollback).filter(
        GuardianActionRollback.rollback_id == rollback_id,
    ).first()

    if rollback_record:
        rollback_record.status = RollbackStatus.REQUESTED
        rollback_record.requested_at = utcnow()
    else:
        rollback_record = GuardianActionRollback(
            rollback_id=rollback_id,
            action_id=action_id,
            snapshot_id=attempt.snapshot_id,
            status=RollbackStatus.REQUESTED,
            requested_at=utcnow(),
            created_at=utcnow(),
        )
        db.add(rollback_record)

    attempt.status = ActionStatus.ROLLBACK_REQUESTED
    attempt.updated_at = utcnow()
    db.commit()

    # Build SnapshotData from DB record
    from guardian.actions.base import SnapshotData
    snapshot_data = SnapshotData(
        snapshot_id=snapshot_record.snapshot_id,
        action_id=snapshot_record.action_id,
        action_type=snapshot_record.action_type,
        target=snapshot_record.target,
        prior_state=snapshot_record.prior_state,
        metadata=snapshot_record.snapshot_metadata,
        immutable=snapshot_record.immutable,
    )

    # Execute rollback
    rollback_mgr = RollbackManager()
    attempt.status = ActionStatus.ROLLBACK_RUNNING
    db.commit()

    rollback_result = rollback_mgr.request_rollback(action, attempt.target, snapshot_data)

    # Update status
    if rollback_result.success:
        attempt.status = ActionStatus.ROLLBACK_SUCCEEDED
        rollback_record.status = RollbackStatus.SUCCEEDED
    else:
        attempt.status = ActionStatus.ROLLBACK_FAILED
        rollback_record.status = RollbackStatus.FAILED
        rollback_record.error = rollback_result.error

    rollback_record.result = rollback_result.output
    rollback_record.finished_at = utcnow()
    attempt.updated_at = utcnow()

    # Audit
    audit_id = compute_audit_id(f"{action_id}-rollback")
    db_audit = GuardianActionAudit(
        audit_id=audit_id,
        incident_id=attempt.incident_id,
        approval_id=attempt.approval_id,
        action_id=action_id,
        actor=user.username,
        action_type=attempt.action_type,
        target=attempt.target,
        rollback_result=rollback_result.to_dict(),
        status=attempt.status,
        error=rollback_result.error,
        created_at=utcnow(),
    )
    db.add(db_audit)

    audit_event(
        db, f"guardian_rollback_{attempt.status}", "guardian_action",
        action_id, {"rollback_status": attempt.status, "actor": user.username}, user=user,
    )
    db.commit()

    return {
        "action_id": action_id,
        "rollback_id": rollback_id,
        "status": attempt.status,
        "rollback_result": rollback_result.to_dict(),
    }


# ── Action Query Endpoints ─────────────────────────────────────────────


@router.get(
    "/actions",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def list_action_attempts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    action_type: Optional[str] = None,
    approval_id: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List action attempts with pagination and filtering."""
    query = db.query(GuardianActionAttempt)
    if status:
        query = query.filter(GuardianActionAttempt.status == status)
    if action_type:
        query = query.filter(GuardianActionAttempt.action_type == action_type)
    if approval_id:
        query = query.filter(GuardianActionAttempt.approval_id == approval_id)

    total = query.count()
    rows = query.order_by(GuardianActionAttempt.created_at.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_action_attempt_to_dict(row) for row in rows],
    }


@router.get(
    "/actions/registry",
    dependencies=[
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def get_action_registry() -> Dict[str, Any]:
    """List all registered action types."""
    return {"actions": list_actions()}


@router.get(
    "/actions/{action_id}",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_ANALYST, ROLE_RESPONDER, ROLE_AUDITOR)),
    ],
)
def get_action_attempt(
    action_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get details for a specific action attempt."""
    attempt = db.query(GuardianActionAttempt).filter(
        GuardianActionAttempt.action_id == action_id,
    ).first()
    if not attempt:
        raise HTTPException(status_code=404, detail="Action attempt not found")
    return _action_attempt_to_dict(attempt)


# ── Audit Endpoints ────────────────────────────────────────────────────


@router.get(
    "/audit",
    dependencies=[
        Depends(guardian_action_limiter),
        Depends(require_roles(ROLE_ADMIN, ROLE_AUDITOR)),
    ],
)
def list_audit_records(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action_id: Optional[str] = None,
    actor: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """List immutable audit records for Guardian actions."""
    query = db.query(GuardianActionAudit)
    if action_id:
        query = query.filter(GuardianActionAudit.action_id == action_id)
    if actor:
        query = query.filter(GuardianActionAudit.actor == actor)
    if status:
        query = query.filter(GuardianActionAudit.status == status)

    total = query.count()
    rows = query.order_by(GuardianActionAudit.created_at.desc()).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_audit_to_dict(row) for row in rows],
    }
