"""Approval manager — manages the approval lifecycle for Guardian response actions.

Approval states: pending → approved | rejected | expired | cancelled

Every approval must be explicit. No implicit approval.
No auto-approval based solely on severity.

Stale-decision protection:
Before execution, revalidate:
- incident state
- decision version
- target identity
- action parameters
- approval expiry
- current policy
- current risk state

If anything important changed, execution MUST fail closed.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from guardian.actions.base import (
    ActionStatus,
    ApprovalStatus,
    compute_approval_id,
    validate_state_transition,
)

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Default approval TTL (30 minutes)
DEFAULT_APPROVAL_TTL_MINUTES = 30


class ApprovalManager:
    """Manages approval requests and approvals.

    Enforces:
- Explicit approval required
- RBAC enforcement
- Stale-decision protection
- Expiry checking
- State machine transitions
    """

    def create_approval_request(
        self,
        session: Session,
        *,
        incident_id: Optional[int],
        decision_id: str,
        requested_action: str,
        action_type: str,
        target: Dict[str, Any],
        rationale: str,
        risk: Optional[Dict[str, Any]] = None,
        requested_by: str = "system",
        ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES,
    ) -> Dict[str, Any]:
        """Create a new approval request.

        Args:
            session: Database session.
            incident_id: Associated incident ID.
            decision_id: The ResponseDecision ID.
            requested_action: Action to be taken.
            action_type: Action category.
            target: Target specification.
            rationale: Why this action is needed.
            risk: Risk assessment data.
            requested_by: Who requested this.
            ttl_minutes: How long the approval is valid.

        Returns:
            Dict with approval request details.
        """
        from backend.models import GuardianApprovalRequest

        approval_id = compute_approval_id(action_type, target, decision_id)
        now = _now_utc()

        # Check for existing request (idempotency) — any status
        existing = session.query(GuardianApprovalRequest).filter(
            GuardianApprovalRequest.approval_id == approval_id,
        ).first()

        if existing:
            return {
                "approval_id": existing.approval_id,
                "status": existing.status,
                "created_at": existing.created_at.isoformat() if existing.created_at else None,
                "existing": True,
            }

        request = GuardianApprovalRequest(
            approval_id=approval_id,
            incident_id=incident_id,
            decision_id=decision_id,
            requested_action=requested_action,
            action_type=action_type,
            target=target,
            rationale=rationale,
            risk=risk,
            status=ApprovalStatus.PENDING,
            requested_by=requested_by,
            expires_at=now + timedelta(minutes=ttl_minutes),
            created_at=now,
            updated_at=now,
        )
        session.add(request)
        session.flush()

        logger.info("Created approval request %s for action %s", approval_id, requested_action)

        return {
            "approval_id": approval_id,
            "status": ApprovalStatus.PENDING,
            "expires_at": request.expires_at.isoformat(),
            "created_at": request.created_at.isoformat(),
        }

    def approve_request(
        self,
        session: Session,
        *,
        approval_id: str,
        approver: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Approve a pending approval request.

        Args:
            session: Database session.
            approval_id: The approval request ID.
            approver: Username of the approver.
            notes: Optional approval notes.

        Returns:
            Dict with approval result.

        Raises:
            ValueError: If approval cannot be processed.
        """
        from backend.models import GuardianApproval, GuardianApprovalRequest

        request = session.query(GuardianApprovalRequest).filter(
            GuardianApprovalRequest.approval_id == approval_id,
        ).first()

        if not request:
            raise ValueError(f"Approval request {approval_id} not found")

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Cannot approve request in status '{request.status}'; must be 'pending'"
            )

        if request.expires_at and request.expires_at < _now_utc():
            # Auto-expire
            request.status = ApprovalStatus.EXPIRED
            request.updated_at = _now_utc()
            session.flush()
            raise ValueError(f"Approval request {approval_id} has expired")

        # Record the approval
        record_id = f"apv-{hashlib.sha256(f'{approval_id}|{approver}|approve'.encode()).hexdigest()[:16]}"
        approval_record = GuardianApproval(
            approval_record_id=record_id,
            approval_request_id=request.id,
            approver=approver,
            decision="approved",
            notes=notes,
            created_at=_now_utc(),
        )
        session.add(approval_record)

        # Update request status
        request.status = ApprovalStatus.APPROVED
        request.updated_at = _now_utc()
        session.flush()

        logger.info("Approval request %s approved by %s", approval_id, approver)

        return {
            "approval_id": approval_id,
            "status": ApprovalStatus.APPROVED,
            "approver": approver,
            "approved_at": approval_record.created_at.isoformat(),
        }

    def reject_request(
        self,
        session: Session,
        *,
        approval_id: str,
        approver: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Reject a pending approval request.

        Args:
            session: Database session.
            approval_id: The approval request ID.
            approver: Username of the rejector.
            notes: Optional rejection notes.

        Returns:
            Dict with rejection result.

        Raises:
            ValueError: If rejection cannot be processed.
        """
        from backend.models import GuardianApproval, GuardianApprovalRequest

        request = session.query(GuardianApprovalRequest).filter(
            GuardianApprovalRequest.approval_id == approval_id,
        ).first()

        if not request:
            raise ValueError(f"Approval request {approval_id} not found")

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Cannot reject request in status '{request.status}'; must be 'pending'"
            )

        # Record the rejection
        record_id = f"apv-{hashlib.sha256(f'{approval_id}|{approver}|reject'.encode()).hexdigest()[:16]}"
        approval_record = GuardianApproval(
            approval_record_id=record_id,
            approval_request_id=request.id,
            approver=approver,
            decision="rejected",
            notes=notes,
            created_at=_now_utc(),
        )
        session.add(approval_record)

        # Update request status
        request.status = ApprovalStatus.REJECTED
        request.updated_at = _now_utc()
        session.flush()

        logger.info("Approval request %s rejected by %s", approval_id, approver)

        return {
            "approval_id": approval_id,
            "status": ApprovalStatus.REJECTED,
            "approver": approver,
            "rejected_at": approval_record.created_at.isoformat(),
        }

    def check_expiry(self, session: Session, approval_id: str) -> bool:
        """Check if an approval request has expired and update if so.

        Args:
            session: Database session.
            approval_id: The approval request ID.

        Returns:
            True if the request is still valid (not expired).
        """
        from backend.models import GuardianApprovalRequest

        request = session.query(GuardianApprovalRequest).filter(
            GuardianApprovalRequest.approval_id == approval_id,
        ).first()

        if not request:
            return False

        if request.status == ApprovalStatus.PENDING and request.expires_at:
            if request.expires_at < _now_utc():
                request.status = ApprovalStatus.EXPIRED
                request.updated_at = _now_utc()
                session.flush()
                logger.info("Approval request %s expired", approval_id)
                return False

        return request.status in (ApprovalStatus.APPROVED, ApprovalStatus.PENDING)

    def validate_for_execution(
        self,
        session: Session,
        *,
        approval_id: str,
        decision_id: str,
        target: Dict[str, Any],
        action_type: str,
    ) -> Tuple[bool, Optional[str]]:
        """Validate that an approval is still valid for execution.

        Performs stale-decision protection:
- approval exists and is approved
- approval is not expired
- decision still matches
- target still matches
- action type is allowed

        Args:
            session: Database session.
            approval_id: The approval request ID.
            decision_id: The decision ID to match.
            target: Target to match.
            action_type: Action type to match.

        Returns:
            Tuple of (is_valid, error_message).
        """
        from backend.models import GuardianApprovalRequest

        request = session.query(GuardianApprovalRequest).filter(
            GuardianApprovalRequest.approval_id == approval_id,
        ).first()

        if not request:
            return False, f"Approval request {approval_id} not found"

        # Check status
        if request.status != ApprovalStatus.APPROVED:
            return False, f"Approval status is '{request.status}', expected 'approved'"

        # Check expiry
        if request.expires_at and request.expires_at < _now_utc():
            request.status = ApprovalStatus.EXPIRED
            request.updated_at = _now_utc()
            session.flush()
            return False, "Approval has expired"

        # Check decision match
        if request.decision_id != decision_id:
            return False, (
                f"Decision ID mismatch: approval is for '{request.decision_id}', "
                f"execution is for '{decision_id}'"
            )

        # Check target match
        if request.target != target:
            return False, (
                f"Target mismatch: approval target is {request.target}, "
                f"execution target is {target}"
            )

        # Check action type
        if request.action_type != action_type:
            return False, (
                f"Action type mismatch: approval is for '{request.action_type}', "
                f"execution is for '{action_type}'"
            )

        return True, None

    def check_rbac(self, role: str, action: str) -> bool:
        """Check if a role is allowed to perform an approval action.

        RBAC rules:
- read_only_auditor: cannot approve, cannot execute
- security_analyst: can review, can approve supported actions
- incident_responder: can approve/execute supported actions
- administrator: full response-management permissions

        Args:
            role: User role.
            action: Action to check ("approve", "reject", "execute", "view").

        Returns:
            True if the role is allowed.
        """
        permissions = {
            "read_only_auditor": {"view"},
            "security_analyst": {"view", "approve", "reject"},
            "incident_responder": {"view", "approve", "reject", "execute"},
            "administrator": {"view", "approve", "reject", "execute", "manage"},
        }
        return action in permissions.get(role, set())

    def get_request_status(self, session: Session, approval_id: str) -> Optional[Dict[str, Any]]:
        """Get the current status of an approval request.

        Args:
            session: Database session.
            approval_id: The approval request ID.

        Returns:
            Dict with request details, or None if not found.
        """
        from backend.models import GuardianApprovalRequest

        request = session.query(GuardianApprovalRequest).filter(
            GuardianApprovalRequest.approval_id == approval_id,
        ).first()

        if not request:
            return None

        return {
            "approval_id": request.approval_id,
            "incident_id": request.incident_id,
            "decision_id": request.decision_id,
            "requested_action": request.requested_action,
            "action_type": request.action_type,
            "target": request.target,
            "rationale": request.rationale,
            "risk": request.risk,
            "status": request.status,
            "requested_by": request.requested_by,
            "expires_at": request.expires_at.isoformat() if request.expires_at else None,
            "created_at": request.created_at.isoformat() if request.created_at else None,
            "updated_at": request.updated_at.isoformat() if request.updated_at else None,
        }
