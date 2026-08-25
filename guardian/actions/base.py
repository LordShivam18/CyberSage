"""Abstract Action interface for Guardian Phase 3 response actions.

Every response action must implement this interface.
Actions are separated into planning, execution, verification, and rollback.
No action may execute without explicit human approval.
"""

from __future__ import annotations

import hashlib
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ActionStatus(str, Enum):
    """Strict lifecycle for action attempts."""
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    EXECUTION_FAILED = "execution_failed"
    VERIFICATION_FAILED = "verification_failed"
    ROLLBACK_AVAILABLE = "rollback_available"
    ROLLBACK_REQUESTED = "rollback_requested"
    ROLLBACK_RUNNING = "rolling_back"
    ROLLBACK_SUCCEEDED = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    STALE = "stale"
    BLOCKED = "blocked"


class RollbackStatus(str, Enum):
    """Rollback lifecycle states."""
    NOT_SUPPORTED = "not_supported"
    AVAILABLE = "available"
    REQUESTED = "requested"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ApprovalStatus(str, Enum):
    """Approval request lifecycle states."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


# Valid state transitions
VALID_ACTION_TRANSITIONS: Dict[str, List[str]] = {
    ActionStatus.PLANNED: [ActionStatus.AWAITING_APPROVAL, ActionStatus.BLOCKED],
    ActionStatus.AWAITING_APPROVAL: [
        ActionStatus.APPROVED,
        ActionStatus.REJECTED,
        ActionStatus.EXPIRED,
    ],
    ActionStatus.APPROVED: [
        ActionStatus.EXECUTING,
        ActionStatus.STALE,
        ActionStatus.EXPIRED,
    ],
    ActionStatus.EXECUTING: [
        ActionStatus.VERIFYING,
        ActionStatus.EXECUTION_FAILED,
    ],
    ActionStatus.VERIFYING: [
        ActionStatus.SUCCEEDED,
        ActionStatus.VERIFICATION_FAILED,
    ],
    ActionStatus.EXECUTION_FAILED: [
        ActionStatus.ROLLBACK_AVAILABLE,
        ActionStatus.ROLLBACK_FAILED,
    ],
    ActionStatus.VERIFICATION_FAILED: [
        ActionStatus.ROLLBACK_AVAILABLE,
        ActionStatus.ROLLBACK_FAILED,
    ],
    ActionStatus.ROLLBACK_AVAILABLE: [
        ActionStatus.ROLLBACK_REQUESTED,
        ActionStatus.BLOCKED,
    ],
    ActionStatus.ROLLBACK_REQUESTED: [ActionStatus.ROLLBACK_RUNNING],
    ActionStatus.ROLLBACK_RUNNING: [
        ActionStatus.ROLLBACK_SUCCEEDED,
        ActionStatus.ROLLBACK_FAILED,
    ],
    # Terminal states
    ActionStatus.SUCCEEDED: [],
    ActionStatus.ROLLBACK_SUCCEEDED: [],
    ActionStatus.ROLLBACK_FAILED: [],
    ActionStatus.REJECTED: [],
    ActionStatus.EXPIRED: [],
    ActionStatus.STALE: [],
    ActionStatus.BLOCKED: [],
}


def validate_state_transition(current: str, target: str) -> bool:
    """Validate that a state transition is allowed."""
    allowed = VALID_ACTION_TRANSITIONS.get(current, [])
    return target in allowed


def compute_action_id(action_type: str, target: Dict[str, Any], decision_id: str) -> str:
    """Compute a deterministic action ID from action type, target, and decision."""
    target_str = str(sorted(target.items()))
    payload = f"{action_type}|{target_str}|{decision_id}"
    return f"act-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def compute_approval_id(action_type: str, target: Dict[str, Any], decision_id: str) -> str:
    """Compute a deterministic approval request ID."""
    target_str = str(sorted(target.items()))
    payload = f"approval|{action_type}|{target_str}|{decision_id}"
    return f"apr-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


def compute_snapshot_id(action_id: str) -> str:
    """Compute a deterministic snapshot ID."""
    return f"snp-{hashlib.sha256(action_id.encode()).hexdigest()[:16]}"


def compute_verification_id(action_id: str) -> str:
    """Compute a deterministic verification ID."""
    return f"vrf-{hashlib.sha256(action_id.encode()).hexdigest()[:16]}"


def compute_rollback_id(action_id: str) -> str:
    """Compute a deterministic rollback ID."""
    return f"rbk-{hashlib.sha256(action_id.encode()).hexdigest()[:16]}"


def compute_audit_id(action_id: str) -> str:
    """Compute a deterministic audit record ID."""
    return f"aud-{hashlib.sha256(action_id.encode()).hexdigest()[:16]}"


@dataclass
class ValidationResult:
    """Result of action validation."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class SnapshotData:
    """Pre-execution snapshot of target state."""
    snapshot_id: str = ""
    action_id: str = ""
    action_type: str = ""
    target: Dict[str, Any] = field(default_factory=dict)
    prior_state: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    immutable: bool = True
    created_at: datetime = field(default_factory=_now_utc)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


@dataclass
class ExecutionResult:
    """Result of action execution."""
    success: bool
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class VerificationResult:
    """Result of independent verification."""
    passed: bool
    checks: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    observed_state: Dict[str, Any] = field(default_factory=dict)
    failure_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RollbackResult:
    """Result of rollback operation."""
    success: bool
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseAction(ABC):
    """Abstract base for all Guardian response actions.

    Actions are separated into distinct phases:
    - validate(): Check preconditions and target validity
    - snapshot(): Capture pre-execution state
    - execute(): Perform the action
    - verify(): Independently confirm the action took effect
    - rollback(): Undo the action if supported
    - describe(): Human-readable description

    Properties:
    - action_type: Category (process, network, persistence)
    - action_name: Specific action (terminate_process, block_destination, etc.)
    - rollback_supported: Whether this action can be rolled back
    - requires_snapshot: Whether a pre-execution snapshot is needed
    """

    @property
    @abstractmethod
    def action_type(self) -> str:
        """Action category: process, network, persistence."""

    @property
    @abstractmethod
    def action_name(self) -> str:
        """Specific action name."""

    @property
    def rollback_supported(self) -> bool:
        """Whether this action supports rollback."""
        return False

    @property
    def requires_snapshot(self) -> bool:
        """Whether this action requires a pre-execution snapshot."""
        return self.rollback_supported

    @abstractmethod
    def validate(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """Validate that the action can be performed on the given target.

        Args:
            target: Target specification (pid, ip, path, etc.)
            parameters: Optional action parameters.

        Returns:
            ValidationResult with valid flag and any errors.
        """

    @abstractmethod
    def snapshot(self, target: Dict[str, Any], action_id: str) -> Optional[SnapshotData]:
        """Capture pre-execution state for rollback capability.

        Args:
            target: Target specification.
            action_id: The action attempt ID.

        Returns:
            SnapshotData if snapshot was captured, None if not supported.
        """

    @abstractmethod
    def execute(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None,
                snapshot: Optional[SnapshotData] = None) -> ExecutionResult:
        """Execute the action.

        MUST NOT be called without a valid approval.
        MUST NOT use shell=True.
        MUST NOT execute arbitrary commands.

        Args:
            target: Target specification.
            parameters: Optional action parameters.
            snapshot: Pre-execution snapshot (if required).

        Returns:
            ExecutionResult with success status and output.
        """

    @abstractmethod
    def verify(self, target: Dict[str, Any], execution_result: ExecutionResult) -> VerificationResult:
        """Independently verify that the action took effect.

        Does not trust the execution result alone.

        Args:
            target: Target specification.
            execution_result: Result from execute().

        Returns:
            VerificationResult with pass/fail and evidence.
        """

    @abstractmethod
    def rollback(self, target: Dict[str, Any], snapshot: SnapshotData) -> RollbackResult:
        """Rollback the action using the stored snapshot.

        Only called when rollback_supported is True.

        Args:
            target: Target specification.
            snapshot: Pre-execution snapshot.

        Returns:
            RollbackResult with success status.
        """

    @abstractmethod
    def describe(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> str:
        """Human-readable description of what this action will do.

        Args:
            target: Target specification.
            parameters: Optional action parameters.

        Returns:
            Description string.
        """
