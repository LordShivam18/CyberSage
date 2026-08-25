"""Rollback manager — deterministic rollback on verified failure.

Rollback only where deterministic rollback is possible.
States: not_supported | available | requested | running | succeeded | failed
A failed verification MUST NOT automatically launch arbitrary rollback logic.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from guardian.actions.base import (
    BaseAction,
    RollbackResult,
    RollbackStatus,
    SnapshotData,
    VerificationResult,
    compute_rollback_id,
)

logger = logging.getLogger(__name__)


class RollbackManager:
    """Manages rollback operations for failed actions."""

    def is_rollback_needed(self, verification_result: VerificationResult, action: BaseAction) -> bool:
        """Determine if rollback is needed.

        Args:
            verification_result: The verification result.
            action: The action that was executed.

        Returns:
            True if rollback should be offered.
        """
        if not action.rollback_supported:
            return False
        if verification_result.passed:
            return False
        return True

    def request_rollback(
        self,
        action: BaseAction,
        target: Dict[str, Any],
        snapshot: Optional[SnapshotData],
    ) -> RollbackResult:
        """Execute rollback for a failed action.

        Args:
            action: The action to rollback.
            target: Target specification.
            snapshot: Pre-execution snapshot.

        Returns:
            RollbackResult with success status.
        """
        if not action.rollback_supported:
            return RollbackResult(
                success=False,
                error="Rollback not supported for this action type",
            )

        if snapshot is None:
            return RollbackResult(
                success=False,
                error="No snapshot available for rollback",
            )

        rollback_id = compute_rollback_id(snapshot.action_id)
        logger.info("Executing rollback %s for action %s", rollback_id, snapshot.action_id)

        try:
            result = action.rollback(target, snapshot)
            logger.info(
                "Rollback %s %s",
                rollback_id,
                "succeeded" if result.success else "failed",
            )
            return result
        except Exception as exc:
            logger.error("Rollback %s raised exception: %s", rollback_id, exc)
            return RollbackResult(
                success=False,
                error=f"Rollback raised exception: {exc}",
            )
