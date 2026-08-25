"""Verification manager — independent verification of action outcomes.

Never trust process exit code alone.
Verification must produce a VerificationResult with:
- passed
- checks
- evidence
- observed_state
- failure_reason
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from guardian.actions.base import (
    ExecutionResult,
    VerificationResult,
    compute_verification_id,
)


class VerificationManager:
    """Manages independent verification of action outcomes."""

    def verify_action(
        self,
        action_id: str,
        target: Dict[str, Any],
        execution_result: ExecutionResult,
        action_verify_fn: Any,
    ) -> VerificationResult:
        """Run independent verification using the action's verify method.

        Args:
            action_id: The action attempt ID.
            target: Target specification.
            execution_result: Result from execution.
            action_verify_fn: The action's verify method.

        Returns:
            VerificationResult with pass/fail and evidence.
        """
        verification_id = compute_verification_id(action_id)

        try:
            result = action_verify_fn(target, execution_result)
            result.verification_id = verification_id
            return result
        except Exception as exc:
            return VerificationResult(
                passed=False,
                checks=[{
                    "check": "verification_exception",
                    "passed": False,
                    "detail": f"Verification raised exception: {exc}",
                }],
                evidence={"exception": str(exc)},
                observed_state={},
                failure_reason=f"Verification failed with exception: {exc}",
            )

    def build_audit_verification_result(self, v_result: VerificationResult) -> Dict[str, Any]:
        """Build audit-friendly verification result dict.

        Args:
            v_result: VerificationResult to serialize.

        Returns:
            Dict suitable for audit record storage.
        """
        return {
            "passed": v_result.passed,
            "checks": v_result.checks,
            "failure_reason": v_result.failure_reason,
            "check_count": len(v_result.checks),
            "passed_count": sum(1 for c in v_result.checks if c.get("passed")),
        }
