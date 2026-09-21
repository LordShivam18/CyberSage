"""Guardian v2 Phase 4 — AI Boundary Contract.

This module documents and enforces the boundary between AI advisory
outputs and deterministic system execution.

AI MAY:
  - Summarise incidents
  - Explain detections
  - Prioritise incidents
  - Suggest response actions (as text recommendations only)
  - Generate rationale text for operator review

AI MUST NEVER directly:
  - Execute commands
  - Construct arbitrary shell commands for execution
  - Bypass approval
  - Alter RBAC
  - Modify snapshots
  - Modify audit records
  - Override deterministic policy
  - Fabricate verification success
  - Claim an action succeeded without actual execution

The deterministic PolicyEngine remains authoritative.
All AI outputs that suggest actions MUST pass through the normal
approval workflow (ApprovalManager → PolicyEngine → execution).

ENFORCEMENT:
  - AI outputs are text/dict only — never callable objects
  - AiBoundaryValidator.validate_suggestion() checks that AI output
    does not contain executable code patterns
  - The execution pathway (api_guardian_phase3.py) never accepts
    AI-generated command strings directly
"""

from __future__ import annotations

import re
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Patterns that indicate AI output contains executable content ────────
# These are heuristics only — not a security boundary. The real security
# boundary is that the execution API never accepts raw AI text.
_DANGEROUS_PATTERNS = [
    re.compile(r"subprocess\s*\.", re.IGNORECASE),
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"shell\s*=\s*True", re.IGNORECASE),
    re.compile(r"exec\s*\(", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"__import__\s*\(", re.IGNORECASE),
    re.compile(r"import\s+os\b", re.IGNORECASE),
    re.compile(r"import\s+subprocess\b", re.IGNORECASE),
]


class AiBoundaryViolation(Exception):
    """Raised when AI output violates the AI boundary contract."""


class AiBoundaryValidator:
    """Validates that AI suggestions do not contain executable content.

    This is a best-effort check to detect obvious boundary violations
    (e.g. AI accidentally generating code). It is NOT a security control —
    the real security is that AI output never enters the execution pathway.
    """

    def validate_suggestion(
        self,
        suggestion: Any,
        context: str = "",
    ) -> Tuple[bool, Optional[str]]:
        """Validate that an AI suggestion is safe to present to an operator.

        Args:
            suggestion: The AI-generated content (text, dict, etc.).
            context: Descriptive context for logging.

        Returns:
            Tuple of (is_safe, violation_reason or None).
        """
        text = str(suggestion)
        for pattern in _DANGEROUS_PATTERNS:
            if pattern.search(text):
                reason = f"AI suggestion contains potentially executable pattern: {pattern.pattern}"
                logger.warning(
                    "AiBoundaryValidator: VIOLATION in %s — %s",
                    context or "unknown", reason,
                )
                return False, reason
        return True, None

    def assert_safe(self, suggestion: Any, context: str = "") -> None:
        """Assert that an AI suggestion is safe. Raises AiBoundaryViolation if not."""
        is_safe, reason = self.validate_suggestion(suggestion, context)
        if not is_safe:
            raise AiBoundaryViolation(reason)


class AiAdvisory:
    """Container for AI advisory output.

    AI output is always advisory — never executable.
    The operator must explicitly approve any suggested action through
    the normal ApprovalManager workflow.
    """

    def __init__(
        self,
        summary: str,
        suggested_action: Optional[Dict[str, Any]] = None,
        explanation: Optional[str] = None,
        confidence: float = 0.0,
        caveats: Optional[str] = None,
    ) -> None:
        self._validator = AiBoundaryValidator()
        # Validate all AI content
        self._validator.assert_safe(summary, "AiAdvisory.summary")
        if explanation:
            self._validator.assert_safe(explanation, "AiAdvisory.explanation")
        if suggested_action:
            self._validator.assert_safe(str(suggested_action), "AiAdvisory.suggested_action")

        self.summary = summary
        self.suggested_action = suggested_action   # dict: {action_type, action_name, target} only
        self.explanation = explanation
        self.confidence = max(0.0, min(1.0, confidence))
        self.caveats = caveats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "suggested_action": self.suggested_action,
            "explanation": self.explanation,
            "confidence": self.confidence,
            "caveats": self.caveats,
            # Explicit reminder to API consumers
            "_boundary": "AI advisory only — requires operator approval before any action",
        }


# ── Module-level boundary assertions ──────────────────────────────────

def assert_ai_cannot_execute(ai_output: Any) -> None:
    """Assert at test time that AI output cannot be directly executed.

    Use this in tests to verify the AI boundary holds.
    """
    assert not callable(ai_output), "AI output must not be callable"
    if isinstance(ai_output, dict):
        assert "execute" not in ai_output, "AI output must not contain an 'execute' key"
        assert "shell" not in ai_output, "AI output must not contain a 'shell' key"
    validator = AiBoundaryValidator()
    is_safe, reason = validator.validate_suggestion(ai_output, "assert_ai_cannot_execute")
    assert is_safe, f"AI boundary violation: {reason}"
