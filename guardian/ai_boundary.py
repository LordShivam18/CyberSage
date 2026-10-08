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
    # Phase 5 Slice 1 additions: remedial-tooling / shell-escape indicators.
    # Still heuristics — defense in depth only.
    re.compile(r"\bpowershell\b", re.IGNORECASE),
    re.compile(r"\bcmd\.exe\b", re.IGNORECASE),
    re.compile(r"\bnetsh\b", re.IGNORECASE),
    re.compile(r"\biptables\b", re.IGNORECASE),
    re.compile(r"\bschtasks\b", re.IGNORECASE),
    re.compile(r"\btaskkill\b", re.IGNORECASE),
    re.compile(r"\brm\s+-rf?\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+\+x\b", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"\breg\s+(add|delete|import)\b", re.IGNORECASE),
    re.compile(r"\bmimikatz\b", re.IGNORECASE),
]

# Structural keys that must never appear in AI advisory output. AI output is
# data-only; these keys would indicate an attempt to cross into execution,
# authorization, or policy control.
_FORBIDDEN_ADVISORY_KEYS = frozenset({
    "execute", "shell", "command", "command_line", "script",
    "policy", "policy_id", "approval", "approval_id", "approve",
    "kill_switch", "killswitch", "rate_limit", "rate_limiter",
    "circuit_breaker", "allowlist", "rbac", "role", "token", "password",
})

# Advisory allowlist: the only keys an AI-sourced suggested action may carry.
# Values are further validated against the registered action allowlist.
_ALLOWED_ADVISORY_ACTION_KEYS = frozenset({"action_type", "action_name", "target"})


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

    def validate_structure(self, suggestion: Any, context: str = "") -> Tuple[bool, Optional[str]]:
        """Validate that a dict-shaped suggestion carries no control keys.

        Rejects any mapping containing keys outside the advisory allowlist or
        any forbidden control key at any nesting level (one level deep for
        the ``target`` sub-object keys ``pid``/``destination_ip`` etc. are
        permitted — only control-plane keys are forbidden).
        """
        if not isinstance(suggestion, dict):
            return True, None
        for key in suggestion.keys():
            if not isinstance(key, str):
                return False, f"Non-string key in AI suggestion ({context or 'unknown'})"
            if key.lower() in _FORBIDDEN_ADVISORY_KEYS:
                reason = f"AI suggestion contains forbidden control key: {key}"
                logger.warning("AiBoundaryValidator: VIOLATION in %s — %s", context or "unknown", reason)
                return False, reason
        action = suggestion.get("suggested_action")
        if isinstance(action, dict):
            extra = set(action.keys()) - _ALLOWED_ADVISORY_ACTION_KEYS
            if extra:
                reason = f"AI suggested_action carries non-advisory keys: {sorted(extra)}"
                logger.warning("AiBoundaryValidator: VIOLATION in %s — %s", context or "unknown", reason)
                return False, reason
            for key in action.keys():
                if isinstance(key, str) and key.lower() in _FORBIDDEN_ADVISORY_KEYS:
                    reason = f"AI suggested_action contains forbidden control key: {key}"
                    logger.warning("AiBoundaryValidator: VIOLATION in %s — %s", context or "unknown", reason)
                    return False, reason
        return True, None


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
    struct_safe, struct_reason = validator.validate_structure(ai_output, "assert_ai_cannot_execute")
    assert struct_safe, f"AI boundary structural violation: {struct_reason}"


def constrain_ai_advisory(suggestion: Dict[str, Any]) -> Dict[str, Any]:
    """Convert untrusted AI output into a constrained advisory structure.

    Allowlist behavior (fail closed):
      - input must be a dict; anything else raises AiBoundaryViolation.
      - text/pattern scan via AiBoundaryValidator (raises on executable
        content); structural scan rejects control-plane keys.
      - ``suggested_action`` (if present) must contain ONLY action_type,
        action_name, and target; action_type/action_name must be registered
        in the action registry (or "*"); target must be a dict whose values
        are scalars (no nested commands).
      - confidence is clamped to [0, 1]; unknown fields are dropped, never
        passed through.

    The returned advisory is presentation-only and can never authorize,
    approve, or trigger execution.
    """
    if not isinstance(suggestion, dict):
        raise AiBoundaryViolation("AI advisory must be a dict")
    validator = AiBoundaryValidator()
    validator.assert_safe(suggestion, "constrain_ai_advisory")
    struct_safe, struct_reason = validator.validate_structure(suggestion, "constrain_ai_advisory")
    if not struct_safe:
        raise AiBoundaryViolation(struct_reason or "structural violation")

    summary = suggestion.get("summary", "")
    if not isinstance(summary, str):
        raise AiBoundaryViolation("AI advisory summary must be text")
    explanation = suggestion.get("explanation")
    if explanation is not None and not isinstance(explanation, str):
        raise AiBoundaryViolation("AI advisory explanation must be text")

    constrained_action = None
    raw_action = suggestion.get("suggested_action")
    if raw_action is not None:
        if not isinstance(raw_action, dict):
            raise AiBoundaryViolation("AI suggested_action must be an object")
        action_type = raw_action.get("action_type")
        action_name = raw_action.get("action_name")
        target = raw_action.get("target", {})
        if not isinstance(action_type, str) or not isinstance(action_name, str):
            raise AiBoundaryViolation("AI suggested_action needs string action_type/action_name")
        if not isinstance(target, dict):
            raise AiBoundaryViolation("AI suggested_action target must be an object")
        # Registry allowlist check — AI cannot invent action types.
        from guardian.actions import registry as action_registry

        known = {(a["action_type"], a["action_name"]) for a in action_registry.list_actions()}
        if action_type != "*" and action_name != "*" and (action_type, action_name) not in known:
            raise AiBoundaryViolation(
                f"AI suggested unknown action '{action_type}:{action_name}'"
            )
        # Target values must be scalars — no nested executable structures.
        for key, value in target.items():
            if isinstance(value, (dict, list)) and key not in (
                "event_ids", "evidence_ids",
            ):
                raise AiBoundaryViolation(
                    f"AI suggested_action target field '{key}' must be a scalar"
                )
            if callable(value):
                raise AiBoundaryViolation("AI target values must not be callable")
        constrained_action = {
            "action_type": action_type,
            "action_name": action_name,
            "target": {k: v for k, v in target.items() if not callable(v)},
        }

    try:
        confidence = float(suggestion.get("confidence", 0.0))
    except (TypeError, ValueError):
        raise AiBoundaryViolation("AI confidence must be numeric")
    confidence = max(0.0, min(1.0, confidence))

    return {
        "summary": summary,
        "suggested_action": constrained_action,
        "explanation": explanation if isinstance(explanation, str) else None,
        "confidence": confidence,
        "_boundary": "AI advisory only — requires operator approval before any action",
    }
