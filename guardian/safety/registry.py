"""Guardian v2 Phase 5 Slice 2 — process-wide breaker + limiter registries.

The safety envelope needs stable, shared :class:`CircuitBreaker` (one per
action type) and :class:`ActionRateLimiter` (execution path) instances.
This module owns them behind tiny accessors so the envelope, the Phase 3
execute path, and tests all observe the same state.

Thread-safety: both wrapped classes are internally locked; the registry
dict itself is guarded here. ``reset_safety_state()`` is test-only.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional

from guardian.safety.circuit_breaker import CircuitBreaker
from guardian.safety.rate_limiter import ActionRateLimiter

logger = logging.getLogger(__name__)

_lock = threading.RLock()
_breakers: Dict[str, CircuitBreaker] = {}
_execution_limiter: ActionRateLimiter | None = None

# Slice 2 execution-path budgets (conservative; policy-level caps from
# PolicyRuleV5.max_executions_per_hour / cooldown_seconds apply on top).
EXEC_LIMIT_PER_MINUTE = 10
EXEC_LIMIT_PER_HOUR = 50


def get_breaker(
    action_type: str,
    failure_threshold: int = 5,
    recovery_timeout_seconds: int = 300,
) -> CircuitBreaker:
    """Return the process-wide breaker for an action type (created on demand)."""
    if not action_type or len(action_type) > 64:
        raise ValueError("action_type must be 1-64 chars")
    with _lock:
        breaker = _breakers.get(action_type)
        if breaker is None:
            breaker = CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout_seconds=recovery_timeout_seconds,
                action_type=action_type,
            )
            _breakers[action_type] = breaker
        return breaker


def get_execution_limiter() -> ActionRateLimiter:
    """Return the process-wide execution-path rate limiter."""
    global _execution_limiter
    with _lock:
        if _execution_limiter is None:
            _execution_limiter = ActionRateLimiter(
                max_per_minute=EXEC_LIMIT_PER_MINUTE,
                max_per_hour=EXEC_LIMIT_PER_HOUR,
            )
        return _execution_limiter


def breaker_stats() -> Dict[str, dict]:
    """Observable snapshot of all breakers (for safety-status reporting)."""
    with _lock:
        return {name: breaker.get_stats() for name, breaker in _breakers.items()}


def limiter_stats() -> dict:
    """Observable snapshot of the execution limiter."""
    return get_execution_limiter().get_stats()


def reset_safety_state() -> None:
    """Clear all shared safety state. TEST-ONLY — never call in production."""
    global _execution_limiter
    with _lock:
        _breakers.clear()
        _execution_limiter = None
    logger.info("safety.registry: shared state reset (test-only)")
