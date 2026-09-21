"""Guardian v2 Phase 4 — Circuit Breaker.

Blocks automated actions after a configurable number of consecutive
failures. Forces a cooling-off period before retrying.

States:
    CLOSED  — normal operation (circuit allows actions)
    OPEN    — blocked (circuit tripped after too many failures)
    HALF_OPEN — testing recovery (one action allowed through)

Fail closed: if state cannot be determined, treat as OPEN (blocked).
"""

from __future__ import annotations

import enum
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class CircuitBreakerState(str, enum.Enum):
    CLOSED = "closed"       # Normal — actions permitted
    OPEN = "open"           # Tripped — actions blocked
    HALF_OPEN = "half_open"  # Recovery probe — one action allowed


class CircuitBreaker:
    """Thread-safe circuit breaker for Guardian automated actions.

    Example:
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=60)
        cb.record_failure("action-123")
        cb.record_failure("action-124")
        cb.record_failure("action-125")
        assert cb.is_open()  # Tripped after 3 failures
        assert not cb.allow_action()  # Blocked

        # After recovery_timeout, allow one probe
        # If probe succeeds → CLOSED
        # If probe fails → OPEN again
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_seconds: int = 300,
        action_type: str = "global",
    ) -> None:
        self._threshold = failure_threshold
        self._recovery_timeout = timedelta(seconds=recovery_timeout_seconds)
        self._action_type = action_type

        self._lock = threading.Lock()
        self._state = CircuitBreakerState.CLOSED
        self._consecutive_failures = 0
        self._last_failure_at: Optional[datetime] = None
        self._trip_count = 0

    def _now(self) -> datetime:
        return datetime.now(timezone.utc).replace(tzinfo=None)

    @property
    def state(self) -> CircuitBreakerState:
        with self._lock:
            return self._evaluate_state()

    def _evaluate_state(self) -> CircuitBreakerState:
        """Internal state evaluation (must be called with lock held)."""
        if self._state == CircuitBreakerState.OPEN:
            if self._last_failure_at and (
                self._now() - self._last_failure_at >= self._recovery_timeout
            ):
                # Transition to HALF_OPEN for recovery probe
                self._state = CircuitBreakerState.HALF_OPEN
                logger.info(
                    "CircuitBreaker[%s]: OPEN → HALF_OPEN (recovery probe)",
                    self._action_type,
                )
        return self._state

    def allow_action(self) -> bool:
        """Return True if an action is allowed to proceed.

        CLOSED → True (always allowed)
        HALF_OPEN → True (one probe allowed; caller must record success/failure)
        OPEN → False (blocked — fail closed)
        """
        try:
            with self._lock:
                state = self._evaluate_state()
                if state == CircuitBreakerState.CLOSED:
                    return True
                if state == CircuitBreakerState.HALF_OPEN:
                    return True  # Allow one probe
                return False  # OPEN — blocked
        except Exception as exc:  # noqa: BLE001
            logger.error("CircuitBreaker.allow_action raised; failing closed: %s", exc)
            return False

    def is_open(self) -> bool:
        """Return True if the circuit is open (blocking actions)."""
        return self.state == CircuitBreakerState.OPEN

    def record_success(self, action_id: str = "") -> None:
        """Record a successful action — may reset the circuit to CLOSED."""
        with self._lock:
            prev_state = self._state
            self._consecutive_failures = 0
            if self._state in (CircuitBreakerState.OPEN, CircuitBreakerState.HALF_OPEN):
                self._state = CircuitBreakerState.CLOSED
                logger.info(
                    "CircuitBreaker[%s]: %s → CLOSED after success (action %s)",
                    self._action_type, prev_state.value, action_id,
                )

    def record_failure(self, action_id: str = "") -> None:
        """Record a failed action — may trip the circuit to OPEN."""
        with self._lock:
            self._consecutive_failures += 1
            self._last_failure_at = self._now()

            if self._consecutive_failures >= self._threshold:
                prev_state = self._state
                self._state = CircuitBreakerState.OPEN
                self._trip_count += 1
                logger.warning(
                    "CircuitBreaker[%s]: %s → OPEN after %d consecutive failures "
                    "(trip #%d, action %s)",
                    self._action_type, prev_state.value,
                    self._consecutive_failures, self._trip_count, action_id,
                )

    def reset(self, by: str = "operator") -> None:
        """Manually reset the circuit to CLOSED (operator override)."""
        with self._lock:
            prev_state = self._state
            self._state = CircuitBreakerState.CLOSED
            self._consecutive_failures = 0
            self._last_failure_at = None
            logger.info(
                "CircuitBreaker[%s]: %s → CLOSED (manual reset by %s)",
                self._action_type, prev_state.value, by,
            )

    def get_stats(self) -> dict:
        """Return observable circuit breaker state."""
        with self._lock:
            return {
                "action_type": self._action_type,
                "state": self._state.value,
                "consecutive_failures": self._consecutive_failures,
                "failure_threshold": self._threshold,
                "recovery_timeout_seconds": int(self._recovery_timeout.total_seconds()),
                "last_failure_at": (
                    self._last_failure_at.isoformat() if self._last_failure_at else None
                ),
                "trip_count": self._trip_count,
            }
