"""Guardian v2 Phase 4 — Safety controls package.

All safety controls fail closed — if a control cannot be evaluated,
the action is blocked.
"""
from guardian.safety.kill_switch import KillSwitch, KillSwitchScope
from guardian.safety.circuit_breaker import CircuitBreaker, CircuitBreakerState
from guardian.safety.rate_limiter import ActionRateLimiter

__all__ = [
    "KillSwitch",
    "KillSwitchScope",
    "CircuitBreaker",
    "CircuitBreakerState",
    "ActionRateLimiter",
]
