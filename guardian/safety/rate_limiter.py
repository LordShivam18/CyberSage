"""Guardian v2 Phase 4 — Action Rate Limiter.

Limits the rate of automated actions to prevent runaway execution.
Implements a sliding-window token-bucket per action type.

Fail closed: if the rate check raises, block.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Default global limit
_DEFAULT_MAX_ACTIONS_PER_MINUTE = 10
_DEFAULT_MAX_ACTIONS_PER_HOUR = 50


class ActionRateLimiter:
    """Sliding-window rate limiter for Guardian automated actions.

    Tracks action counts per action_type over rolling time windows.
    Exceeding any limit blocks further actions.

    Fail closed: any error → block.

    Example:
        limiter = ActionRateLimiter(max_per_minute=5, max_per_hour=20)
        ok, reason = limiter.check_and_record("process")
        if not ok:
            raise BlockedByRateLimit(reason)
    """

    def __init__(
        self,
        max_per_minute: int = _DEFAULT_MAX_ACTIONS_PER_MINUTE,
        max_per_hour: int = _DEFAULT_MAX_ACTIONS_PER_HOUR,
    ) -> None:
        self._max_per_minute = max_per_minute
        self._max_per_hour = max_per_hour
        self._lock = threading.Lock()
        # Per action_type: deque of timestamps (epoch seconds as float)
        self._minute_windows: Dict[str, deque] = defaultdict(lambda: deque())
        self._hour_windows: Dict[str, deque] = defaultdict(lambda: deque())

    def _now_ts(self) -> float:
        return datetime.now(timezone.utc).timestamp()

    def _prune(self, window: deque, cutoff: float) -> None:
        """Remove timestamps older than cutoff."""
        while window and window[0] < cutoff:
            window.popleft()

    def check_and_record(self, action_type: str) -> Tuple[bool, Optional[str]]:
        """Check if an action is within rate limits, and record it if so.

        Returns:
            (allowed: bool, reason: str | None)
        """
        try:
            with self._lock:
                now = self._now_ts()
                minute_cutoff = now - 60.0
                hour_cutoff = now - 3600.0

                minute_window = self._minute_windows[action_type]
                hour_window = self._hour_windows[action_type]

                self._prune(minute_window, minute_cutoff)
                self._prune(hour_window, hour_cutoff)

                minute_count = len(minute_window)
                hour_count = len(hour_window)

                if minute_count >= self._max_per_minute:
                    reason = (
                        f"Rate limit exceeded for '{action_type}': "
                        f"{minute_count}/{self._max_per_minute} actions in the last minute"
                    )
                    logger.warning("ActionRateLimiter: %s", reason)
                    return False, reason

                if hour_count >= self._max_per_hour:
                    reason = (
                        f"Rate limit exceeded for '{action_type}': "
                        f"{hour_count}/{self._max_per_hour} actions in the last hour"
                    )
                    logger.warning("ActionRateLimiter: %s", reason)
                    return False, reason

                # Record
                minute_window.append(now)
                hour_window.append(now)
                return True, None

        except Exception as exc:  # noqa: BLE001
            logger.error("ActionRateLimiter.check_and_record raised; failing closed: %s", exc)
            return False, f"rate_limiter_error (fail closed): {exc}"

    def check_only(self, action_type: str) -> Tuple[bool, Optional[str]]:
        """Check limits without recording. Does not consume quota."""
        try:
            with self._lock:
                now = self._now_ts()
                minute_cutoff = now - 60.0
                hour_cutoff = now - 3600.0

                minute_window = self._minute_windows[action_type]
                hour_window = self._hour_windows[action_type]

                minute_count = sum(1 for t in minute_window if t >= minute_cutoff)
                hour_count = sum(1 for t in hour_window if t >= hour_cutoff)

                if minute_count >= self._max_per_minute:
                    return False, f"Would exceed per-minute limit ({minute_count}/{self._max_per_minute})"
                if hour_count >= self._max_per_hour:
                    return False, f"Would exceed per-hour limit ({hour_count}/{self._max_per_hour})"
                return True, None
        except Exception as exc:  # noqa: BLE001
            logger.error("ActionRateLimiter.check_only raised; failing closed: %s", exc)
            return False, f"rate_limiter_error (fail closed): {exc}"

    def get_stats(self) -> dict:
        """Return current rate limiter stats per action type."""
        with self._lock:
            now = self._now_ts()
            minute_cutoff = now - 60.0
            hour_cutoff = now - 3600.0
            result = {}
            for action_type in set(list(self._minute_windows.keys()) + list(self._hour_windows.keys())):
                mw = self._minute_windows[action_type]
                hw = self._hour_windows[action_type]
                result[action_type] = {
                    "actions_last_minute": sum(1 for t in mw if t >= minute_cutoff),
                    "actions_last_hour": sum(1 for t in hw if t >= hour_cutoff),
                    "max_per_minute": self._max_per_minute,
                    "max_per_hour": self._max_per_hour,
                }
            return result

    def reset(self, action_type: Optional[str] = None) -> None:
        """Reset rate limiter state. If action_type=None, resets all."""
        with self._lock:
            if action_type:
                self._minute_windows[action_type].clear()
                self._hour_windows[action_type].clear()
            else:
                self._minute_windows.clear()
                self._hour_windows.clear()
