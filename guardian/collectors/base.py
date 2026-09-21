"""BaseCollector — abstract interface for Guardian data collectors.

Design rules:
* Collectors are read-only — they gather facts but never modify system state.
* Collectors produce GuardianEvent objects, not arbitrary dicts.
* Collectors must not embed networking or backend logic.
* Clean shutdown via stop() is required.
* A single collector failure must not crash the agent.
* Collector health state is observable via get_health().
"""

from __future__ import annotations

import abc
import enum
from typing import Any, Dict, List

from guardian.models.event import GuardianEvent

COLLECTOR_VERSION = "2.0.0"


class CollectorHealth(str, enum.Enum):
    """Observable health states for a collector.

    Transitions:
        STARTING  → RUNNING | DEGRADED | STOPPED
        RUNNING   → DEGRADED | STOPPED
        DEGRADED  → RUNNING (on reconnect) | STOPPED
        STOPPED   → STARTING (on restart)
        FAILED    → STOPPED (terminal — requires explicit restart)
    """

    STARTING = "starting"   # Initialisation in progress
    RUNNING = "running"     # Collecting live events
    DEGRADED = "degraded"   # OS facility unavailable; using fallback / empty
    STOPPED = "stopped"     # Gracefully stopped
    FAILED = "failed"       # Unrecoverable error; no events collected


class BaseCollector(abc.ABC):
    """Abstract base class for all Guardian collectors."""

    @property
    @abc.abstractmethod
    def collector_type(self) -> str:
        """Unique collector identifier, e.g. 'process_monitor'."""

    @abc.abstractmethod
    def start(self) -> None:
        """Start collecting events. Called once during agent startup.

        Must be safe to call even if the underlying OS facility is
        unavailable — log a warning and remain in a degraded state
        rather than raising.
        """

    @abc.abstractmethod
    def stop(self) -> None:
        """Stop collecting events. Called during agent shutdown.

        Must release OS resources, close handles, and join threads.
        Must be safe to call multiple times.
        """

    @abc.abstractmethod
    def collect(self) -> List[GuardianEvent]:
        """Return any events collected since the last call.

        Returns an empty list if no new events are available.
        Must never raise — return an empty list on internal error.
        """

    @abc.abstractmethod
    def get_health(self) -> CollectorHealth:
        """Return the current health state of this collector.

        Must never raise.
        """

    def get_stats(self) -> Dict[str, Any]:
        """Return observable runtime statistics for this collector.

        Subclasses should override to provide richer detail.
        Guaranteed not to raise.
        """
        return {
            "collector_type": self.collector_type,
            "health": self.get_health().value,
        }

    def __enter__(self) -> BaseCollector:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
