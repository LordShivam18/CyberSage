"""BaseCollector — abstract interface for Guardian data collectors.

Design rules:
* Collectors are read-only — they gather facts but never modify system state.
* Collectors produce GuardianEvent objects, not arbitrary dicts.
* Collectors must not embed networking or backend logic.
* Clean shutdown via stop() is required.
* A single collector failure must not crash the agent.
"""

from __future__ import annotations

import abc
from typing import List

from guardian.models.event import GuardianEvent

COLLECTOR_VERSION = "2.0.0"


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

    def __enter__(self) -> BaseCollector:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
