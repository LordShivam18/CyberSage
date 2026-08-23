"""
Abstract Collector interface.

A Collector gathers raw facts from the operating system.
It must never evaluate those facts or create Findings — that is the
responsibility of SecurityCheck implementations.

Safety contract
---------------
* Collectors are read-only.  They must not write files, modify registry
  keys, change system configuration, terminate processes, or make network
  requests to remote hosts.
* Collectors must not collect passwords, credentials, hashes, tokens,
  private keys, browser cookies, clipboard contents, or document contents.
* Every OS call must go through ``platform_abstraction`` so that tests can
  provide mock data without requiring Windows.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any

from ..models import CollectorResult

from .. import __version__


COLLECTOR_VERSION = __version__


class Collector(abc.ABC):
    """Abstract base class for all data collectors."""

    #: Short machine-readable name, e.g. ``"os_info"``.
    name: str

    #: Human-readable description of what this collector gathers.
    description: str

    #: Set to True if this collector requires administrator privileges for
    #: full results.  Collectors must degrade gracefully when not elevated.
    requires_admin: bool = False

    def collect(self) -> CollectorResult:
        """
        Gather facts and return a CollectorResult.

        Must not raise exceptions — errors are captured in CollectorResult.errors.
        Must not perform remediation or system changes.
        """
        started = datetime.now(timezone.utc).isoformat()
        errors: list[str] = []
        permission_denied = False
        data: dict[str, Any] = {}

        try:
            data, errors, permission_denied = self._collect_impl()
        except PermissionError as exc:
            errors.append(f"PermissionError: {exc}")
            permission_denied = True
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{type(exc).__name__}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            collector_version=COLLECTOR_VERSION,
            collected_at=started,
            data=data,
            errors=errors,
            permission_denied=permission_denied,
        )

    @abc.abstractmethod
    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        """
        Perform collection.

        Returns
        -------
        (data, errors, permission_denied)
        """


class CollectorRegistry:
    """Simple ordered registry of collector instances."""

    def __init__(self) -> None:
        self._collectors: list[Collector] = []

    def register(self, collector: Collector) -> None:
        self._collectors.append(collector)

    def all(self) -> list[Collector]:
        return list(self._collectors)
