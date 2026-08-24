"""Windows process event collector for Guardian v2.

STATUS: PLACEHOLDER — not yet connected to a live ETW provider.

This module defines the collector interface and a deterministic
normalization layer. The actual ETW session startup, event callback
registration, and live event streaming are NOT implemented.

Production implementation requires:
* `etw` library or `pywintrace` for ETW consumer registration
* Microsoft-Windows-Kernel-Process provider GUID
* Real-time event callback registration
* Windows host with appropriate permissions

Design:
* Runs in user space — no kernel driver required.
* Normalizes raw ETW events into GuardianEvent objects.
* Gracefully handles access-denied / unavailable metadata.
* Deterministic normalization layer enables testing without live Windows.
* A single process metadata read failure does not crash the agent.

This collector does NOT claim full EDR visibility. It provides
process lifecycle telemetry suitable for Guardian v2 detection.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from guardian.collectors.base import BaseCollector, COLLECTOR_VERSION
from guardian.models.event import GuardianEvent, create_guardian_event

logger = logging.getLogger(__name__)


def _sha256_file(path: str) -> Optional[str]:
    """Compute SHA-256 of a file. Returns None on any error."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError, IOError):
        return None


def _safe_file_hash(path: Optional[str]) -> Optional[str]:
    """Compute file hash only for paths that exist and are readable."""
    if not path or not os.path.isfile(path):
        return None
    return _sha256_file(path)


def normalize_process_event(
    raw: Dict[str, Any],
    *,
    host_id: str,
    host_hostname: str,
    agent_version: str,
    event_category: str = "process",
) -> GuardianEvent:
    """Normalize a raw process event dict into a GuardianEvent.

    This is the deterministic, testable normalization layer.
    It can be unit-tested without a live Windows host.

    Expected raw fields (flexible — missing fields become None):
        timestamp, event_type (CreateProcess/ProcessStop),
        process_name, process_id, executable_path, command_line,
        parent_process_name, parent_process_id, parent_executable_path,
        user_name, user_sid
    """
    timestamp: Optional[datetime] = None
    ts_raw = raw.get("timestamp")
    if isinstance(ts_raw, datetime):
        timestamp = ts_raw
    elif isinstance(ts_raw, str):
        try:
            timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            timestamp = None
    elif isinstance(ts_raw, (int, float)):
        try:
            timestamp = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc).replace(tzinfo=None)
        except (ValueError, OSError):
            timestamp = None

    process_exe_path: Optional[str] = raw.get("executable_path") or raw.get("exe_path")
    file_hash = _safe_file_hash(process_exe_path)

    return create_guardian_event(
        host_id=host_id,
        host_hostname=host_hostname,
        agent_version=agent_version,
        event_category=event_category,
        timestamp=timestamp,
        process_name=raw.get("process_name"),
        process_pid=raw.get("process_id") or raw.get("pid"),
        process_exe_path=process_exe_path,
        process_exe_hash_sha256=file_hash,
        process_command_line=raw.get("command_line") or raw.get("cmdline"),
        parent_process_name=raw.get("parent_process_name"),
        parent_process_pid=raw.get("parent_process_id") or raw.get("ppid"),
        parent_process_exe_path=raw.get("parent_executable_path"),
        user_name=raw.get("user_name") or raw.get("username"),
        user_sid=raw.get("user_sid"),
        evidence={"event_type": raw.get("event_type", "unknown")},
        raw_event=raw,
    )


class ProcessMonitorCollector(BaseCollector):
    """Windows process lifecycle event collector.

    Uses ETW via the Microsoft-Windows-Kernel-Process provider
    for user-space process creation/termination events.

    On non-Windows platforms, operates in degraded mode (no live events).
    """

    def __init__(
        self,
        host_id: str = "",
        host_hostname: str = "",
        agent_version: str = "",
    ) -> None:
        self._host_id = host_id
        self._hostname = host_hostname or platform.node()
        self._agent_version = agent_version
        self._running = False
        self._lock = threading.Lock()
        self._pending: List[GuardianEvent] = []
        self._etw_session = None  # Placeholder for ETW session handle

    @property
    def collector_type(self) -> str:
        return "process_monitor"

    def start(self) -> None:
        """Start the ETW process monitoring session."""
        with self._lock:
            if self._running:
                return
            self._running = True

        if platform.system() != "Windows":
            logger.warning(
                "ProcessMonitorCollector: non-Windows platform detected; "
                "no live process events will be collected (degraded mode)."
            )
            return

        try:
            self._start_etw_session()
        except Exception as exc:
            logger.error(
                "ProcessMonitorCollector: failed to start ETW session: %s. "
                "Operating in degraded mode.",
                exc,
            )

    def _start_etw_session(self) -> None:
        """Initialize the ETW session for process events.

        PLACEHOLDER — not yet implemented.
        A production implementation would use:
        - `etw` library or `pywintrace` for ETW consumer registration
        - Microsoft-Windows-Kernel-Process provider GUID
        - Real-time event callback registration
        """
        logger.info("ProcessMonitorCollector: ETW session started (placeholder — no live events).")

    def stop(self) -> None:
        """Stop the ETW session and release resources."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._etw_session is not None:
            try:
                # Placeholder: production implementation would stop the ETW session.
                self._etw_session = None
            except Exception as exc:
                logger.error("ProcessMonitorCollector: error stopping ETW session: %s", exc)

        logger.info("ProcessMonitorCollector: stopped.")

    def collect(self) -> List[GuardianEvent]:
        """Return process events collected since the last call.

        In production, this drains the ETW callback buffer.
        For testing, events can be injected via inject_event().
        """
        with self._lock:
            events = list(self._pending)
            self._pending.clear()
        return events

    def inject_event(self, raw: Dict[str, Any]) -> None:
        """Inject a raw event dict for testing or manual simulation.

        This method is for testing only — production events arrive via ETW.
        """
        event = normalize_process_event(
            raw,
            host_id=self._host_id,
            host_hostname=self._hostname,
            agent_version=self._agent_version,
        )
        with self._lock:
            self._pending.append(event)

    def on_etw_event(self, raw: Dict[str, Any]) -> None:
        """ETW callback — called for each process event from the kernel provider.

        Normalizes the raw ETW data and adds it to the pending buffer.
        Errors in a single event must not crash the agent.
        """
        try:
            event = normalize_process_event(
                raw,
                host_id=self._host_id,
                host_hostname=self._hostname,
                agent_version=self._agent_version,
            )
            with self._lock:
                self._pending.append(event)
        except Exception as exc:
            logger.error(
                "ProcessMonitorCollector: failed to normalize ETW event: %s", exc
            )
