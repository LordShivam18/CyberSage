"""Windows process event collector for Guardian v2.

IMPLEMENTATION STATUS:
    * Normalisation layer — COMPLETE and testable without Windows.
    * ETW integration — INTERFACE DEFINED; live session requires Windows + pywintrace.
      The ETW session is isolated behind _EtwSessionAdapter which soft-imports pywintrace.
      On Linux/CI the collector silently degrades to DEGRADED health; inject_event() works.

Design:
    * Runs in user space — no kernel driver required.
    * Normalises raw ETW events into GuardianEvent objects.
    * Bounded event queue with configurable max-size and backpressure.
    * Gracefully handles access-denied / unavailable metadata.
    * Deterministic normalisation layer enables testing without live Windows.
    * A single process metadata read failure does not crash the agent.
    * Collector health state is observable via get_health().
    * Reconnect/restart with exponential back-off.

This collector does NOT claim full EDR visibility. It provides
process lifecycle telemetry suitable for Guardian v2 detection.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import queue
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from guardian.collectors.base import BaseCollector, CollectorHealth, COLLECTOR_VERSION
from guardian.models.event import GuardianEvent, create_guardian_event

logger = logging.getLogger(__name__)

# ── Bounded queue configuration ────────────────────────────────────────
_DEFAULT_MAX_QUEUE = 10_000   # Events buffered before back-pressure kicks in
_BACKPRESSURE_WARN_PCT = 0.80  # Warn when queue reaches 80 % capacity

# ── ETW reconnect configuration ───────────────────────────────────────
_ETW_RECONNECT_BASE_DELAY = 1.0   # seconds
_ETW_RECONNECT_MAX_DELAY = 60.0   # seconds
_ETW_RECONNECT_BACKOFF = 2.0      # exponential factor

# Microsoft-Windows-Kernel-Process ETW provider GUID
_ETW_KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"


# ── File hashing ───────────────────────────────────────────────────────


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


# ── Normalisation ──────────────────────────────────────────────────────


def normalize_process_event(
    raw: Dict[str, Any],
    *,
    host_id: str,
    host_hostname: str,
    agent_version: str,
    event_category: str = "process",
) -> GuardianEvent:
    """Normalize a raw process event dict into a GuardianEvent.

    This is the deterministic, testable normalisation layer.
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


# ── ETW session adapter ────────────────────────────────────────────────


class _EtwSessionAdapter:
    """Thin adapter around pywintrace / etw for process events.

    Soft-imports pywintrace — if unavailable (Linux/CI), operates in
    NO-OP mode so the collector can still be tested via inject_event().

    No shell=True, no arbitrary executable invocation.
    """

    def __init__(self, callback) -> None:
        self._callback = callback
        self._session = None
        self._available = False
        self._try_import()

    def _try_import(self) -> None:
        if platform.system() != "Windows":
            logger.debug("_EtwSessionAdapter: non-Windows platform — ETW unavailable")
            return
        try:
            import etw  # type: ignore[import]  # noqa: F401  (soft import)
            self._available = True
            logger.debug("_EtwSessionAdapter: pywintrace/etw available")
        except ImportError:
            logger.warning(
                "_EtwSessionAdapter: pywintrace/etw not installed — "
                "no live ETW events. Install pywintrace for production use."
            )

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> None:
        """Start the ETW trace session."""
        if not self._available:
            return
        try:
            import etw  # type: ignore[import]
            # Microsoft-Windows-Kernel-Process provider
            self._session = etw.ETW(
                providers=[etw.ProviderInfo("Microsoft-Windows-Kernel-Process",
                                            etw.GUID(_ETW_KERNEL_PROCESS_GUID))],
                event_callback=self._on_event,
            )
            self._session.start()
            logger.info("_EtwSessionAdapter: ETW trace session started")
        except Exception as exc:
            logger.error("_EtwSessionAdapter: failed to start ETW session: %s", exc)
            self._session = None
            raise

    def stop(self) -> None:
        """Stop the ETW trace session."""
        if self._session is not None:
            try:
                self._session.stop()
                logger.info("_EtwSessionAdapter: ETW trace session stopped")
            except Exception as exc:
                logger.error("_EtwSessionAdapter: error stopping ETW session: %s", exc)
            finally:
                self._session = None

    def _on_event(self, event: Any) -> None:
        """ETW callback — convert raw event to dict and forward to collector callback."""
        try:
            raw: Dict[str, Any] = {}
            if hasattr(event, "EventHeader"):
                hdr = event.EventHeader
                raw["timestamp"] = getattr(hdr, "TimeStamp", None)
            if hasattr(event, "TaskName"):
                raw["event_type"] = event.TaskName
            for attr in ("ProcessName", "process_name"):
                if hasattr(event, attr):
                    raw["process_name"] = getattr(event, attr)
                    break
            for attr in ("ProcessId", "process_id", "pid"):
                if hasattr(event, attr):
                    raw["process_id"] = getattr(event, attr)
                    break
            for attr in ("ImageName", "image_name", "executable_path"):
                if hasattr(event, attr):
                    raw["executable_path"] = getattr(event, attr)
                    break
            for attr in ("CommandLine", "command_line", "cmdline"):
                if hasattr(event, attr):
                    raw["command_line"] = getattr(event, attr)
                    break
            for attr in ("ParentId", "parent_process_id", "ppid"):
                if hasattr(event, attr):
                    raw["parent_process_id"] = getattr(event, attr)
                    break
            self._callback(raw)
        except Exception as exc:
            logger.error("_EtwSessionAdapter: error processing ETW event: %s", exc)


# ── ProcessMonitorCollector ────────────────────────────────────────────


class ProcessMonitorCollector(BaseCollector):
    """Windows process lifecycle event collector.

    Uses ETW via the Microsoft-Windows-Kernel-Process provider
    for user-space process creation/termination events.

    On non-Windows platforms (or when pywintrace is absent),
    operates in DEGRADED health — no live events, but inject_event()
    and normalize_process_event() continue to work for testing.

    Thread-safe. Bounded queue with configurable max size.
    Reconnects automatically on ETW session failure.
    """

    def __init__(
        self,
        host_id: str = "",
        host_hostname: str = "",
        agent_version: str = "",
        max_queue_size: int = _DEFAULT_MAX_QUEUE,
    ) -> None:
        self._host_id = host_id
        self._hostname = host_hostname or platform.node()
        self._agent_version = agent_version
        self._max_queue = max_queue_size

        self._health = CollectorHealth.STOPPED
        self._health_lock = threading.Lock()

        # Bounded deque — acts as the event buffer with O(1) append/pop
        self._pending: deque = deque(maxlen=max_queue_size)
        self._pending_lock = threading.Lock()

        self._etw: Optional[_EtwSessionAdapter] = None
        self._reconnect_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self._events_received: int = 0
        self._events_dropped: int = 0
        self._reconnect_count: int = 0
        self._last_event_at: Optional[datetime] = None
        self._running: bool = False
        self._stats_lock = threading.Lock()

    @property
    def collector_type(self) -> str:
        return "process_monitor"

    # ── Health ─────────────────────────────────────────────────────────

    def _set_health(self, health: CollectorHealth) -> None:
        with self._health_lock:
            prev = self._health
            self._health = health
        if prev != health:
            logger.info(
                "ProcessMonitorCollector: health %s → %s",
                prev.value, health.value,
            )

    def get_health(self) -> CollectorHealth:
        with self._health_lock:
            return self._health

    def get_stats(self) -> Dict[str, Any]:
        with self._stats_lock:
            return {
                "collector_type": self.collector_type,
                "health": self.get_health().value,
                "max_queue_size": self._max_queue,
                "queue_used": len(self._pending),
                "events_received": self._events_received,
                "events_dropped": self._events_dropped,
                "reconnect_count": self._reconnect_count,
                "last_event_at": (
                    self._last_event_at.isoformat() if self._last_event_at else None
                ),
                "etw_available": self._etw.available if self._etw else False,
            }

    # ── Lifecycle ──────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the ETW process monitoring session."""
        self._running = True
        self._set_health(CollectorHealth.STARTING)
        self._stop_event.clear()
        self._etw = _EtwSessionAdapter(callback=self._on_etw_event)

        if not self._etw.available:
            logger.warning(
                "ProcessMonitorCollector: ETW not available on this platform/install. "
                "Operating in DEGRADED mode — no live events."
            )
            self._set_health(CollectorHealth.DEGRADED)
            return

        self._try_start_etw()

    def _try_start_etw(self) -> None:
        """Attempt to start the ETW session; schedule reconnect on failure."""
        try:
            assert self._etw is not None
            self._etw.start()
            self._set_health(CollectorHealth.RUNNING)
        except Exception as exc:
            logger.error(
                "ProcessMonitorCollector: ETW session failed: %s. "
                "Scheduling reconnect.",
                exc,
            )
            self._set_health(CollectorHealth.DEGRADED)
            self._schedule_reconnect()

    def _schedule_reconnect(self, delay: float = _ETW_RECONNECT_BASE_DELAY) -> None:
        """Start a background thread that reconnects after `delay` seconds."""
        if self._stop_event.is_set():
            return

        def _reconnect_worker() -> None:
            attempt = 1
            current_delay = delay
            while not self._stop_event.is_set():
                logger.info(
                    "ProcessMonitorCollector: reconnect attempt %d in %.1fs",
                    attempt, current_delay,
                )
                self._stop_event.wait(current_delay)
                if self._stop_event.is_set():
                    return
                try:
                    if self._etw is not None:
                        self._etw.stop()
                    self._etw = _EtwSessionAdapter(callback=self._on_etw_event)
                    if self._etw.available:
                        self._etw.start()
                        with self._stats_lock:
                            self._reconnect_count += 1
                        self._set_health(CollectorHealth.RUNNING)
                        logger.info("ProcessMonitorCollector: reconnected after %d attempt(s)", attempt)
                        return
                    else:
                        self._set_health(CollectorHealth.DEGRADED)
                        return
                except Exception as exc:
                    logger.warning("ProcessMonitorCollector: reconnect %d failed: %s", attempt, exc)
                    current_delay = min(current_delay * _ETW_RECONNECT_BACKOFF, _ETW_RECONNECT_MAX_DELAY)
                    attempt += 1

        self._reconnect_thread = threading.Thread(
            target=_reconnect_worker,
            name="guardian-etw-reconnect",
            daemon=True,
        )
        self._reconnect_thread.start()

    def stop(self) -> None:
        """Stop the ETW session and release resources."""
        self._running = False
        self._stop_event.set()

        if self._etw is not None:
            self._etw.stop()
            self._etw = None

        if self._reconnect_thread is not None and self._reconnect_thread.is_alive():
            self._reconnect_thread.join(timeout=5.0)
            self._reconnect_thread = None

        self._set_health(CollectorHealth.STOPPED)
        logger.info("ProcessMonitorCollector: stopped.")

    # ── Event collection ───────────────────────────────────────────────

    def collect(self) -> List[GuardianEvent]:
        """Return process events collected since the last call.

        Drains the bounded buffer. Thread-safe.
        Returns an empty list on any internal error.
        """
        try:
            with self._pending_lock:
                events = list(self._pending)
                self._pending.clear()
            return events
        except Exception as exc:  # noqa: BLE001
            logger.error("ProcessMonitorCollector.collect(): unexpected error: %s", exc)
            return []

    def _on_etw_event(self, raw: Dict[str, Any]) -> None:
        """Internal ETW callback — normalise and buffer the event.

        Back-pressure: if the queue is full (deque maxlen), the oldest
        event is silently evicted (deque behaviour). We log a warning
        when approaching capacity.
        """
        try:
            event = normalize_process_event(
                raw,
                host_id=self._host_id,
                host_hostname=self._hostname,
                agent_version=self._agent_version,
            )
            with self._pending_lock:
                current_size = len(self._pending)
                if current_size >= int(self._max_queue * _BACKPRESSURE_WARN_PCT):
                    logger.warning(
                        "ProcessMonitorCollector: queue at %d/%d (%.0f%%) — back-pressure",
                        current_size, self._max_queue,
                        100.0 * current_size / self._max_queue,
                    )
                # deque(maxlen=...) automatically evicts oldest when full
                was_full = current_size >= self._max_queue
                self._pending.append(event)

            with self._stats_lock:
                self._events_received += 1
                if was_full:
                    self._events_dropped += 1
                self._last_event_at = datetime.now(timezone.utc).replace(tzinfo=None)

        except Exception as exc:
            logger.error(
                "ProcessMonitorCollector: failed to normalize ETW event: %s", exc
            )

    # ── Test injection ─────────────────────────────────────────────────

    def inject_event(self, raw: Dict[str, Any]) -> None:
        """Inject a raw event dict for testing or manual simulation.

        This method supports both unit tests (no live Windows host) and
        the CI injectable collector mechanism. It is not a production
        code path — production events arrive via ETW callback.
        """
        self._on_etw_event(raw)

    def on_etw_event(self, raw: Dict[str, Any]) -> None:
        """Public ETW callback alias (kept for backward compatibility).

        Normalises the raw ETW data and adds it to the pending buffer.
        Errors in a single event must not crash the agent.
        """
        self._on_etw_event(raw)
