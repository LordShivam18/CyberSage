"""Guardian Windows network telemetry collector.

Production-grade companion to ProcessMonitorCollector. Captures genuine
supported connection events via ETW on Windows and normalizes them into
the existing ``guardian.event.v1`` network schema.

Provider (documented, configurable):
    Microsoft-Windows-TCPIP
    GUID {2F07E2EE-15DB-40F1-90EF-9D7ABA282188}
    Events: TCP/UDP connect/accept/disconnect where exposed by the
    installed pywintrace/etw version and OS build.

Field policy (honest, no invented attribution):
  - Local/remote IP and ports, transport protocol, timestamp, host
    identity, and provider metadata are normalized when present.
  - Associated process (PID/name) is attached ONLY when the event source
    provides it or when the caller supplies a reliably correlated value.
    Otherwise the fields stay None and the evidence records
    ``process_attribution: "unavailable"``.
  - IPv4 and IPv6 are both accepted. Malformed addresses are preserved as
    raw evidence but never crash the collector.
  - Malformed events and callback exceptions are isolated per event.

Lifecycle mirrors ProcessMonitorCollector: user-space only, no driver,
bounded buffer with explicit drop accounting, degraded health when ETW
is unavailable, reconnect with exponential back-off, graceful shutdown.
"""

from __future__ import annotations

import ipaddress
import logging
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

_DEFAULT_MAX_QUEUE = 10_000
_BACKPRESSURE_WARN_PCT = 0.80

_RECONNECT_BASE_DELAY = 1.0
_RECONNECT_MAX_DELAY = 60.0
_RECONNECT_BACKOFF = 2.0

# Documented Microsoft-Windows-TCPIP provider GUID. Configurable via
# AgentConfig.etw_network_provider_guid for OS builds that differ.
DEFAULT_TCPIP_PROVIDER_GUID = "{2F07E2EE-15DB-40F1-90EF-9D7ABA282188}"
DEFAULT_TCPIP_PROVIDER_NAME = "Microsoft-Windows-TCPIP"


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
        except (ValueError, OSError):
            return None
    return None


def _clean_ip(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _clean_port(value: Any) -> Optional[int]:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def normalize_network_event(
    raw: Dict[str, Any],
    *,
    host_id: str,
    host_hostname: str,
    agent_version: str,
) -> GuardianEvent:
    """Normalize a raw network event dict into a GuardianEvent.

    Deterministic and testable without Windows. Missing fields become None;
    process attribution is never invented.
    """
    timestamp = _parse_timestamp(raw.get("timestamp"))
    destination_ip = _clean_ip(raw.get("destination_ip") or raw.get("remote_ip"))
    source_ip = _clean_ip(raw.get("source_ip") or raw.get("local_ip"))
    destination_port = _clean_port(raw.get("destination_port") or raw.get("remote_port"))
    source_port = _clean_port(raw.get("source_port") or raw.get("local_port"))
    protocol = raw.get("protocol")
    if isinstance(protocol, str):
        protocol = protocol.upper() or None
    else:
        protocol = None

    process_pid = raw.get("process_id") or raw.get("pid")
    try:
        process_pid = int(process_pid) if process_pid is not None else None
    except (TypeError, ValueError):
        process_pid = None
    process_name = raw.get("process_name")
    if not isinstance(process_name, str) or not process_name:
        process_name = None
        if process_pid is None:
            attribution = "unavailable"
        else:
            attribution = "pid_only"
    else:
        attribution = "provided" if process_pid is not None else "name_only"

    return create_guardian_event(
        host_id=host_id,
        host_hostname=host_hostname,
        agent_version=agent_version,
        event_category="network",
        timestamp=timestamp,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        process_name=process_name,
        process_pid=process_pid,
        evidence={
            "event_type": raw.get("event_type", "unknown"),
            "provider": raw.get("provider", DEFAULT_TCPIP_PROVIDER_NAME),
            "process_attribution": attribution,
        },
        raw_event=raw,
    )


class _NetworkEtwSessionAdapter:
    """Soft-import adapter for the TCPIP ETW provider (Windows only)."""

    def __init__(self, callback, *, provider_guid: str = DEFAULT_TCPIP_PROVIDER_GUID,
                 provider_name: str = DEFAULT_TCPIP_PROVIDER_NAME,
                 session_name: str = "GuardianNetworkTrace") -> None:
        self._callback = callback
        self._provider_guid = provider_guid
        self._provider_name = provider_name
        self._session_name = session_name
        self._session = None
        self._available = False
        self._try_import()

    def _try_import(self) -> None:
        if platform.system() != "Windows":
            return
        try:
            import etw  # type: ignore[import]  # noqa: F401
            self._available = True
        except ImportError:
            logger.warning(
                "_NetworkEtwSessionAdapter: pywintrace/etw not installed — "
                "no live network events."
            )

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> None:
        if not self._available:
            return
        try:
            import etw  # type: ignore[import]

            self._session = etw.ETW(
                providers=[etw.ProviderInfo(self._provider_name, etw.GUID(self._provider_guid))],
                event_callback=self._on_event,
                session_name=self._session_name,
            )
            self._session.start()
            logger.info("_NetworkEtwSessionAdapter: session '%s' started", self._session_name)
        except Exception as exc:
            logger.error("_NetworkEtwSessionAdapter: failed to start: %s", exc)
            self._session = None
            raise

    def stop(self) -> None:
        if self._session is not None:
            try:
                self._session.stop()
            except Exception as exc:
                logger.error("_NetworkEtwSessionAdapter: error stopping: %s", exc)
            finally:
                self._session = None

    def _on_event(self, event: Any) -> None:
        try:
            raw: Dict[str, Any] = {"provider": self._provider_name}
            if hasattr(event, "EventHeader"):
                raw["timestamp"] = getattr(event.EventHeader, "TimeStamp", None)
            if hasattr(event, "TaskName"):
                raw["event_type"] = event.TaskName
            for dest, names in (
                ("destination_ip", ["DestAddress", "destination_ip", "RemoteAddr", "remote_ip"]),
                ("destination_port", ["DestPort", "destination_port", "RemotePort", "remote_port"]),
                ("source_ip", ["SourceAddress", "source_ip", "LocalAddr", "local_ip"]),
                ("source_port", ["SourcePort", "source_port", "LocalPort", "local_port"]),
                ("protocol", ["Protocol", "protocol"]),
                ("process_id", ["ProcessId", "process_id", "pid", "PID"]),
                ("process_name", ["ProcessName", "process_name", "ImageFileName"]),
            ):
                for attr in names:
                    if hasattr(event, attr):
                        raw[dest] = getattr(event, attr)
                        break
            self._callback(raw)
        except Exception as exc:
            logger.error("_NetworkEtwSessionAdapter: error processing event: %s", exc)


class NetworkMonitorCollector(BaseCollector):
    """Windows network connection event collector (user-space, no driver)."""

    def __init__(
        self,
        host_id: str = "",
        host_hostname: str = "",
        agent_version: str = "",
        max_queue_size: int = _DEFAULT_MAX_QUEUE,
        provider_guid: str = DEFAULT_TCPIP_PROVIDER_GUID,
        provider_name: str = DEFAULT_TCPIP_PROVIDER_NAME,
    ) -> None:
        self._host_id = host_id
        self._hostname = host_hostname or platform.node()
        self._agent_version = agent_version
        self._max_queue = max_queue_size
        self._provider_guid = provider_guid
        self._provider_name = provider_name
        self._health = CollectorHealth.STOPPED
        self._health_lock = threading.Lock()
        self._pending: deque = deque(maxlen=max_queue_size)
        self._pending_lock = threading.Lock()
        self._etw: Optional[_NetworkEtwSessionAdapter] = None
        self._reconnect_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._events_received = 0
        self._events_dropped = 0
        self._reconnect_count = 0
        self._last_event_at: Optional[datetime] = None
        self._running = False
        self._stats_lock = threading.Lock()

    @property
    def collector_type(self) -> str:
        return "network_monitor"

    def _set_health(self, health: CollectorHealth) -> None:
        with self._health_lock:
            prev = self._health
            self._health = health
        if prev != health:
            logger.info("NetworkMonitorCollector: health %s → %s", prev.value, health.value)

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
                "last_event_at": self._last_event_at.isoformat() if self._last_event_at else None,
                "etw_available": self._etw.available if self._etw else False,
                "provider": self._provider_name,
            }

    def start(self) -> None:
        self._running = True
        self._set_health(CollectorHealth.STARTING)
        self._stop_event.clear()
        self._etw = _NetworkEtwSessionAdapter(
            callback=self._on_etw_event,
            provider_guid=self._provider_guid,
            provider_name=self._provider_name,
        )
        if not self._etw.available:
            logger.warning("NetworkMonitorCollector: ETW unavailable — DEGRADED mode.")
            self._set_health(CollectorHealth.DEGRADED)
            return
        try:
            self._etw.start()
            self._set_health(CollectorHealth.RUNNING)
        except Exception as exc:
            logger.error("NetworkMonitorCollector: ETW start failed: %s", exc)
            self._set_health(CollectorHealth.DEGRADED)
            self._schedule_reconnect()

    def _schedule_reconnect(self, delay: float = _RECONNECT_BASE_DELAY) -> None:
        if self._stop_event.is_set():
            return

        def _worker() -> None:
            current = delay
            while not self._stop_event.is_set():
                self._stop_event.wait(current)
                if self._stop_event.is_set():
                    return
                try:
                    if self._etw is not None:
                        self._etw.stop()
                    self._etw = _NetworkEtwSessionAdapter(callback=self._on_etw_event)
                    if self._etw.available:
                        self._etw.start()
                        with self._stats_lock:
                            self._reconnect_count += 1
                        self._set_health(CollectorHealth.RUNNING)
                        return
                    self._set_health(CollectorHealth.DEGRADED)
                    return
                except Exception as exc:
                    logger.warning("NetworkMonitorCollector: reconnect failed: %s", exc)
                    current = min(current * _RECONNECT_BACKOFF, _RECONNECT_MAX_DELAY)

        self._reconnect_thread = threading.Thread(target=_worker, name="guardian-net-reconnect", daemon=True)
        self._reconnect_thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._etw is not None:
            self._etw.stop()
            self._etw = None
        if self._reconnect_thread is not None and self._reconnect_thread.is_alive():
            self._reconnect_thread.join(timeout=5.0)
            self._reconnect_thread = None
        self._set_health(CollectorHealth.STOPPED)

    def collect(self) -> List[GuardianEvent]:
        try:
            with self._pending_lock:
                events = list(self._pending)
                self._pending.clear()
            return events
        except Exception as exc:  # noqa: BLE001
            logger.error("NetworkMonitorCollector.collect(): %s", exc)
            return []

    def _on_etw_event(self, raw: Dict[str, Any]) -> None:
        try:
            event = normalize_network_event(
                raw, host_id=self._host_id, host_hostname=self._hostname,
                agent_version=self._agent_version,
            )
            with self._pending_lock:
                was_full = len(self._pending) >= self._max_queue
                self._pending.append(event)
            with self._stats_lock:
                self._events_received += 1
                if was_full:
                    self._events_dropped += 1
                self._last_event_at = datetime.now(timezone.utc).replace(tzinfo=None)
        except Exception as exc:
            logger.error("NetworkMonitorCollector: normalize failed: %s", exc)

    def inject_event(self, raw: Dict[str, Any]) -> None:
        """Inject a raw dict for unit/harness use (not a production path)."""
        self._on_etw_event(raw)
