"""ETW provider management for Guardian v2 Windows telemetry.

This module is Windows-specific and is isolated from the rest of the
Guardian codebase via soft imports and platform checks.

Key providers:
    Microsoft-Windows-Kernel-Process  {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
        Events: CreateProcess, ProcessStop, ThreadCreate, ThreadStop (select subset)

    Microsoft-Windows-Kernel-File     {EDD08927-9CC4-4E65-B970-C2560FB5C289}
        Events: Create, Write, Delete, Rename (future extension)

Usage:
    This module is imported by ProcessMonitorCollector._EtwSessionAdapter.
    Do NOT import this module directly on Linux/CI — it will degrade gracefully
    but is designed for Windows production use.

Security:
    * No shell=True
    * No arbitrary executable invocation
    * User-space only — no kernel driver required
    * Requires SeSystemProfilePrivilege or administrator for some providers

Known limitations:
    * pywintrace/etw library must be installed separately (Windows-only dep)
    * Not all ETW event fields may be available depending on OS version
    * NOT production-validated — see docs/phase4_etw.md for limitations
"""

from __future__ import annotations

import logging
import platform
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# ETW provider GUIDs
KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
KERNEL_FILE_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
# Documented Microsoft-Windows-TCPIP provider (network connections).
# Configurable per deployment; network_monitor.py is the owning caller.
TCPIP_PROVIDER_GUID = "{2F07E2EE-15DB-40F1-90EF-9D7ABA282188}"
TCPIP_PROVIDER_NAME = "Microsoft-Windows-TCPIP"

# Availability flag — set at import time
_ETW_AVAILABLE = False
_ETW_IMPORT_ERROR: Optional[str] = None

if platform.system() == "Windows":
    try:
        import etw as _etw_module  # type: ignore[import]
        _ETW_AVAILABLE = True
    except ImportError as _e:
        _ETW_IMPORT_ERROR = str(_e)
        logger.warning(
            "guardian.collectors.etw_provider: pywintrace not installed (%s). "
            "Install pywintrace for live ETW telemetry. Degraded mode active.",
            _ETW_IMPORT_ERROR,
        )
else:
    _ETW_IMPORT_ERROR = f"non-Windows platform: {platform.system()}"
    logger.debug(
        "guardian.collectors.etw_provider: platform is %s — ETW not available",
        platform.system(),
    )


def is_available() -> bool:
    """Return True if ETW is available on this host."""
    return _ETW_AVAILABLE


def get_unavailable_reason() -> Optional[str]:
    """Return the reason ETW is unavailable, or None if available."""
    return _ETW_IMPORT_ERROR if not _ETW_AVAILABLE else None


def create_process_trace_session(
    callback: Callable[[Dict[str, Any]], None],
    session_name: str = "GuardianProcessTrace",
) -> Optional[Any]:
    """Create and return an ETW trace session for process events.

    Args:
        callback: Called for each raw normalised event dict.
        session_name: Unique ETW session name.

    Returns:
        The ETW session object, or None if ETW is unavailable.

    The returned session is NOT started — caller must call .start().

    Raises:
        RuntimeError: If ETW is available but session creation fails.
    """
    if not _ETW_AVAILABLE:
        logger.warning(
            "create_process_trace_session: ETW not available (%s). Returning None.",
            _ETW_IMPORT_ERROR,
        )
        return None

    try:
        import etw  # type: ignore[import]

        def _etw_callback(event: Any) -> None:
            """Translate pywintrace event object to normalised dict and call user callback."""
            try:
                raw: Dict[str, Any] = {}

                # Timestamp from EventHeader
                if hasattr(event, "EventHeader"):
                    ts = getattr(event.EventHeader, "TimeStamp", None)
                    if ts is not None:
                        raw["timestamp"] = ts

                # TaskName → event_type (e.g. "CreateProcess", "ProcessStop")
                if hasattr(event, "TaskName"):
                    raw["event_type"] = event.TaskName

                # Process metadata — field names vary across pywintrace versions
                _copy_attr(event, raw, "process_name", ["ProcessName", "process_name", "ImageFileName"])
                _copy_attr(event, raw, "process_id", ["ProcessId", "process_id", "pid"])
                _copy_attr(event, raw, "executable_path", ["ImageName", "image_name", "executable_path"])
                _copy_attr(event, raw, "command_line", ["CommandLine", "command_line", "cmdline"])
                _copy_attr(event, raw, "parent_process_id", ["ParentId", "parent_process_id", "ppid"])
                _copy_attr(event, raw, "user_name", ["UserName", "user_name", "username"])
                _copy_attr(event, raw, "user_sid", ["UserSID", "user_sid"])

                callback(raw)
            except Exception as exc:  # noqa: BLE001
                logger.error("etw_provider: error in ETW callback: %s", exc)

        session = etw.ETW(
            providers=[
                etw.ProviderInfo(
                    "Microsoft-Windows-Kernel-Process",
                    etw.GUID(KERNEL_PROCESS_GUID),
                )
            ],
            event_callback=_etw_callback,
            session_name=session_name,
        )
        logger.info("etw_provider: process trace session '%s' created", session_name)
        return session

    except Exception as exc:
        raise RuntimeError(f"etw_provider: failed to create trace session: {exc}") from exc


def _copy_attr(
    source: Any,
    dest: Dict[str, Any],
    dest_key: str,
    source_attrs: list,
) -> None:
    """Copy the first matching attribute from source to dest."""
    for attr in source_attrs:
        val = getattr(source, attr, None)
        if val is not None:
            dest[dest_key] = val
            return


def create_network_trace_session(
    callback: Callable[[Dict[str, Any]], None],
    session_name: str = "GuardianNetworkTrace",
    provider_guid: str = TCPIP_PROVIDER_GUID,
    provider_name: str = TCPIP_PROVIDER_NAME,
) -> Optional[Any]:
    """Create an ETW trace session for network connection events.

    Same lifecycle contract as create_process_trace_session. Returns None
    when ETW is unavailable. Raises RuntimeError when session creation
    fails on a capable host. Process attribution is attached only when
    the event source exposes it.
    """
    if not _ETW_AVAILABLE:
        logger.warning(
            "create_network_trace_session: ETW not available (%s). Returning None.",
            _ETW_IMPORT_ERROR,
        )
        return None
    try:
        import etw  # type: ignore[import]

        def _network_callback(event: Any) -> None:
            try:
                raw: Dict[str, Any] = {"provider": provider_name}
                if hasattr(event, "EventHeader"):
                    raw["timestamp"] = getattr(event.EventHeader, "TimeStamp", None)
                if hasattr(event, "TaskName"):
                    raw["event_type"] = event.TaskName
                _copy_attr(event, raw, "destination_ip", ["DestAddress", "destination_ip", "RemoteAddr"])
                _copy_attr(event, raw, "destination_port", ["DestPort", "destination_port", "RemotePort"])
                _copy_attr(event, raw, "source_ip", ["SourceAddress", "source_ip", "LocalAddr"])
                _copy_attr(event, raw, "source_port", ["SourcePort", "source_port", "LocalPort"])
                _copy_attr(event, raw, "protocol", ["Protocol", "protocol"])
                _copy_attr(event, raw, "process_id", ["ProcessId", "process_id", "pid"])
                _copy_attr(event, raw, "process_name", ["ProcessName", "process_name"])
                callback(raw)
            except Exception as exc:  # noqa: BLE001
                logger.error("etw_provider: error in network callback: %s", exc)

        session = etw.ETW(
            providers=[etw.ProviderInfo(provider_name, etw.GUID(provider_guid))],
            event_callback=_network_callback,
            session_name=session_name,
        )
        logger.info("etw_provider: network trace session '%s' created", session_name)
        return session
    except Exception as exc:
        raise RuntimeError(f"etw_provider: failed to create network session: {exc}") from exc
