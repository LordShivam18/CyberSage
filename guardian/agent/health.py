"""Agent health snapshot builder (uses existing components, redacts secrets).

Liveness = process running. Readiness = config valid + queue writable +
recent successful backend contact (or explicit offline-degraded note).
Degraded = ETW down, auth failing, or queue pressure. Fatal = config
invalid or queue unwritable. The snapshot never contains credentials,
tokens, key material, or raw event contents.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.ops.health import compose_agent_snapshot


def _disk_free_bytes(path: str) -> int:
    try:
        return shutil.disk_usage(path).free
    except Exception:  # noqa: BLE001 - disk pressure must report, not raise
        return -1


def build_agent_snapshot(*, config, identity, collectors: Optional[list] = None,
                         queue=None, sync=None, auth_ok: bool = True,
                         service_state: str = "foreground") -> Dict[str, Any]:
    """Collect health from live components without mutating them."""
    collector_stats: List[Dict[str, Any]] = []
    for collector in collectors or []:
        try:
            stats = collector.get_stats()
            collector_stats.append({"name": getattr(collector, "collector_type", "unknown"),
                                    "health": stats.get("health", "unknown"),
                                    "status": stats.get("health", "unknown"),
                                    "events_received": stats.get("events_received", 0),
                                    "events_dropped": stats.get("events_dropped", 0),
                                    "last_event_at": stats.get("last_event_at")})
        except Exception as exc:  # noqa: BLE001
            collector_stats.append({"name": "unknown", "health": "degraded",
                                    "status": "degraded", "error": str(exc)[:200]})
    queue_signals: Dict[str, Any] = {"total_active": 0, "capacity": 1, "oldest_created_at": "unknown"}
    if queue is not None:
        try:
            stats = queue.queue_stats()
            try:
                depth = queue.queue_depth_age()
            except Exception:  # noqa: BLE001
                depth = {}
            queue_signals = {"total_active": stats.get("total_active", 0),
                             "capacity": stats.get("capacity", 1),
                             "pending": stats.get("pending", 0),
                             "sending": stats.get("sending", 0),
                             "failed": stats.get("failed", 0),
                             "sent": stats.get("sent", 0),
                             "oldest_created_at": depth.get("oldest_created_at", "unknown")}
        except Exception as exc:  # noqa: BLE001
            queue_signals = {"total_active": -1, "capacity": 1,
                             "oldest_created_at": "unknown", "error": str(exc)[:200]}
    sync_signals: Dict[str, Any] = {"consecutive_failures": 0, "backoff_seconds": 0,
                                    "last_success_at": "never"}
    if sync is not None:
        try:
            sync_signals = sync.health() if hasattr(sync, "health") else {
                "consecutive_failures": getattr(sync, "consecutive_failures", 0),
                "backoff_seconds": getattr(sync, "backoff_seconds", 0),
                "last_success_at": "never"}
        except Exception as exc:  # noqa: BLE001
            sync_signals = {"consecutive_failures": -1, "backoff_seconds": 0,
                            "last_success_at": "never", "error": str(exc)[:200]}
    try:
        config.validate()
        config_valid, config_error = True, ""
    except Exception as exc:  # noqa: BLE001
        config_valid, config_error = False, str(exc)[:300]
    identity_dict = {}
    try:
        identity_dict = identity.to_dict() if hasattr(identity, "to_dict") else dict(identity or {})
    except Exception:  # noqa: BLE001
        identity_dict = {}
    identity_dict.pop("protected_token", None)
    etw_states = [str(item.get("health", "unknown")) for item in collector_stats]
    etw_state = etw_states[0] if etw_states else "unknown"
    snapshot = compose_agent_snapshot(
        identity={"agent_key": identity_dict.get("agent_key", ""),
                  "host_id": identity_dict.get("host_id", "")},
        version=getattr(config, "agent_version", "unknown"),
        collectors=collector_stats, queue=queue_signals, sync=sync_signals,
        disk_free_bytes=_disk_free_bytes(getattr(config, "data_dir", ".")),
        etw_state=etw_state, service_state=service_state,
        config_valid=config_valid, config_error=config_error, auth_ok=auth_ok)
    snapshot["checked_at"] = time.time()
    try:
        from guardian.agent.secure_storage import protection_status

        snapshot["protection"] = protection_status()
    except Exception:  # noqa: BLE001
        snapshot["protection"] = {"dpapi_available": "unknown"}
    return snapshot


def snapshot_path(data_dir: str) -> str:
    """Location of the operator-readable health snapshot (no secrets)."""
    return str(Path(data_dir) / "agent_health.json")
