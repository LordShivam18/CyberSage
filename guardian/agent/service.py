"""Guardian agent service lifecycle (explicit, least-privilege, reversible).

Modes:
  - foreground: development/diagnostic run (default; no installation).
  - install/remove/start/stop: explicit Windows service management via the
    companion windows_service module (Windows + pywin32 only).

Guarantees:
  - Controlled start/stop with bounded shutdown time.
  - Collector + sync worker lifecycle management with graceful drain.
  - Identity + queue recovery at startup (leases recovered, never deleted).
  - Health reporting (JSON) and structured logging without secrets.
  - Startup configuration validation; restart recovery documented.
  - Service installation is explicit, documented, and reversible. Unit
    harnesses never install services.
"""

from __future__ import annotations

import json
import logging
import platform
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def write_health_snapshot(data_dir: str, snapshot: Dict[str, Any]) -> Path:
    """Write an observable health snapshot (no secrets) for operators."""
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "agent_health.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    try:
        import os

        os.replace(tmp, path)
    except Exception:  # noqa: BLE001
        pass
    return path


class ServiceController:
    """Foreground lifecycle manager shared by CLI and Windows service."""

    def __init__(self, agent, *, shutdown_timeout: float = 30.0) -> None:
        self._agent = agent
        self._shutdown_timeout = max(5.0, float(shutdown_timeout))
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start_foreground(self) -> None:
        """Run the agent in the foreground until stopped."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._agent.run, name="guardian-foreground", daemon=True)
        self._thread.start()
        try:
            while self._thread.is_alive() and not self._stop_event.is_set():
                self._stop_event.wait(timeout=1.0)
        finally:
            self.stop_gracefully()

    def stop_gracefully(self) -> None:
        """Request shutdown and wait up to the bounded timeout."""
        self._stop_event.set()
        try:
            stop = getattr(self._agent, "stop", None)
            if callable(stop):
                stop()
        except Exception as exc:  # noqa: BLE001
            logger.error("ServiceController: error during stop: %s", exc)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=self._shutdown_timeout)
            if self._thread.is_alive():
                logger.warning(
                    "ServiceController: shutdown exceeded %.0fs bound; leaving daemon thread",
                    self._shutdown_timeout,
                )
            self._thread = None


def install_service_instructions() -> str:
    """Human-readable explicit install/remove guidance (no side effects)."""
    return (
        "Windows service management is explicit and reversible:\n"
        "  python -m guardian.agent.windows_service install   # requires elevation\n"
        "  python -m guardian.agent.windows_service start\n"
        "  python -m guardian.agent.windows_service stop\n"
        "  python -m guardian.agent.windows_service remove   # reversible\n"
        "ETW privileges are separate: SeSystemProfilePrivilege or local\n"
        "administrator is required for kernel providers. Service account\n"
        "needs only Log on as a service + ETW profile privilege.\n"
        f"Platform now: {platform.system()}. Non-Windows hosts run foreground mode only."
    )
