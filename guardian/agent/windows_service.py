"""Windows service entry point (Windows + pywin32 only, explicit use).

This module is never imported on non-Windows hosts and never runs during
unit harnesses. Installation/removal/start/stop are explicit operator
actions; importing this module has no side effects.

Requires: Windows, pywin32 (``pip install cybersage-portable[win]`` or
equivalent), elevation for install/remove, and ETW privileges
(SeSystemProfilePrivilege or administrator) for kernel providers.
"""

from __future__ import annotations

import logging
import platform
import sys

logger = logging.getLogger(__name__)

if platform.system() != "Windows":
    raise RuntimeError("guardian.agent.windows_service is Windows-only")


def _require_pywin32():  # pragma: no cover - Windows-only path
    try:
        import win32serviceutil  # type: ignore[import]
        import win32service  # type: ignore[import]
        import win32event  # type: ignore[import]
        import servicemanager  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError(
            "pywin32 is required for Windows service mode. "
            "Install it on Windows first."
        ) from exc
    return win32serviceutil, win32service, win32event, servicemanager


class GuardianWindowsService:  # pragma: no cover - Windows-only path
    """pywin32 ServiceFramework wrapper with graceful shutdown."""

    _svc_name_ = "CyberSageGuardian"
    _svc_display_name_ = "CyberSage Guardian Agent"
    _svc_description_ = "CyberSage Guardian endpoint telemetry agent (user-space, least privilege)."

    def __init__(self, args):
        win32serviceutil, win32service, win32event, _ = _require_pywin32()
        import win32serviceutil as _util  # noqa: F401

        self._win32service = win32service
        self._win32event = win32event
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._agent = None

    def SvcStop(self):  # noqa: N802 - pywin32 convention
        self.ReportServiceStatus(self._win32service.SERVICE_STOP_PENDING)
        try:
            if self._agent is not None:
                self._agent.stop()
        finally:
            self._win32event.SetEvent(self._stop_event)

    def SvcDoRun(self):  # noqa: N802 - pywin32 convention
        from guardian.agent.config import AgentConfig
        from guardian.agent.main import GuardianAgent

        config = AgentConfig()
        config.validate()
        self._agent = GuardianAgent(config=config)
        self._agent.run()


def main(argv=None) -> int:
    """CLI: install | remove | start | stop | foreground-notes."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("install", "remove", "start", "stop", "restart"):
        print(
            "Usage: python -m guardian.agent.windows_service [install|remove|start|stop|restart]\n"
            "Explicit, reversible Windows service management. Requires elevation for\n"
            "install/remove and pywin32 on Windows. Foreground mode: python -m guardian.agent.main"
        )
        return 2
    win32serviceutil, _, _, _ = _require_pywin32()
    win32serviceutil.HandleCommandLine(GuardianWindowsService)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
