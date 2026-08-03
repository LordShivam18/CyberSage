"""
Collector 1 of 8 — Operating System information.

Gathers: Windows version/build, architecture, last boot time,
pending-restart indicators, and Windows Update service status.

Limitations
-----------
* Patch compliance cannot be confirmed — update service state does not
  indicate whether all available patches have been installed.
* Pending-restart indicators are read from two well-known registry keys;
  other restart conditions may exist.
* Last boot time is from Win32_OperatingSystem.LastBootUpTime via CIM.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from ..platform_abstraction import (
    run_ps_os_version,
    run_ps_pending_restart,
    run_ps_update_service,
)
from .base import Collector


class OsInfoCollector(Collector):
    name = "os_info"
    description = "Windows version, architecture, boot time, pending restart, and update service state."
    requires_admin = False

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        data: dict[str, Any] = {
            "platform": sys.platform,
            "python_version": platform.python_version(),
        }

        # OS version via CIM
        os_raw, err = run_ps_os_version()
        if err:
            errors.append(f"os_version: {err}")
            data["os_version"] = None
        else:
            data["os_version"] = os_raw

        # Pending restart indicators
        restart_raw, err = run_ps_pending_restart()
        if err:
            errors.append(f"pending_restart: {err}")
            data["pending_restart"] = None
        else:
            data["pending_restart"] = restart_raw

        # Windows Update service
        wu_raw, err = run_ps_update_service()
        if err:
            errors.append(f"update_service: {err}")
            data["update_service"] = None
        else:
            data["update_service"] = wu_raw

        return data, errors, False
