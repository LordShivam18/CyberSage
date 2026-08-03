"""
Collector 5 of 8 — Persistence mechanisms.

Read-only inventory of:
  * User and common startup folders
  * Run / RunOnce registry keys (HKCU and HKLM)
  * Enabled scheduled tasks
  * Auto-start services

Safety rules
------------
* No entries are deleted or modified.
* Registry access is read-only via winreg.OpenKey(KEY_READ).
* Findings are flagged by explainable rules only.
"""

from __future__ import annotations

import hashlib
import sys
from typing import Any

from ..platform_abstraction import (
    read_registry_keys,
    run_ps_scheduled_tasks,
    run_ps_security_services,
    run_ps_startup_common,
    run_ps_startup_user,
)
from .base import Collector

# Safe run-key locations to enumerate (HKCU and HKLM).
_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    # Wow6432Node for 32-bit entries on 64-bit systems
    ("HKLM", r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


def _hive_const(hive: str) -> int:
    if sys.platform != "win32":
        return 0
    import winreg  # noqa: PLC0415
    return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive]


def _path_hash(value: str) -> str:
    """Short stable hash for a path/value combination used in finding_id."""
    return hashlib.sha256(value.lower().encode("utf-8", errors="replace")).hexdigest()[:12]


class PersistenceCollector(Collector):
    name = "persistence"
    description = (
        "Read-only inventory of startup folders, Run/RunOnce registry keys, "
        "enabled scheduled tasks, and auto-start services."
    )
    requires_admin = False

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        permission_denied = False
        data: dict[str, Any] = {}

        # Startup folders
        user_startup, err = run_ps_startup_user()
        if err:
            errors.append(f"startup_folder_user: {err}")
            data["startup_user"] = []
        else:
            data["startup_user"] = user_startup if isinstance(user_startup, list) else []

        common_startup, err = run_ps_startup_common()
        if err:
            errors.append(f"startup_folder_common: {err}")
            data["startup_common"] = []
        else:
            data["startup_common"] = common_startup if isinstance(common_startup, list) else []

        # Run / RunOnce registry keys
        run_entries: list[dict[str, Any]] = []
        if sys.platform == "win32":
            for hive_name, subkey in _RUN_KEYS:
                try:
                    hive = _hive_const(hive_name)
                    values, err = read_registry_keys(hive, subkey)
                    if err and err != "key_not_found":
                        if "permission" in err:
                            permission_denied = True
                        errors.append(f"run_key {hive_name}\\{subkey}: {err}")
                    for name, data_val, _ in values:
                        run_entries.append({
                            "hive": hive_name,
                            "key": subkey,
                            "name": str(name),
                            "value": str(data_val)[:512],  # cap length
                            "path_hash": _path_hash(f"{hive_name}\\{subkey}\\{name}"),
                        })
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"run_key {hive_name}\\{subkey}: {type(exc).__name__}")
        else:
            errors.append("run_keys: not_windows")

        data["run_entries"] = run_entries

        # Scheduled tasks
        tasks, err = run_ps_scheduled_tasks()
        if err:
            errors.append(f"scheduled_tasks: {err}")
            data["scheduled_tasks"] = []
        else:
            data["scheduled_tasks"] = tasks if isinstance(tasks, list) else [tasks] if tasks else []

        # Auto-start services (reuse security_services query for Windows Defender/Security)
        # A broader services query is done via the processes collector; here we note
        # key security service autostart states.
        svc, err = run_ps_security_services()
        if err:
            errors.append(f"security_autostart: {err}")
            data["security_autostart_services"] = []
        else:
            data["security_autostart_services"] = svc if isinstance(svc, list) else [svc] if svc else []

        return data, errors, permission_denied
