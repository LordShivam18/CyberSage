"""
Collector 3 of 8 — Accounts and privileges.

Gathers: current user privilege level, local administrator group members,
enabled local accounts, guest account state, password policy indicators,
RDP exposure, and auto-logon indicators.

Safety rules enforced
---------------------
* Password hashes, credentials, stored passwords, and LSASS memory are
  NEVER accessed.
* Auto-logon detection reads only the ``AutoAdminLogon`` value — the
  ``DefaultPassword`` registry entry is explicitly not read.
* HKLM\\SAM is not accessed.
"""

from __future__ import annotations

from typing import Any

from ..platform_abstraction import (
    get_autologon_indicator,
    get_current_username,
    is_admin,
    run_ps_local_admins,
    run_ps_local_users,
    run_ps_rdp,
)
from .base import Collector


class AccountsCollector(Collector):
    name = "accounts"
    description = (
        "Current user privileges, local admin members, local accounts, "
        "guest account, password policy, RDP state, and auto-logon indicators."
    )
    requires_admin = False

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        permission_denied = False
        data: dict[str, Any] = {}

        # Current privilege
        data["current_user"] = get_current_username()
        data["is_admin"] = is_admin()

        # Local admin group members
        admins, err = run_ps_local_admins()
        if err == "permission_denied":
            errors.append("local_admins: permission_denied")
            permission_denied = True
            data["local_admins"] = None
        elif err:
            errors.append(f"local_admins: {err}")
            data["local_admins"] = None
        else:
            data["local_admins"] = admins if isinstance(admins, list) else [admins] if admins else []

        # Local users
        users, err = run_ps_local_users()
        if err == "permission_denied":
            errors.append("local_users: permission_denied")
            permission_denied = True
            data["local_users"] = None
        elif err:
            errors.append(f"local_users: {err}")
            data["local_users"] = None
        else:
            data["local_users"] = users if isinstance(users, list) else [users] if users else []

        # RDP exposure
        rdp, err = run_ps_rdp()
        if err:
            errors.append(f"rdp: {err}")
            data["rdp_deny_ts_connections"] = None
        else:
            data["rdp_deny_ts_connections"] = (rdp or {}).get("fDenyTSConnections")

        # Auto-logon indicator (no password reading)
        autologon, err = get_autologon_indicator()
        if err and err != "not_windows":
            errors.append(f"autologon: {err}")
            data["autologon_enabled"] = None
        else:
            data["autologon_enabled"] = autologon

        return data, errors, permission_denied
