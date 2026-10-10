"""Stable agent identity persistence.

Contract (reuses backend registration semantics):
  - agent_key: stable local identity, configured once, reused across restarts.
  - host_id: stable host identity, generated once when absent.
  - server agent_id: numeric backend id returned at registration, persisted
    for recovery and health correlation.
  - The agent ALWAYS sends an explicit agent_key. It never relies on the
    backend "most recently registered agent" fallback (legacy server
    behavior kept for backward compatibility only).

Storage: JSON file inside the application data directory with restrictive
permissions (Windows ACL / POSIX 0o600). Secrets themselves live in
secure_storage.py; this file holds identity references only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

IDENTITY_FILENAME = "agent_identity.json"
IDENTITY_SCHEMA_VERSION = 1


@dataclass
class AgentIdentity:
    agent_key: str = ""
    host_id: str = ""
    host_hostname: str = ""
    server_agent_id: Optional[int] = None
    agent_version: str = "2.0.0"
    schema_version: int = IDENTITY_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentIdentity":
        kwargs = {k: data.get(k, "") for k in ("agent_key", "host_id", "host_hostname", "agent_version")}
        kwargs["server_agent_id"] = data.get("server_agent_id")
        kwargs["schema_version"] = int(data.get("schema_version", IDENTITY_SCHEMA_VERSION))
        return cls(**kwargs)


def generate_host_id(hostname: str = "", username: str = "") -> str:
    """Generate a stable host id from machine data (no secrets logged)."""
    payload = "|".join([hostname or platform.node(), username or ""])
    if platform.system() == "Windows":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            )
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            payload = f"{value}|{payload}"
        except Exception:
            pass
    return f"host-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def _identity_path(data_dir: str) -> Path:
    return Path(data_dir) / IDENTITY_FILENAME


def _restrict_file(path: Path) -> bool:
    """Apply restrictive ACLs with verified access. Returns True when restricted.

    Delegates to the shared, verified helper so identity files can never be
    stranded unreadable: False means inherited ACLs were kept with a warning.
    """
    if os.name != "nt":
        return True
    try:
        from guardian.agent.secure_storage import apply_windows_acl

        if apply_windows_acl(path):
            return True
        logger.warning("identity: keeping inherited ACLs on %s (restriction unverified)", path)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning("identity: could not restrict %s: %s", path, exc)
        return False


def load_identity(data_dir: str) -> Optional[AgentIdentity]:
    """Load persisted identity, or None when absent/corrupt (fail closed)."""
    path = _identity_path(data_dir)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        identity = AgentIdentity.from_dict(raw)
        if not identity.agent_key or not identity.host_id:
            logger.warning("identity: persisted file missing agent_key/host_id")
            return None
        return identity
    except FileNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("identity: failed to load %s: %s", path, exc)
        return None


def save_identity(data_dir: str, identity: AgentIdentity) -> Path:
    """Persist identity atomically with verified restrictive permissions.

    The temp file is restricted and verified BEFORE the atomic replace, so
    the final file is never left stranded: either it carries verified
    restrictive ACLs or it keeps usable inherited ACLs with a warning.
    """
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = _identity_path(data_dir)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(identity.to_dict(), indent=2), encoding="utf-8")
    restricted = _restrict_file(tmp)
    if not restricted:
        # Defense in depth: never replace a good file with a stranded temp
        # file. If the temp file itself is unreadable (rollback unverified),
        # drop it and fail loudly so startup reports the cause instead of
        # booting with a missing identity.
        try:
            with tmp.open("rb"):
                pass
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise OSError(
                f"identity: refusing to replace {path}: temp file unreadable "
                f"after ACL handling ({exc}); manual recovery: icacls {path} /reset"
            )
        logger.warning(
            "identity: %s persisted with inherited ACLs (restriction unverified; "
            "see protection status)", path)
    os.replace(tmp, path)
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except Exception:  # noqa: BLE001
        pass
    return path


def ensure_identity(
    data_dir: str, *, agent_key: str, host_id: str = "", host_hostname: str = "",
    agent_version: str = "2.0.0",
) -> AgentIdentity:
    """Reuse persisted identity across restarts; never mint per start.

    Priority: persisted file > explicit config > generated host_id.
    A new agent record is NOT created per start: agent_key is stable and
    server_agent_id is preserved once learned.
    """
    existing = load_identity(data_dir)
    if existing is not None:
        # Config agent_key mismatch is a misconfiguration: fail closed by
        # keeping the persisted key and warning (no silent re-registration).
        if agent_key and existing.agent_key != agent_key:
            logger.warning("identity: configured agent_key differs from persisted identity; keeping persisted key")
        return existing
    if not agent_key:
        raise ValueError("agent_key is required to establish identity")
    identity = AgentIdentity(
        agent_key=agent_key,
        host_id=host_id or generate_host_id(host_hostname),
        host_hostname=host_hostname or platform.node(),
        server_agent_id=None,
        agent_version=agent_version,
    )
    save_identity(data_dir, identity)
    return identity
