"""
Privacy and redaction utilities.

Three modes
-----------
standard
    No redaction.  Full hostnames, usernames, paths, and IPs are retained.

redacted
    Hostnames, usernames, home-directory paths, and local IP addresses are
    replaced with stable placeholders.  Process command-line arguments are
    removed.  Device identifiers are removed.

minimal
    Only operating-system name, version, and finding check IDs/statuses are
    retained.  All other identifying information is replaced.

Rules
-----
* The selected mode is recorded in every report.
* The backend stores only the hostname/device label that was present in the
  report after redaction — it never silently re-expands redacted values.
* No automatic device fingerprint is generated from MachineGuid, hardware
  serial, TPM EK, MAC address, or similar identifier.
* Secrets (passwords, tokens, hashes, private keys, cookies, clipboard
  contents) are never placed in reports or logs regardless of privacy mode.
"""

from __future__ import annotations

import hashlib
import re
import socket
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any, Optional

from .models import PrivacyMode


# ---------------------------------------------------------------------------
# Redaction configuration
# ---------------------------------------------------------------------------


@dataclass
class RedactionConfig:
    mode: PrivacyMode
    redact_usernames: bool = True
    redact_hostnames: bool = True
    redact_home_paths: bool = True
    redact_local_ips: bool = True
    redact_cmdline_args: bool = True
    redact_device_ids: bool = True

    @classmethod
    def for_mode(cls, mode: PrivacyMode) -> "RedactionConfig":
        if mode == PrivacyMode.STANDARD:
            return cls(
                mode=mode,
                redact_usernames=False,
                redact_hostnames=False,
                redact_home_paths=False,
                redact_local_ips=False,
                redact_cmdline_args=False,
                redact_device_ids=False,
            )
        if mode == PrivacyMode.REDACTED:
            return cls(
                mode=mode,
                redact_usernames=True,
                redact_hostnames=True,
                redact_home_paths=True,
                redact_local_ips=True,
                redact_cmdline_args=True,
                redact_device_ids=True,
            )
        # MINIMAL: everything identifying is replaced
        return cls(
            mode=mode,
            redact_usernames=True,
            redact_hostnames=True,
            redact_home_paths=True,
            redact_local_ips=True,
            redact_cmdline_args=True,
            redact_device_ids=True,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_local_ip(addr: str) -> bool:
    """Return True if addr is a private, loopback, or link-local IP."""
    try:
        ip = IPv4Address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except AddressValueError:
        pass
    try:
        ip6 = IPv6Address(addr)
        return ip6.is_private or ip6.is_loopback or ip6.is_link_local
    except AddressValueError:
        pass
    return False


def _stable_placeholder(value: str, prefix: str = "REDACTED") -> str:
    """Return a deterministic placeholder that encodes a truncated hash of the value."""
    h = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"<{prefix}-{h}>"


def _redact_home_path(path: str, username_hint: Optional[str] = None) -> str:
    """Replace home-directory segments in a filesystem path."""
    # Matches Windows home paths: C:\Users\<name>\... or /home/<name>/...
    path = re.sub(
        r"(?i)(C:\\Users\\|/home/)([^/\\]+)",
        lambda m: m.group(1) + _stable_placeholder(m.group(2), "USER"),
        path,
    )
    if username_hint:
        path = path.replace(username_hint, _stable_placeholder(username_hint, "USER"))
    return path


def _redact_username(value: str, username: str) -> str:
    if not username:
        return value
    return value.replace(username, _stable_placeholder(username, "USER"))


# ---------------------------------------------------------------------------
# Main redaction function
# ---------------------------------------------------------------------------


def redact_value(
    value: Any,
    config: RedactionConfig,
    *,
    current_user: str = "",
    current_hostname: str = "",
    field_hint: str = "",
) -> Any:
    """
    Apply redaction rules to a single value according to RedactionConfig.

    ``field_hint`` is an optional field-name hint used to apply context-aware
    redaction (e.g. ``"cmdline"`` triggers argument stripping).
    """
    if config.mode == PrivacyMode.STANDARD:
        return value

    if isinstance(value, str):
        result = value

        # Command-line arguments
        if config.redact_cmdline_args and field_hint in {"cmdline", "command_line", "args", "arguments"}:
            result = "<CMDLINE-REDACTED>"
            return result

        # Device identifiers
        if config.redact_device_ids and field_hint in {"machine_guid", "device_id", "serial", "uuid", "hardware_id"}:
            return "<DEVICE-ID-REDACTED>"

        # Hostname
        if config.redact_hostnames and current_hostname and current_hostname in result:
            result = result.replace(current_hostname, _stable_placeholder(current_hostname, "HOST"))

        # Username in paths / strings
        if config.redact_usernames and current_user and current_user in result:
            result = _redact_username(result, current_user)

        # Home directory paths
        if config.redact_home_paths:
            result = _redact_home_path(result, current_user if config.redact_usernames else None)

        # Local IPs
        if config.redact_local_ips:
            result = re.sub(
                r"\b((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})\b",
                lambda m: _stable_placeholder(m.group(1), "IP") if _is_local_ip(m.group(1)) else m.group(1),
                result,
            )

        return result

    if isinstance(value, dict):
        return {
            k: redact_value(v, config, current_user=current_user, current_hostname=current_hostname, field_hint=k)
            for k, v in value.items()
        }

    if isinstance(value, list):
        return [
            redact_value(item, config, current_user=current_user, current_hostname=current_hostname, field_hint=field_hint)
            for item in value
        ]

    return value


def redact_host_summary(
    host: dict,
    config: RedactionConfig,
    *,
    current_user: str = "",
) -> dict:
    """
    Redact the host summary block.

    The backend stores only what is present here — no silent re-expansion of
    redacted hostnames.
    """
    if config.mode == PrivacyMode.STANDARD:
        return host

    result = dict(host)
    if config.redact_hostnames and "hostname" in result:
        result["hostname"] = _stable_placeholder(result["hostname"], "HOST")

    if config.mode == PrivacyMode.MINIMAL:
        # Keep only non-identifying OS fields
        keep = {"os_name", "os_version", "os_build", "architecture"}
        result = {k: v for k, v in result.items() if k in keep}
        result.setdefault("hostname", "<HOST-REDACTED>")
        result.setdefault("last_boot", None)

    return result
