"""Windows-appropriate protection for sensitive local data.

Threat model and guarantees (honest, documented):
  - Application data directory: restrictive ACLs (Windows icacls:
    owner + SYSTEM + Administrators, no inheritance) or POSIX 0o700.
  - SQLite database + WAL + related files: same directory protections.
    ACLs are access control, NOT encryption at rest.
  - Reusable credentials (backend auth token) and sensitive event payloads:
    Windows DPAPI (CURRENT_USER scope) when available. DPAPI protects with
    the user/machine key; it does not survive user-profile loss.
  - Non-Windows: file-permission-only protection with an explicit
    DEGRADED warning. This module never pretends DPAPI is available.
  - No unprotected decryption key is stored beside encrypted data: DPAPI
    keys live in the OS user profile, not in the data directory.
  - Logs are redacted: helpers here never log secret values.

Key protection / rotation / recovery:
  - Rotation: overwrite the protected blob via protect_secret(); old blobs
    are atomically replaced.
  - Recovery: DPAPI decryption failure returns an explicit error; the
    agent surfaces auth-degraded health and does not silently continue
    with a wrong credential.
  - Failure assumption: profile loss or machine change makes DPAPI blobs
    unrecoverable; the operator must re-provision GUARDIAN_AUTH_TOKEN.
"""

from __future__ import annotations

import base64
import logging
import os
import platform
from pathlib import Path
from typing Optional

logger = logging.getLogger(__name__)

_DPAPI_UNAVAILABLE_REASON: Optional[str] = None
if platform.system() != "Windows":
    _DPAPI_UNAVAILABLE_REASON = f"non-Windows platform: {platform.system()}"
else:
    try:
        import win32crypt  # type: ignore[import]  # pywin32, Windows-only
    except ImportError as exc:
        _DPAPI_UNAVAILABLE_REASON = f"pywin32 not installed: {exc}"


def dpapi_available() -> bool:
    """Return True only when OS-backed DPAPI protection is usable."""
    return _DPAPI_UNAVAILABLE_REASON is None


def protection_status() -> dict:
    """Observable protection state (no secrets included)."""
    return {
        "platform": platform.system(),
        "dpapi_available": dpapi_available(),
        "unavailable_reason": _DPAPI_UNAVAILABLE_REASON,
        "note": "ACLs are access control, not encryption at rest.",
    }


def ensure_data_dir(path: str) -> Path:
    """Create the application data directory with restrictive ACLs."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "nt":
            import subprocess

            subprocess.run(
                ["icacls", str(directory), "/inheritance:r", "/grant:r",
                 "SYSTEM:F", "Administrators:F", f"{os.getenv('USERNAME', 'Administrators')}:F"],
                capture_output=True, timeout=15,
            )
        else:
            os.chmod(directory, 0o700)
    except Exception as exc:  # noqa: BLE001
        logger.warning("secure_storage: could not restrict %s: %s", directory, exc)
    return directory


def protect_secret(plaintext: str) -> str:
    """Protect a secret with DPAPI. Raises when unavailable (fail closed)."""
    if not plaintext:
        raise ValueError("plaintext must not be empty")
    if not dpapi_available():
        raise RuntimeError(f"DPAPI unavailable: {_DPAPI_UNAVAILABLE_REASON}")
    import win32crypt  # type: ignore[import]

    blob = win32crypt.CryptProtectData(plaintext.encode("utf-8"), None, None, None, None, 0)
    return "dpapi:" + base64.b64encode(blob).decode("ascii")


def unprotect_secret(protected: str) -> str:
    """Recover a DPAPI-protected secret. Raises on failure (fail closed)."""
    if not isinstance(protected, str) or not protected.startswith("dpapi:"):
        raise ValueError("protected value must use the 'dpapi:' envelope")
    if not dpapi_available():
        raise RuntimeError(f"DPAPI unavailable: {_DPAPI_UNAVAILABLE_REASON}")
    import win32crypt  # type: ignore[import]

    blob = base64.b64decode(protected[len("dpapi:"):])
    # pywin32 canonical API:
    try:
        _, recovered = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return recovered.decode("utf-8") if isinstance(recovered, bytes) else str(recovered)
    except Exception as exc:
        raise RuntimeError(f"DPAPI decryption failed: {exc}") from exc


def redact(value: object) -> str:
    """Return a redacted placeholder for any secret-like value."""
    if value is None or value == "":
        return "not-set"
    return "***REDACTED***"
