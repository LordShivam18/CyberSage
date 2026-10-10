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
from typing import Optional

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
            if not apply_windows_acl(directory):
                logger.warning(
                    "secure_storage: keeping inherited ACLs on %s "
                    "(restriction unverified; see protection status)", directory)
        else:
            os.chmod(directory, 0o700)
    except Exception as exc:  # noqa: BLE001
        logger.warning("secure_storage: could not restrict %s: %s", directory, exc)
    return directory


def _current_user_principal() -> str:
    """Resolve the current process identity for ACL grants.

    getpass.getuser() reflects the process token environment; the raw
    USERNAME variable alone has proven unreliable (alias/UPN formats that
    icacls cannot map to the process SID, stranding the file).
    """
    try:
        import getpass

        name = getpass.getuser()
        if isinstance(name, str) and name.strip():
            return name.strip()
    except Exception:  # noqa: BLE001
        pass
    fallback = os.getenv("USERNAME", "Administrators")
    return fallback.strip() or "Administrators"


def _verify_access(path: Path) -> bool:
    """Prove the current process can still use the path (no secrets logged)."""
    try:
        target = Path(path)
        if target.is_dir():
            probe = target / ".acl_probe"
            probe.write_text("probe", encoding="utf-8")
            probe.read_text(encoding="utf-8")
            probe.unlink()
        else:
            with target.open("rb"):
                pass
        return True
    except OSError:
        return False


def apply_windows_acl(path: Path) -> bool:
    """Apply restrictive Windows ACLs and verify current-process access.

    Grants the resolved process principal plus SYSTEM and Administrators
    with inheritance removed, then PROVES the current process can still
    use the path (read for files; create/read/delete probe for dirs).
    On any failure — bad return code or failed verification — inheritance
    is restored via ``icacls /reset`` and False is returned so the caller
    keeps usable inherited ACLs with an explicit warning instead of a
    stranded file. Never raises for ACL problems. Non-Windows returns True
    (callers apply POSIX modes separately).
    """
    if os.name != "nt":
        return True
    import subprocess

    target = Path(path)
    principal = _current_user_principal()
    try:
        result = subprocess.run(
            ["icacls", str(target), "/inheritance:r", "/grant:r",
             f"{principal}:F", "SYSTEM:F", "Administrators:F"],
            capture_output=True, timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("secure_storage: icacls did not run for %s: %s", target, exc)
        return False
    if result.returncode != 0:
        logger.warning(
            "secure_storage: icacls rejected principal %s for %s (rc=%d); "
            "keeping inherited ACLs", principal, target, result.returncode)
        return False
    if _verify_access(target):
        return True
    logger.warning(
        "secure_storage: access verification failed for %s after ACL change; "
        "restoring inherited ACLs", target)
    rollback_verified = False
    try:
        reset = subprocess.run(["icacls", str(target), "/reset"],
                               capture_output=True, timeout=15)
        # The rollback itself is CHECKED, not assumed: re-verify access and
        # require a clean return code before reporting inherited ACLs.
        rollback_verified = reset.returncode == 0 and _verify_access(target)
    except Exception as reset_exc:  # noqa: BLE001
        logger.warning("secure_storage: ACL rollback failed for %s: %s", target, reset_exc)
    if rollback_verified:
        logger.warning("secure_storage: inherited ACLs restored and verified for %s", target)
    else:
        logger.error(
            "secure_storage: ACL rollback UNVERIFIED for %s; manual intervention "
            "required (icacls <path> /reset)", target)
    return False


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
