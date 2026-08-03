"""
Collector 8 of 8 — Certificate posture.

Gathers: expired certificates in trusted-root stores, and recently
added user-installed root certificates.

Safety rules
------------
* No certificate is removed or modified.
* Certificate installation recency is NOT inferred from filesystem
  timestamps, which are unreliable.  When recency cannot be
  established safely, status is returned as ``unavailable``.
* Self-signed roots are identified by Subject == Issuer.
* No certificate is automatically declared malicious.

Limitations
-----------
* Installation date/time cannot be reliably determined from available
  metadata.  The ``recently_installed`` field is always reported as
  ``unavailable`` in v1.
* Certificate access failures are reported, not silently ignored.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..platform_abstraction import run_ps_cert_roots_machine, run_ps_cert_roots_user
from .base import Collector


def _is_self_signed(cert: dict) -> bool:
    """Return True when Subject equals Issuer (a heuristic, not a cryptographic proof)."""
    subject = (cert.get("Subject") or "").strip()
    issuer = (cert.get("Issuer") or "").strip()
    return bool(subject and issuer and subject == issuer)


def _parse_cert_date(date_str: Any) -> Any:
    """
    Parse a certificate date string.  Returns None on failure rather
    than raising; certificate store date formats vary.
    """
    if date_str is None:
        return None
    try:
        # PowerShell returns dates as '/Date(ms)/' or ISO-like strings.
        s = str(date_str).strip()
        if s.startswith("/Date("):
            ms = int(s[6:-2].split("+")[0].split("-")[0])
            return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
        # Try ISO
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.isoformat()
    except Exception:  # noqa: BLE001
        return None


def _annotate_cert(cert: dict) -> dict:
    """Annotate a raw certificate dict with derived fields."""
    now = datetime.now(timezone.utc).isoformat()
    not_after = _parse_cert_date(cert.get("NotAfter"))
    not_before = _parse_cert_date(cert.get("NotBefore"))

    expired = False
    if not_after:
        try:
            expires_dt = datetime.fromisoformat(not_after)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
            expired = expires_dt < datetime.now(timezone.utc)
        except Exception:  # noqa: BLE001
            pass

    return {
        "thumbprint": str(cert.get("Thumbprint") or "")[:64],
        "subject": str(cert.get("Subject") or "")[:512],
        "issuer": str(cert.get("Issuer") or "")[:512],
        "not_before": not_before,
        "not_after": not_after,
        "expired": expired,
        "self_signed": _is_self_signed(cert),
        # Installation recency CANNOT be safely established from available
        # data in v1 (filesystem timestamps are unreliable).
        "recently_installed": "unavailable",
    }


class CertificatesCollector(Collector):
    name = "certificates"
    description = (
        "Trusted root certificate stores (user and machine): "
        "expired certificates, self-signed roots, and access failures."
    )
    requires_admin = False

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        data: dict[str, Any] = {
            "user_roots": [],
            "machine_roots": [],
        }

        # User root store
        user_certs, err = run_ps_cert_roots_user()
        if err:
            errors.append(f"cert_roots_user: {err}")
            data["user_roots_accessible"] = False
        else:
            data["user_roots_accessible"] = True
            raw_list = user_certs if isinstance(user_certs, list) else [user_certs] if user_certs else []
            data["user_roots"] = [_annotate_cert(c) for c in raw_list if isinstance(c, dict)]

        # Machine root store
        machine_certs, err = run_ps_cert_roots_machine()
        if err:
            if "permission" in (err or ""):
                errors.append(f"cert_roots_machine: permission_denied")
                data["machine_roots_accessible"] = False
            else:
                errors.append(f"cert_roots_machine: {err}")
                data["machine_roots_accessible"] = False
        else:
            data["machine_roots_accessible"] = True
            raw_list = machine_certs if isinstance(machine_certs, list) else [machine_certs] if machine_certs else []
            data["machine_roots"] = [_annotate_cert(c) for c in raw_list if isinstance(c, dict)]

        return data, errors, False
