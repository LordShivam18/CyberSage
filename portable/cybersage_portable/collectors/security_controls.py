"""
Collector 2 of 8 — Security controls.

Gathers: Microsoft Defender state, firewall profiles, SmartScreen,
UAC consent level, Secure Boot, TPM, BitLocker volumes, and Windows
Security Center service states.

Limitations
-----------
* Third-party AV/EDR solutions are not queried.  This collector only
  checks Windows built-in security controls.
* BitLocker enumeration requires elevation for non-OS volumes on some
  configurations; this collector degrades gracefully.
* Unavailable APIs return a status of ``unavailable``, not a fabricated result.
"""

from __future__ import annotations

from typing import Any

from ..platform_abstraction import (
    get_uac_state,
    run_ps_bitlocker,
    run_ps_defender,
    run_ps_firewall,
    run_ps_secure_boot,
    run_ps_security_services,
    run_ps_smartscreen,
    run_ps_tpm,
)
from .base import Collector


class SecurityControlsCollector(Collector):
    name = "security_controls"
    description = (
        "Microsoft Defender, firewall profiles, SmartScreen, UAC, "
        "Secure Boot, TPM, BitLocker, and Windows Security Center services."
    )
    requires_admin = False  # Most checks work as standard user; some degrade.

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        permission_denied = False
        data: dict[str, Any] = {}

        # Defender
        defender, err = run_ps_defender()
        if err:
            errors.append(f"defender: {err}")
            data["defender"] = None
        else:
            data["defender"] = defender

        # Firewall
        firewall, err = run_ps_firewall()
        if err:
            errors.append(f"firewall: {err}")
            data["firewall"] = None
        else:
            data["firewall"] = firewall if isinstance(firewall, list) else [firewall] if firewall else []

        # SmartScreen
        smartscreen, err = run_ps_smartscreen()
        if err:
            errors.append(f"smartscreen: {err}")
            data["smartscreen"] = None
        else:
            data["smartscreen"] = smartscreen

        # UAC (registry read)
        uac_level, err = get_uac_state()
        if err == "permission_denied":
            errors.append("uac: permission_denied")
            permission_denied = True
            data["uac_consent_level"] = None
        elif err:
            errors.append(f"uac: {err}")
            data["uac_consent_level"] = None
        else:
            data["uac_consent_level"] = uac_level

        # Secure Boot
        secure_boot, err = run_ps_secure_boot()
        if err:
            errors.append(f"secure_boot: {err}")
            data["secure_boot"] = None
        else:
            data["secure_boot"] = secure_boot

        # TPM
        tpm, err = run_ps_tpm()
        if err:
            errors.append(f"tpm: {err}")
            data["tpm"] = None
        else:
            data["tpm"] = tpm

        # BitLocker
        bitlocker, err = run_ps_bitlocker()
        if err == "permission_denied":
            errors.append("bitlocker: permission_denied")
            permission_denied = True
            data["bitlocker"] = None
        elif err:
            errors.append(f"bitlocker: {err}")
            data["bitlocker"] = None
        else:
            data["bitlocker"] = bitlocker if isinstance(bitlocker, list) else []

        # Security Center services
        svc, err = run_ps_security_services()
        if err:
            errors.append(f"security_services: {err}")
            data["security_services"] = None
        else:
            data["security_services"] = svc if isinstance(svc, list) else [svc] if svc else []

        return data, errors, permission_denied
