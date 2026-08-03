"""
Collector 6 of 8 — Network posture.

Gathers: listening TCP/UDP ports (with owning process), established
outbound connections, DNS configuration, network profiles,
proxy settings, SMBv1 state, and WinRM remote-management state.

Limitations
-----------
* No remote port scanning is performed.
* No remote host probing of any kind.
* UDP port ownership is not always deterministic without elevation.
"""

from __future__ import annotations

from typing import Any

from ..platform_abstraction import (
    run_ps_dns,
    run_ps_net_profiles,
    run_ps_proxy,
    run_ps_smb,
    run_ps_tcp_established,
    run_ps_tcp_listen,
    run_ps_udp_listen,
    run_ps_winrm,
)
from .base import Collector


class NetworkCollector(Collector):
    name = "network"
    description = (
        "Listening ports, active outbound connections, DNS, network profiles, "
        "proxy, SMBv1 state, and WinRM remote-management exposure."
    )
    requires_admin = False

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        data: dict[str, Any] = {}

        # Listening TCP
        tcp_listen, err = run_ps_tcp_listen()
        if err:
            errors.append(f"tcp_listen: {err}")
            data["tcp_listening"] = []
        else:
            data["tcp_listening"] = tcp_listen if isinstance(tcp_listen, list) else [tcp_listen] if tcp_listen else []

        # Listening UDP
        udp_listen, err = run_ps_udp_listen()
        if err:
            errors.append(f"udp_listen: {err}")
            data["udp_listening"] = []
        else:
            data["udp_listening"] = udp_listen if isinstance(udp_listen, list) else [udp_listen] if udp_listen else []

        # Established connections (outbound)
        tcp_estab, err = run_ps_tcp_established()
        if err:
            errors.append(f"tcp_established: {err}")
            data["tcp_established"] = []
        else:
            data["tcp_established"] = tcp_estab if isinstance(tcp_estab, list) else [tcp_estab] if tcp_estab else []

        # DNS client servers
        dns, err = run_ps_dns()
        if err:
            errors.append(f"dns: {err}")
            data["dns_servers"] = []
        else:
            data["dns_servers"] = dns if isinstance(dns, list) else [dns] if dns else []

        # Network profiles
        profiles, err = run_ps_net_profiles()
        if err:
            errors.append(f"net_profiles: {err}")
            data["network_profiles"] = []
        else:
            data["network_profiles"] = profiles if isinstance(profiles, list) else [profiles] if profiles else []

        # SMB configuration (SMBv1 state)
        smb, err = run_ps_smb()
        if err:
            errors.append(f"smb: {err}")
            data["smb"] = None
        else:
            data["smb"] = smb

        # WinRM (remote management)
        winrm, err = run_ps_winrm()
        if err:
            errors.append(f"winrm: {err}")
            data["winrm"] = None
        else:
            data["winrm"] = winrm

        # Proxy settings
        proxy, err = run_ps_proxy()
        if err:
            errors.append(f"proxy: {err}")
            data["proxy"] = None
        else:
            data["proxy"] = proxy

        return data, errors, False
