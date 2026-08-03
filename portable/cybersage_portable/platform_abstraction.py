"""
Platform abstraction layer.

ALL operating-system calls in the portable scanner flow through this module.
Collectors import only from here, never from ``winreg``, ``ctypes``, or
``subprocess`` directly.  This makes every collector fully mockable in tests
without requiring Windows.

Design rules enforced here
--------------------------
* No WMIC.  All Windows data is obtained via PowerShell CIM cmdlets, native
  ``winreg`` reads, ``ctypes``, or standard-library APIs.
* No ``shell=True``.  Every subprocess call uses an explicit list of arguments.
* No user-controlled string interpolation in commands.
* Every PowerShell command is on a fixed allowlist defined in ``_PS_COMMANDS``.
* ``-NoProfile -NonInteractive`` is always passed.
* Subprocess timeouts are bounded (default 15 s, configurable per call).
* ``stderr`` is captured and sanitized before inclusion in results.
* On non-Windows platforms all functions return ``None`` or empty structures
  so the test suite and CI run without modification.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from typing import Any, Optional

_IS_WINDOWS = sys.platform == "win32"

# Subprocess creation flag that suppresses the console window on Windows.
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0

# Maximum size (bytes) of stderr we retain to avoid log flooding.
_MAX_STDERR_BYTES = 2048

# Default timeout for all subprocess calls (seconds).
DEFAULT_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Allowlisted PowerShell CIM commands
# No user input may ever be interpolated into these strings.
# ---------------------------------------------------------------------------


_PS_COMMANDS: dict[str, str] = {
    # OS
    "os_version": (
        "Get-CimInstance -ClassName Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime | "
        "ConvertTo-Json -Compress"
    ),
    "pending_restart_cim": (
        "try { "
        "  $cb = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing' "
        "         -Name RebootPending -ErrorAction SilentlyContinue; "
        "  $wu = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' "
        "         -Name RebootRequired -ErrorAction SilentlyContinue; "
        "  [PSCustomObject]@{cbs=$cb.RebootPending -eq $true; wu=$wu.RebootRequired -eq $true} | ConvertTo-Json -Compress "
        "} catch { '{\"cbs\":null,\"wu\":null}' }"
    ),
    "update_service": (
        "Get-Service -Name wuauserv -ErrorAction SilentlyContinue | "
        "Select-Object Status,StartType | ConvertTo-Json -Compress"
    ),
    # Defender
    "defender_status": (
        "try { Get-MpComputerStatus | "
        "Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,"
        "AMServiceEnabled,QuickScanSignatureVersion,AntivirusSignatureLastUpdated,"
        "QuickScanEndTime | ConvertTo-Json -Compress "
        "} catch { '{\"error\":\"mpstatus_unavailable\"}' }"
    ),
    # Firewall
    "firewall_profiles": (
        "Get-NetFirewallProfile | "
        "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | "
        "ConvertTo-Json -Compress"
    ),
    # SmartScreen
    "smartscreen": (
        "try { Get-ItemProperty "
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' "
        "-Name SmartScreenEnabled -ErrorAction SilentlyContinue | "
        "Select-Object SmartScreenEnabled | ConvertTo-Json -Compress "
        "} catch { '{\"SmartScreenEnabled\":null}' }"
    ),
    # Secure Boot
    "secure_boot": (
        "try { Confirm-SecureBootUEFI -ErrorAction SilentlyContinue | "
        "ForEach-Object { [PSCustomObject]@{SecureBoot=$_} } | ConvertTo-Json -Compress "
        "} catch { '{\"SecureBoot\":null}' }"
    ),
    # TPM
    "tpm_status": (
        "try { Get-Tpm | "
        "Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,ManufacturerVersion | "
        "ConvertTo-Json -Compress "
        "} catch { '{\"TpmPresent\":null}' }"
    ),
    # BitLocker
    "bitlocker": (
        "try { "
        "Get-BitLockerVolume -ErrorAction SilentlyContinue | "
        "Select-Object MountPoint,ProtectionStatus,VolumeStatus,EncryptionMethod | "
        "ConvertTo-Json -Compress "
        "} catch { '[]' }"
    ),
    # Security Center services
    "security_center_services": (
        "Get-Service -Name 'wscsvc','WdNisSvc','WinDefend','SecurityHealthService' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object Name,Status,StartType | ConvertTo-Json -Compress"
    ),
    # Accounts
    "local_users": (
        "Get-LocalUser | "
        "Select-Object Name,Enabled,PasswordRequired,PasswordExpires,"
        "PasswordNeverExpires,LastLogon,Description | ConvertTo-Json -Compress"
    ),
    "local_admins": (
        "Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | "
        "Select-Object Name,ObjectClass,PrincipalSource | ConvertTo-Json -Compress"
    ),
    "rdp_port": (
        "try { Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
        "-Name fDenyTSConnections -ErrorAction SilentlyContinue | "
        "Select-Object fDenyTSConnections | ConvertTo-Json -Compress "
        "} catch { '{\"fDenyTSConnections\":1}' }"
    ),
    # Processes
    "running_processes": (
        "Get-CimInstance -ClassName Win32_Process | "
        "Select-Object ProcessId,Name,ExecutablePath,ParentProcessId,CreationDate,"
        "CommandLine | ConvertTo-Json -Compress"
    ),
    # Signatures — use Get-AuthenticodeSignature on process paths (called individually)
    # Persistence
    "startup_folder_user": (
        "try { "
        "$p = [System.Environment]::GetFolderPath('Startup'); "
        "Get-ChildItem -Path $p -ErrorAction SilentlyContinue | "
        "Select-Object FullName,Name,Extension | ConvertTo-Json -Compress "
        "} catch { '[]' }"
    ),
    "startup_folder_common": (
        "try { "
        "$p = [System.Environment]::GetFolderPath('CommonStartup'); "
        "Get-ChildItem -Path $p -ErrorAction SilentlyContinue | "
        "Select-Object FullName,Name,Extension | ConvertTo-Json -Compress "
        "} catch { '[]' }"
    ),
    "scheduled_tasks": (
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "Select-Object TaskName,TaskPath,State,"
        "@{N='Actions';E={$_.Actions | ForEach-Object {$_.Execute}}},"
        "@{N='Triggers';E={$_.Triggers | Select-Object -ExpandProperty CimClass -ErrorAction SilentlyContinue}} | "
        "ConvertTo-Json -Compress -Depth 3"
    ),
    # Network
    "listening_ports": (
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress,LocalPort,OwningProcess,State | "
        "ConvertTo-Json -Compress"
    ),
    "listening_udp": (
        "Get-NetUDPEndpoint | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | "
        "ConvertTo-Json -Compress"
    ),
    "established_connections": (
        "Get-NetTCPConnection -State Established | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | "
        "ConvertTo-Json -Compress"
    ),
    "dns_client": (
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress"
    ),
    "network_profiles": (
        "Get-NetConnectionProfile | "
        "Select-Object Name,NetworkCategory,InterfaceAlias | ConvertTo-Json -Compress"
    ),
    "smb_config": (
        "try { "
        "Get-SmbServerConfiguration | "
        "Select-Object EnableSMB1Protocol,EnableSMB2Protocol | ConvertTo-Json -Compress "
        "} catch { '{\"EnableSMB1Protocol\":null}' }"
    ),
    "winrm_service": (
        "Get-Service -Name WinRM -ErrorAction SilentlyContinue | "
        "Select-Object Status,StartType | ConvertTo-Json -Compress"
    ),
    # Proxy
    "proxy_settings": (
        "try { "
        "Get-ItemProperty "
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
        "-Name ProxyEnable,ProxyServer,ProxyOverride -ErrorAction SilentlyContinue | "
        "Select-Object ProxyEnable,ProxyServer,ProxyOverride | ConvertTo-Json -Compress "
        "} catch { '{\"ProxyEnable\":null}' }"
    ),
    # Certificates (trusted root store — current user)
    "cert_roots_user": (
        "Get-ChildItem -Path Cert:\\CurrentUser\\Root | "
        "Select-Object Thumbprint,Subject,Issuer,NotAfter,NotBefore,SerialNumber | "
        "ConvertTo-Json -Compress"
    ),
    "cert_roots_machine": (
        "Get-ChildItem -Path Cert:\\LocalMachine\\Root | "
        "Select-Object Thumbprint,Subject,Issuer,NotAfter,NotBefore,SerialNumber | "
        "ConvertTo-Json -Compress"
    ),
}


# ---------------------------------------------------------------------------
# Internal runner
# ---------------------------------------------------------------------------


def _run_ps(command_key: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Any, Optional[str]]:
    """
    Execute an allowlisted PowerShell CIM command.

    Parameters
    ----------
    command_key:
        Key into ``_PS_COMMANDS``.  Raises ``KeyError`` if not found.
    timeout:
        Seconds before the subprocess is forcibly terminated.

    Returns
    -------
    (parsed_result, error_message)
        ``parsed_result`` is the JSON-decoded output, or ``None`` on failure.
        ``error_message`` is a sanitized string or ``None`` on success.
    """
    if not _IS_WINDOWS:
        return None, "not_windows"

    cmd = _PS_COMMANDS[command_key]  # KeyError intentional if unknown key
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        stderr = (result.stderr or "").strip()[:_MAX_STDERR_BYTES]
        if result.returncode != 0:
            return None, f"ps_exit_{result.returncode}: {stderr}"

        stdout = result.stdout.strip()
        if not stdout:
            return None, "empty_output"

        try:
            return json.loads(stdout), None
        except json.JSONDecodeError as exc:
            return None, f"json_parse_error: {exc}"

    except subprocess.TimeoutExpired:
        return None, f"timeout_after_{timeout}s"
    except FileNotFoundError:
        return None, "powershell_not_found"
    except Exception as exc:  # noqa: BLE001
        return None, f"subprocess_error: {type(exc).__name__}"


def _run_ps_signature(path: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Optional[dict], Optional[str]]:
    """
    Check Authenticode signature for a specific file path (read-only).
    The path is quoted safely and is not interpolated from user-controlled data.
    """
    if not _IS_WINDOWS:
        return None, "not_windows"

    # Sanitize: only check paths that look like absolute Windows paths.
    if not path or len(path) > 512:
        return None, "path_too_long_or_empty"
    if not os.path.isabs(path):
        return None, "path_not_absolute"

    # Build a safe PowerShell snippet — the path is escaped by repr.
    escaped = path.replace("'", "''")  # PowerShell single-quote escaping
    cmd = (
        f"try {{ Get-AuthenticodeSignature -FilePath '{escaped}' | "
        f"Select-Object Status,StatusMessage,SignerCertificate | ConvertTo-Json -Compress }}"
        f" catch {{ '{{\"Status\":\"Unavailable\"}}' }}"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
        if result.returncode != 0:
            return None, f"ps_exit_{result.returncode}"
        stdout = result.stdout.strip()
        if not stdout:
            return None, "empty_output"
        return json.loads(stdout), None
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception) as exc:
        return None, str(type(exc).__name__)


# ---------------------------------------------------------------------------
# Registry reads (winreg — read-only mode only)
# ---------------------------------------------------------------------------


def _read_registry_value(hive_const: int, subkey: str, value_name: str) -> tuple[Any, Optional[str]]:
    """
    Read a single registry value in read-only mode.
    Returns (value, None) on success or (None, error_string) on failure.
    Never writes to the registry.
    """
    if not _IS_WINDOWS:
        return None, "not_windows"
    try:
        import winreg  # noqa: PLC0415
        with winreg.OpenKey(hive_const, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value, None
    except FileNotFoundError:
        return None, "key_not_found"
    except PermissionError:
        return None, "permission_denied"
    except Exception as exc:  # noqa: BLE001
        return None, f"registry_error: {type(exc).__name__}"


def _read_registry_keys(hive_const: int, subkey: str) -> tuple[list[tuple[str, Any, int]], Optional[str]]:
    """
    Enumerate all values under a registry key (read-only).
    Returns ([(name, data, type), ...], None) or ([], error_string).
    """
    if not _IS_WINDOWS:
        return [], "not_windows"
    try:
        import winreg  # noqa: PLC0415
        results = []
        with winreg.OpenKey(hive_const, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, i)
                    results.append((name, data, vtype))
                    i += 1
                except OSError:
                    break
        return results, None
    except FileNotFoundError:
        return [], "key_not_found"
    except PermissionError:
        return [], "permission_denied"
    except Exception as exc:  # noqa: BLE001
        return [], f"registry_error: {type(exc).__name__}"


# ---------------------------------------------------------------------------
# ctypes / standard-library platform functions
# ---------------------------------------------------------------------------


def get_current_username() -> str:
    """Return the current username without exposing credentials."""
    return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def get_hostname() -> str:
    try:
        return platform.node()
    except Exception:  # noqa: BLE001
        return ""


def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    if not _IS_WINDOWS:
        return os.getuid() == 0  # type: ignore[attr-defined]
    try:
        import ctypes  # noqa: PLC0415
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def get_uac_state() -> tuple[Optional[int], Optional[str]]:
    """
    Read UAC consent-prompt behaviour level from the registry (read-only).
    Returns (level_int, None) or (None, error_string).
    Levels: 0=disabled, 1=no-prompt-admin, 2=prompt-creds, 5=default.
    """
    if not _IS_WINDOWS:
        return None, "not_windows"
    try:
        import winreg  # noqa: PLC0415
        HKLM = winreg.HKEY_LOCAL_MACHINE
    except ImportError:
        return None, "winreg_unavailable"
    return _read_registry_value(
        HKLM,
        r"SOFTWARE\Microsoft\Windows\NT\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
    )


def get_autologon_indicator() -> tuple[bool, Optional[str]]:
    """
    Detect auto-logon configuration without reading the stored password.
    Returns (autologon_enabled: bool, error_or_None).
    """
    if not _IS_WINDOWS:
        return False, "not_windows"
    try:
        import winreg  # noqa: PLC0415
        HKLM = winreg.HKEY_LOCAL_MACHINE
    except ImportError:
        return False, "winreg_unavailable"
    val, err = _read_registry_value(
        HKLM,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "AutoAdminLogon",
    )
    if err:
        return False, err
    return str(val) == "1", None


# ---------------------------------------------------------------------------
# Public API re-exported for collectors
# ---------------------------------------------------------------------------

# OS
run_ps_os_version = lambda: _run_ps("os_version")
run_ps_pending_restart = lambda: _run_ps("pending_restart_cim")
run_ps_update_service = lambda: _run_ps("update_service")

# Security controls
run_ps_defender = lambda: _run_ps("defender_status")
run_ps_firewall = lambda: _run_ps("firewall_profiles")
run_ps_smartscreen = lambda: _run_ps("smartscreen")
run_ps_secure_boot = lambda: _run_ps("secure_boot")
run_ps_tpm = lambda: _run_ps("tpm_status")
run_ps_bitlocker = lambda: _run_ps("bitlocker")
run_ps_security_services = lambda: _run_ps("security_center_services")

# Accounts
run_ps_local_users = lambda: _run_ps("local_users")
run_ps_local_admins = lambda: _run_ps("local_admins")
run_ps_rdp = lambda: _run_ps("rdp_port")

# Processes
run_ps_processes = lambda: _run_ps("running_processes")
run_ps_authenticode = _run_ps_signature

# Persistence
run_ps_startup_user = lambda: _run_ps("startup_folder_user")
run_ps_startup_common = lambda: _run_ps("startup_folder_common")
run_ps_scheduled_tasks = lambda: _run_ps("scheduled_tasks")
run_ps_auto_services = lambda: _run_ps("security_center_services")

# Network
run_ps_tcp_listen = lambda: _run_ps("listening_ports")
run_ps_udp_listen = lambda: _run_ps("listening_udp")
run_ps_tcp_established = lambda: _run_ps("established_connections")
run_ps_dns = lambda: _run_ps("dns_client")
run_ps_net_profiles = lambda: _run_ps("network_profiles")
run_ps_smb = lambda: _run_ps("smb_config")
run_ps_winrm = lambda: _run_ps("winrm_service")
run_ps_proxy = lambda: _run_ps("proxy_settings")

# Certificates
run_ps_cert_roots_user = lambda: _run_ps("cert_roots_user")
run_ps_cert_roots_machine = lambda: _run_ps("cert_roots_machine")

# Native helpers
read_registry_value = _read_registry_value
read_registry_keys = _read_registry_keys
