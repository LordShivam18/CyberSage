"""
Collector 7 of 8 — Browser posture.

Gathers installed browser versions and extension inventories for
Chrome, Edge, and Firefox.  Discovered via registry and known
profile-path locations.

Safety rules
------------
* History, cookies, saved passwords, form data, and browsing
  contents are NEVER read.
* Only the extensions metadata files (JSON manifests) are read.
* No browser process is launched or modified.
* No network requests are made to validate extension identifiers.

Limitations
-----------
* Detection depends on standard installation paths and registry entries.
  Portable or non-standard browser installations may not be detected.
* Extension metadata reflects the state at collection time only.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional

from .base import Collector

# Registry paths for installed browser detection (read-only).
_BROWSER_REGISTRY = {
    "chrome": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
    ],
    "edge": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
    ],
    "firefox": [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe",
    ],
}

# Known extension directories relative to profile root.
_CHROME_EXT_REL = "Extensions"
_FIREFOX_EXT_REL = os.path.join("extensions")

# Maximum extensions to enumerate per browser (prevent runaway I/O).
_MAX_EXTENSIONS = 200


def _read_registry_string(subkey: str, value_name: str = "") -> Optional[str]:
    """Read a string registry value from HKLM (read-only)."""
    if sys.platform != "win32":
        return None
    try:
        import winreg  # noqa: PLC0415
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, value_name)
            return str(val)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _safe_read_json(path: str, max_bytes: int = 65536) -> Optional[dict]:
    """Read and parse a JSON file with a size cap.  Never executes file content."""
    try:
        p = Path(path)
        if p.stat().st_size > max_bytes:
            return None
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return json.loads(fh.read())
    except Exception:  # noqa: BLE001
        return None


def _get_chrome_profile_dirs(browser: str) -> list[Path]:
    """Return Chrome/Edge user profile directories."""
    local_app = os.environ.get("LOCALAPPDATA", "")
    if not local_app:
        return []
    if browser == "chrome":
        base = Path(local_app) / "Google" / "Chrome" / "User Data"
    else:  # edge
        base = Path(local_app) / "Microsoft" / "Edge" / "User Data"
    if not base.exists():
        return []
    dirs = [base / "Default"]
    # Also find Profile 1, Profile 2, etc.
    try:
        for item in base.iterdir():
            if item.is_dir() and re.match(r"^Profile \d+$", item.name):
                dirs.append(item)
    except PermissionError:
        pass
    return [d for d in dirs if d.exists()]


def _enumerate_chrome_extensions(profile_dir: Path, browser: str) -> list[dict[str, Any]]:
    ext_dir = profile_dir / _CHROME_EXT_REL
    if not ext_dir.exists():
        return []
    results: list[dict[str, Any]] = []
    try:
        for ext_id in list(ext_dir.iterdir())[:_MAX_EXTENSIONS]:
            if not ext_id.is_dir():
                continue
            # Find the highest version subdirectory
            try:
                versions = sorted(
                    [v for v in ext_id.iterdir() if v.is_dir()],
                    key=lambda v: v.name, reverse=True
                )
            except PermissionError:
                continue
            if not versions:
                continue
            manifest_path = versions[0] / "manifest.json"
            manifest = _safe_read_json(str(manifest_path))
            if manifest is None:
                continue
            results.append({
                "browser": browser,
                "extension_id": ext_id.name,
                "name": str(manifest.get("name", ""))[:256],
                "version": str(manifest.get("version", ""))[:64],
                "description": str(manifest.get("description", ""))[:512],
                "permissions": [str(p)[:128] for p in (manifest.get("permissions") or [])[:20]],
                "update_url": str(manifest.get("update_url") or "")[:512],
                "unpacked": not bool(manifest.get("update_url")),  # no update_url → likely developer/unpacked
            })
    except PermissionError:
        pass
    return results


def _get_firefox_profile_dirs() -> list[Path]:
    """Find Firefox profile directories."""
    app_data = os.environ.get("APPDATA", "")
    if not app_data:
        return []
    profiles_ini = Path(app_data) / "Mozilla" / "Firefox" / "profiles.ini"
    if not profiles_ini.exists():
        return []
    base_dir = profiles_ini.parent
    # Simple ini parsing — no configparser to avoid import overhead.
    dirs: list[Path] = []
    try:
        with profiles_ini.open("r", encoding="utf-8", errors="replace") as fh:
            path_val: Optional[str] = None
            is_relative = True
            for line in fh:
                line = line.strip()
                if line.lower().startswith("path="):
                    path_val = line.split("=", 1)[1]
                elif line.lower().startswith("isrelative="):
                    is_relative = line.split("=", 1)[1].strip() == "1"
                elif line.startswith("[") and path_val:
                    full = base_dir / path_val if is_relative else Path(path_val)
                    if full.exists():
                        dirs.append(full)
                    path_val = None
                    is_relative = True
            if path_val:
                full = base_dir / path_val if is_relative else Path(path_val)
                if full.exists():
                    dirs.append(full)
    except (PermissionError, OSError):
        pass
    return dirs


def _enumerate_firefox_extensions(profile_dir: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    addons_json_path = profile_dir / "addons.json"
    addons_data = _safe_read_json(str(addons_json_path))
    if not addons_data:
        return results
    addons = addons_data.get("addons") or []
    for addon in addons[:_MAX_EXTENSIONS]:
        results.append({
            "browser": "firefox",
            "extension_id": str(addon.get("id", ""))[:256],
            "name": str(addon.get("name", ""))[:256],
            "version": str(addon.get("version", ""))[:64],
            "description": str(addon.get("description", ""))[:512],
            "permissions": [str(p)[:128] for p in (addon.get("permissions") or [])[:20]],
            "update_url": str(addon.get("updateURL") or "")[:512],
            "unpacked": addon.get("location") == "app-profile",
            "active": addon.get("active", False),
        })
    return results


def _detect_browser_version(browser: str) -> Optional[str]:
    """Read browser version from known registry paths (read-only)."""
    if sys.platform != "win32":
        return None
    version_keys = {
        "chrome": r"SOFTWARE\Google\Chrome\BLBeacon",
        "edge": r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
        "firefox": r"SOFTWARE\Mozilla\Mozilla Firefox",
    }
    key = version_keys.get(browser)
    if not key:
        return None
    if browser == "firefox":
        return _read_registry_string(key, "CurrentVersion")
    return _read_registry_string(key, "pv")


class BrowserCollector(Collector):
    name = "browser"
    description = (
        "Installed browser versions and extension inventories for "
        "Chrome, Edge, and Firefox.  History, cookies, and passwords are not accessed."
    )
    requires_admin = False

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        data: dict[str, Any] = {"browsers": [], "extensions": []}

        for browser in ("chrome", "edge", "firefox"):
            version = _detect_browser_version(browser)
            entry: dict[str, Any] = {
                "browser": browser,
                "detected": version is not None,
                "version": version,
            }
            data["browsers"].append(entry)

            if version is None:
                continue  # Not installed or not detectable

            # Enumerate extensions
            if browser in ("chrome", "edge"):
                for profile in _get_chrome_profile_dirs(browser):
                    try:
                        exts = _enumerate_chrome_extensions(profile, browser)
                        data["extensions"].extend(exts)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"{browser}_extensions: {type(exc).__name__}")
            elif browser == "firefox":
                for profile in _get_firefox_profile_dirs():
                    try:
                        exts = _enumerate_firefox_extensions(profile)
                        data["extensions"].extend(exts)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"firefox_extensions: {type(exc).__name__}")

        return data, errors, False
