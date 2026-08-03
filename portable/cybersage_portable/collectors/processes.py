"""
Collector 4 of 8 — Running processes.

Gathers: process inventory including executable paths, parent PIDs,
creation times, and Authenticode signature states.

Limitations
-----------
* Authenticode signature information is collected only for processes with
  accessible, absolute executable paths.  Unsigned executables are flagged
  as informational only — being unsigned is not evidence of malice.
* Process command-line arguments are collected for finding_id construction
  only and are NEVER written to reports (privacy rule).  Redaction of
  command lines is handled by the privacy module.
* finding_id for process findings is derived from the normalized executable
  path, NOT from the PID, which is volatile.
* This collector does not terminate, suspend, or modify any process.
"""

from __future__ import annotations

import os
import re
from typing import Any

from ..platform_abstraction import run_ps_authenticode, run_ps_processes
from .base import Collector

# Directories that are suspicious execution locations for most executables.
_SUSPICIOUS_DIRS: frozenset[str] = frozenset({
    "temp", "tmp", "appdata\\local\\temp", "downloads", "desktop",
    "users\\public", "programdata",
})

# Limit the number of processes for which we check signatures (performance).
_MAX_SIGNATURE_CHECKS = 50


def _normalize_path(path: str) -> str:
    """Return a lowercase, normalized absolute path for use as a stable key."""
    if not path:
        return ""
    return os.path.normcase(os.path.normpath(path.strip()))


def _in_suspicious_dir(path: str) -> bool:
    """Return True if the path is in a directory commonly abused for execution."""
    if not path:
        return False
    lower = path.lower().replace("/", "\\")
    return any(sus in lower for sus in _SUSPICIOUS_DIRS)


class ProcessesCollector(Collector):
    name = "processes"
    description = (
        "Running process inventory: executable paths, parent process IDs, "
        "creation times, and Authenticode signature states."
    )
    requires_admin = False  # Full path access may require elevation in some cases.

    def _collect_impl(self) -> tuple[dict[str, Any], list[str], bool]:
        errors: list[str] = []
        data: dict[str, Any] = {}

        procs_raw, err = run_ps_processes()
        if err:
            errors.append(f"processes: {err}")
            data["processes"] = []
            return data, errors, "permission_denied" in (err or "")

        if procs_raw is None:
            data["processes"] = []
            return data, errors, False

        if isinstance(procs_raw, dict):
            procs_raw = [procs_raw]

        # Normalise and annotate each process entry.
        processes: list[dict[str, Any]] = []
        signature_candidates: list[str] = []

        for p in (procs_raw or []):
            exe = str(p.get("ExecutablePath") or "").strip()
            norm_path = _normalize_path(exe)
            entry: dict[str, Any] = {
                "pid": p.get("ProcessId"),
                "name": str(p.get("Name") or ""),
                "exe_path": exe,
                "exe_path_normalized": norm_path,
                "parent_pid": p.get("ParentProcessId"),
                "created_at": str(p.get("CreationDate") or ""),
                # Command-line is collected for path normalization only;
                # it is truncated here to prevent inadvertent credential capture.
                "cmdline_available": bool(p.get("CommandLine")),
                "in_suspicious_dir": _in_suspicious_dir(exe),
                "signature": None,  # populated below
            }
            processes.append(entry)
            if norm_path and len(signature_candidates) < _MAX_SIGNATURE_CHECKS:
                signature_candidates.append(norm_path)

        # Collect signatures for unique paths only (read-only Authenticode check).
        seen: set[str] = set()
        sig_map: dict[str, Any] = {}
        for path in signature_candidates:
            if path in seen or not os.path.isabs(path):
                continue
            seen.add(path)
            sig, sig_err = run_ps_authenticode(path, timeout=10)
            if sig_err:
                sig_map[path] = {"Status": "Unavailable", "error": sig_err}
            else:
                sig_map[path] = sig

        # Attach signatures to process entries.
        for entry in processes:
            norm = entry["exe_path_normalized"]
            if norm in sig_map:
                sig_data = sig_map[norm]
                entry["signature"] = {
                    "status": (sig_data or {}).get("Status"),
                    "message": (sig_data or {}).get("StatusMessage"),
                }

        data["processes"] = processes
        data["signature_checks_performed"] = len(seen)
        return data, errors, False
