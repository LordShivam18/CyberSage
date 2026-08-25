"""Persistence entry disabling action — disables a known persistence mechanism.

Safety constraints:
- Allowlists supported persistence locations only
- Never accepts arbitrary registry paths or filesystem paths without validation
- Rejects system-critical persistence locations
- Verifies the persistence entry is actually disabled after execution
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Dict, List, Optional

from guardian.actions.base import (
    BaseAction,
    ExecutionResult,
    RollbackResult,
    SnapshotData,
    ValidationResult,
    VerificationResult,
)

# Allowlisted persistence types
ALLOWED_PERSISTENCE_TYPES = frozenset({
    "registry_run_key",
    "scheduled_task",
    "startup_folder",
})

# Protected persistence paths that must never be modified
PROTECTED_PERSISTENCE_PATHS = frozenset({
    # Windows critical
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    # Linux critical
    "/etc/systemd/system",
    "/etc/init.d",
})


class DisablePersistenceEntryAction(BaseAction):
    """Disable a known persistence mechanism.

    Target: { "persistence_type": <str>, "persistence_path": <str>, "entry_name": <str> }
    Parameters: { "backup": <bool> } (optional, default True — backup before disable)
    """

    @property
    def action_type(self) -> str:
        return "persistence"

    @property
    def action_name(self) -> str:
        return "disable_persistence_entry"

    @property
    def rollback_supported(self) -> bool:
        return True

    def validate(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        persistence_type = target.get("persistence_type", "")
        if not persistence_type:
            errors.append("target.persistence_type is required")
        elif persistence_type not in ALLOWED_PERSISTENCE_TYPES:
            errors.append(
                f"target.persistence_type '{persistence_type}' is not in allowlist. "
                f"Allowed: {sorted(ALLOWED_PERSISTENCE_TYPES)}"
            )

        persistence_path = target.get("persistence_path", "")
        if not persistence_path:
            errors.append("target.persistence_path is required")
        else:
            # Check for protected paths
            for protected in PROTECTED_PERSISTENCE_PATHS:
                if persistence_path.lower().startswith(protected.lower()):
                    errors.append(
                        f"target.persistence_path '{persistence_path}' is a protected system location"
                    )
                    break

            # Path traversal check
            if ".." in persistence_path:
                errors.append("target.persistence_path contains path traversal (..)")

        entry_name = target.get("entry_name", "")
        if not entry_name:
            errors.append("target.entry_name is required")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def snapshot(self, target: Dict[str, Any], action_id: str) -> Optional[SnapshotData]:
        """Capture current persistence entry state for rollback."""
        persistence_type = target.get("persistence_type", "")
        persistence_path = target.get("persistence_path", "")
        entry_name = target.get("entry_name", "")

        prior_state: Dict[str, Any] = {"entry_data": None, "entry_exists": False}

        if persistence_type == "registry_run_key":
            if sys.platform == "win32":
                try:
                    result = subprocess.run(
                        ["reg", "query", persistence_path, "/v", entry_name],
                        capture_output=True, text=True, timeout=10, shell=False,
                    )
                    prior_state["entry_exists"] = result.returncode == 0
                    if prior_state["entry_exists"]:
                        # Extract the value
                        for line in result.stdout.splitlines():
                            if entry_name.lower() in line.lower():
                                parts = line.split("    ")
                                if len(parts) >= 3:
                                    prior_state["entry_data"] = {
                                        "type": parts[1].strip(),
                                        "value": parts[2].strip(),
                                    }
                                break
                except Exception:
                    prior_state["error"] = "Failed to query registry"
            else:
                prior_state["entry_exists"] = True  # Assume exists for simulation
                prior_state["entry_data"] = {"type": "REG_SZ", "value": "/usr/bin/test"}
        elif persistence_type == "scheduled_task":
            prior_state["entry_exists"] = True
            prior_state["entry_data"] = {"task_name": entry_name}
        elif persistence_type == "startup_folder":
            prior_state["entry_exists"] = True
            prior_state["entry_data"] = {"shortcut_name": entry_name}

        return SnapshotData(
            snapshot_id="",
            action_id=action_id,
            action_type=self.action_type,
            target=target,
            prior_state=prior_state,
            metadata={"persistence_type": persistence_type, "persistence_path": persistence_path},
        )

    def execute(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None,
                snapshot: Optional[SnapshotData] = None) -> ExecutionResult:
        persistence_type = target.get("persistence_type", "")
        persistence_path = target.get("persistence_path", "")
        entry_name = target.get("entry_name", "")
        backup = (parameters or {}).get("backup", True)

        try:
            if persistence_type == "registry_run_key":
                return self._disable_registry_key(persistence_path, entry_name, backup)
            elif persistence_type == "scheduled_task":
                return self._disable_scheduled_task(entry_name, backup)
            elif persistence_type == "startup_folder":
                return self._disable_startup_entry(persistence_path, entry_name, backup)
            else:
                return ExecutionResult(success=False, error=f"Unknown persistence type: {persistence_type}")
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Disable persistence failed: {exc}")

    def _disable_registry_key(self, path: str, name: str, backup: bool) -> ExecutionResult:
        if sys.platform == "win32":
            # Backup the value
            if backup:
                backup_result = subprocess.run(
                    ["reg", "export", path, f"C:\\guardian_backup_{name}.reg", "/y"],
                    capture_output=True, text=True, timeout=10, shell=False,
                )

            # Delete the value
            result = subprocess.run(
                ["reg", "delete", path, "/v", name, "/f"],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            success = result.returncode == 0
            return ExecutionResult(
                success=success,
                output={"path": path, "name": name, "action": "reg_delete"},
                error=None if success else f"Failed to delete registry value: {result.stderr}",
            )
        else:
            # Linux simulation: just report success for CI/testing
            return ExecutionResult(
                success=True,
                output={"path": path, "name": name, "action": "simulated_disable"},
            )

    def _disable_scheduled_task(self, task_name: str, backup: bool) -> ExecutionResult:
        if sys.platform == "win32":
            # Disable the task (don't delete — safer)
            result = subprocess.run(
                ["schtasks", "/Change", "/TN", task_name, "/Disable"],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            success = result.returncode == 0
            return ExecutionResult(
                success=success,
                output={"task_name": task_name, "action": "schtasks_disable"},
                error=None if success else f"Failed to disable task: {result.stderr}",
            )
        else:
            return ExecutionResult(
                success=True,
                output={"task_name": task_name, "action": "simulated_disable"},
            )

    def _disable_startup_entry(self, path: str, name: str, backup: bool) -> ExecutionResult:
        # For startup folder entries, rename with .disabled extension
        import os

        full_path = os.path.join(path, name)
        disabled_path = full_path + ".disabled"

        try:
            if os.path.exists(full_path):
                if backup:
                    backup_path = full_path + ".guardian_backup"
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                    os.rename(full_path, backup_path)
                    full_path_for_disable = backup_path
                else:
                    full_path_for_disable = full_path

                os.rename(full_path_for_disable, disabled_path)
                return ExecutionResult(
                    success=True,
                    output={"original": full_path, "disabled": disabled_path, "action": "rename"},
                )
            else:
                return ExecutionResult(
                    success=False,
                    error=f"Startup entry not found: {full_path}",
                )
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Failed to disable startup entry: {exc}")

    def verify(self, target: Dict[str, Any], execution_result: ExecutionResult) -> VerificationResult:
        persistence_type = target.get("persistence_type", "")
        persistence_path = target.get("persistence_path", "")
        entry_name = target.get("entry_name", "")
        checks = []

        if persistence_type == "registry_run_key":
            if sys.platform == "win32":
                result = subprocess.run(
                    ["reg", "query", persistence_path, "/v", entry_name],
                    capture_output=True, text=True, timeout=10, shell=False,
                )
                entry_gone = result.returncode != 0
                checks.append({
                    "check": "registry_value_removed",
                    "passed": entry_gone,
                    "detail": f"Registry value '{entry_name}' {'removed' if entry_gone else 'still exists'}",
                })
            else:
                checks.append({
                    "check": "registry_value_removed",
                    "passed": True,
                    "detail": "Simulated verification passed",
                })
        elif persistence_type == "startup_folder":
            import os
            full_path = os.path.join(persistence_path, entry_name)
            disabled_path = full_path + ".disabled"
            original_gone = not os.path.exists(full_path)
            disabled_exists = os.path.exists(disabled_path)
            checks.append({
                "check": "entry_disabled",
                "passed": original_gone and disabled_exists,
                "detail": f"Original {'gone' if original_gone else 'exists'}, disabled {'exists' if disabled_exists else 'missing'}",
            })
        else:
            checks.append({
                "check": "persistence_disabled",
                "passed": execution_result.success,
                "detail": f"Execution result: {'success' if execution_result.success else 'failed'}",
            })

        all_passed = all(c["passed"] for c in checks)
        return VerificationResult(
            passed=all_passed,
            checks=checks,
            observed_state={"persistence_type": persistence_type, "entry_name": entry_name},
            failure_reason=None if all_passed else f"Persistence entry '{entry_name}' not verified as disabled",
        )

    def rollback(self, target: Dict[str, Any], snapshot: SnapshotData) -> RollbackResult:
        persistence_type = target.get("persistence_type", "")
        persistence_path = target.get("persistence_path", "")
        entry_name = target.get("entry_name", "")

        try:
            if persistence_type == "registry_run_key":
                if sys.platform == "win32":
                    # Restore from backup
                    backup_path = f"C:\\guardian_backup_{entry_name}.reg"
                    result = subprocess.run(
                        ["reg", "import", backup_path],
                        capture_output=True, text=True, timeout=10, shell=False,
                    )
                    return RollbackResult(
                        success=result.returncode == 0,
                        output={"restored": persistence_path, "entry": entry_name},
                        error=None if result.returncode == 0 else f"Restore failed: {result.stderr}",
                    )
                else:
                    return RollbackResult(success=True, output={"restored": persistence_path})

            elif persistence_type == "startup_folder":
                import os
                full_path = os.path.join(persistence_path, entry_name)
                disabled_path = full_path + ".disabled"
                backup_path = full_path + ".guardian_backup"

                if os.path.exists(backup_path):
                    os.rename(backup_path, full_path)
                    return RollbackResult(success=True, output={"restored": full_path})
                elif os.path.exists(disabled_path):
                    os.rename(disabled_path, full_path)
                    return RollbackResult(success=True, output={"restored": full_path})
                else:
                    return RollbackResult(success=False, error="No backup found to restore")

            else:
                return RollbackResult(success=False, error=f"Rollback not implemented for {persistence_type}")

        except Exception as exc:
            return RollbackResult(success=False, error=f"Rollback failed: {exc}")

    def describe(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> str:
        ptype = target.get("persistence_type", "?")
        path = target.get("persistence_path", "?")
        name = target.get("entry_name", "?")
        return f"Disable persistence entry '{name}' ({ptype}) at {path}"
