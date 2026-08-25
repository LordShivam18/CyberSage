"""Process termination action — terminates a specified process.

Safety constraints:
- Validates PID is a positive integer
- Rejects protected/system process names
- Does not use shell=True
- Does not accept arbitrary command strings
- Verifies process is no longer active after termination
"""

from __future__ import annotations

import os
import signal
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

# Protected process names that must NEVER be terminated
PROTECTED_PROCESSES = frozenset({
    "system", "smss", "csrss", "wininit", "winlogon", "lsass",
    "services", "svchost", "dwm", "fontdrvhost", "sihost",
    "explorer", "dcomlaunch", "rpcss", "plugplay", "broker",
    # Linux system processes
    "init", "kthreadd", "systemd", "kworker", "migration",
    "rcu_sched", "watchdog", "sshd", "dbus-daemon",
})

# PIDs that must never be killed
PROTECTED_PIDS = frozenset({0, 1})


class TerminateProcessAction(BaseAction):
    """Terminate a specified process by PID.

    Target: { "pid": <int>, "process_name": <str> }
    Parameters: { "force": <bool> } (optional, default False)
    """

    @property
    def action_type(self) -> str:
        return "process"

    @property
    def action_name(self) -> str:
        return "terminate_process"

    @property
    def rollback_supported(self) -> bool:
        return False  # Cannot un-terminate a process

    def validate(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> ValidationResult:
        errors: List[str] = []

        pid = target.get("pid")
        if pid is None:
            errors.append("target.pid is required")
        elif not isinstance(pid, int) or pid <= 0:
            errors.append(f"target.pid must be a positive integer, got: {pid!r}")
        elif pid in PROTECTED_PIDS:
            errors.append(f"target.pid {pid} is a protected system PID")

        process_name = target.get("process_name", "")
        if process_name and process_name.lower() in PROTECTED_PROCESSES:
            errors.append(f"target.process_name '{process_name}' is a protected system process")

        if parameters:
            force = parameters.get("force")
            if force is not None and not isinstance(force, bool):
                errors.append("parameters.force must be a boolean")

        return ValidationResult(valid=len(errors) == 0, errors=errors)

    def snapshot(self, target: Dict[str, Any], action_id: str) -> Optional[SnapshotData]:
        # Process termination is not reversible, no meaningful snapshot
        return None

    def execute(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None,
                snapshot: Optional[SnapshotData] = None) -> ExecutionResult:
        pid = target.get("pid")
        force = (parameters or {}).get("force", False)

        try:
            if sys.platform == "win32":
                # Windows: use taskkill with explicit arguments (no shell)
                args = ["taskkill"]
                if force:
                    args.append("/F")
                args.extend(["/PID", str(pid)])
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,  # CRITICAL: shell=False
                )
                success = result.returncode == 0
                output = {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
                error = None if success else f"taskkill failed: {result.stderr}"
            else:
                # Unix: send signal
                sig = signal.SIGKILL if force else signal.SIGTERM
                try:
                    os.kill(pid, sig)
                    success = True
                    output = {"signal": sig.name, "pid": pid}
                    error = None
                except ProcessLookupError:
                    success = False
                    output = {"pid": pid, "error": "process not found"}
                    error = f"Process {pid} not found"
                except PermissionError:
                    success = False
                    output = {"pid": pid, "error": "permission denied"}
                    error = f"Permission denied to terminate process {pid}"

            return ExecutionResult(success=success, output=output, error=error)

        except subprocess.TimeoutExpired:
            return ExecutionResult(success=False, error="taskkill timed out after 30s")
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Unexpected error: {exc}")

    def verify(self, target: Dict[str, Any], execution_result: ExecutionResult) -> VerificationResult:
        pid = target.get("pid")
        checks = []

        # Check if process is still running
        if sys.platform == "win32":
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            still_running = str(pid) in result.stdout
            checks.append({
                "check": "process_terminated",
                "passed": not still_running,
                "detail": f"PID {pid} {'still running' if still_running else 'terminated'}",
            })
        else:
            try:
                os.kill(pid, 0)  # Signal 0 = check existence
                still_running = True
                checks.append({
                    "check": "process_terminated",
                    "passed": False,
                    "detail": f"PID {pid} still running",
                })
            except ProcessLookupError:
                still_running = False
                checks.append({
                    "check": "process_terminated",
                    "passed": True,
                    "detail": f"PID {pid} terminated",
                })
            except PermissionError:
                still_running = True
                checks.append({
                    "check": "process_terminated",
                    "passed": False,
                    "detail": f"Cannot verify PID {pid} (permission denied)",
                })

        all_passed = all(c["passed"] for c in checks)
        return VerificationResult(
            passed=all_passed,
            checks=checks,
            observed_state={"pid": pid, "still_running": still_running if 'still_running' in dir() else None},
            failure_reason=None if all_passed else f"Process {pid} still active after termination",
        )

    def rollback(self, target: Dict[str, Any], snapshot: SnapshotData) -> RollbackResult:
        return RollbackResult(
            success=False,
            error="Process termination is not reversible",
        )

    def describe(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> str:
        pid = target.get("pid", "?")
        name = target.get("process_name", "unknown")
        force = (parameters or {}).get("force", False)
        mode = "force kill" if force else "terminate"
        return f"Terminate process {name} (PID {pid}) using {mode}"
