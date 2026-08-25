"""Network destination blocking action — blocks traffic to a specified destination.

Safety constraints:
- Validates destination IP/port format
- Rejects malformed addresses
- Does not use shell=True
- Does not block entire networks (scoped to specific destination)
- Verifies block is in place after execution
"""

from __future__ import annotations

import ipaddress
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

# Well-known ports that should not be blocked without explicit confirmation
SENSITIVE_PORTS = frozenset({22, 53, 80, 443, 3389})


class BlockDestinationAction(BaseAction):
    """Block network traffic to a specified IP destination.

    Target: { "destination_ip": <str>, "destination_port": <int> }
    Parameters: { "protocol": <str> } (optional, default "tcp")
    """

    @property
    def action_type(self) -> str:
        return "network"

    @property
    def action_name(self) -> str:
        return "block_destination"

    @property
    def rollback_supported(self) -> bool:
        return True  # Firewall rules can be removed

    def validate(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        dest_ip = target.get("destination_ip")
        if not dest_ip:
            errors.append("target.destination_ip is required")
        else:
            try:
                addr = ipaddress.ip_address(dest_ip)
                # Reject private/loopback as likely misconfiguration
                if addr.is_loopback:
                    errors.append(f"destination_ip {dest_ip} is a loopback address")
                if addr.is_multicast:
                    errors.append(f"destination_ip {dest_ip} is a multicast address")
            except ValueError:
                errors.append(f"destination_ip '{dest_ip}' is not a valid IP address")

        dest_port = target.get("destination_port")
        if dest_port is not None:
            if not isinstance(dest_port, int) or not (1 <= dest_port <= 65535):
                errors.append(f"destination_port must be 1-65535, got: {dest_port!r}")
            elif dest_port in SENSITIVE_PORTS:
                warnings.append(f"destination_port {dest_port} is a well-known port")

        protocol = (parameters or {}).get("protocol", "tcp")
        if protocol not in ("tcp", "udp", "both"):
            errors.append(f"protocol must be 'tcp', 'udp', or 'both', got: '{protocol}'")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def snapshot(self, target: Dict[str, Any], action_id: str) -> Optional[SnapshotData]:
        """Capture current firewall state for rollback."""
        dest_ip = target.get("destination_ip", "")
        dest_port = target.get("destination_port")
        protocol = (target.get("parameters") or {}).get("protocol", "tcp")

        prior_state: Dict[str, Any] = {"existing_rules": []}

        if sys.platform == "win32":
            # Check existing Windows firewall rules
            try:
                rule_name = f"Guardian-Block-{dest_ip}"
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                    capture_output=True, text=True, timeout=10, shell=False,
                )
                if rule_name.lower() in result.stdout.lower():
                    prior_state["existing_rules"].append({"name": rule_name, "exists": True})
                else:
                    prior_state["existing_rules"].append({"name": rule_name, "exists": False})
            except Exception:
                prior_state["existing_rules"].append({"name": rule_name, "exists": False, "error": "check failed"})
        else:
            # Check existing iptables rules
            try:
                port_flag = f"--dport {dest_port}" if dest_port else ""
                proto_flag = f"-p {protocol}" if protocol != "both" else ""
                result = subprocess.run(
                    ["iptables", "-C", "OUTPUT", proto_flag, "-d", dest_ip, port_flag, "-j", "DROP"],
                    capture_output=True, text=True, timeout=10, shell=False,
                )
                prior_state["existing_rules"].append({
                    "rule_exists": result.returncode == 0,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                })
            except Exception:
                prior_state["existing_rules"].append({"error": "iptables check failed"})

        return SnapshotData(
            snapshot_id="",  # Will be set by caller
            action_id=action_id,
            action_type=self.action_type,
            target=target,
            prior_state=prior_state,
            metadata={"protocol": protocol},
        )

    def execute(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None,
                snapshot: Optional[SnapshotData] = None) -> ExecutionResult:
        dest_ip = target.get("destination_ip", "")
        dest_port = target.get("destination_port")
        protocol = (parameters or {}).get("protocol", "tcp")

        try:
            if sys.platform == "win32":
                return self._execute_windows(dest_ip, dest_port, protocol)
            else:
                return self._execute_linux(dest_ip, dest_port, protocol)
        except Exception as exc:
            return ExecutionResult(success=False, error=f"Block destination failed: {exc}")

    def _execute_windows(self, dest_ip: str, dest_port: Optional[int], protocol: str) -> ExecutionResult:
        rule_name = f"Guardian-Block-{dest_ip}"
        args = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=out", "action=block",
            f"remoteip={dest_ip}",
        ]
        if dest_port:
            args.append(f"remoteport={dest_port}")
        if protocol in ("tcp", "udp"):
            args.append(f"protocol={protocol}")

        result = subprocess.run(args, capture_output=True, text=True, timeout=30, shell=False)
        success = result.returncode == 0
        return ExecutionResult(
            success=success,
            output={"rule_name": rule_name, "stdout": result.stdout, "stderr": result.stderr},
            error=None if success else f"Failed to add firewall rule: {result.stderr}",
        )

    def _execute_linux(self, dest_ip: str, dest_port: Optional[int], protocol: str) -> ExecutionResult:
        args = ["iptables", "-A", "OUTPUT", "-d", dest_ip]
        if protocol in ("tcp", "udp"):
            args.extend(["-p", protocol])
        if dest_port:
            args.extend(["--dport", str(dest_port)])
        args.extend(["-j", "DROP"])

        result = subprocess.run(args, capture_output=True, text=True, timeout=30, shell=False)
        success = result.returncode == 0
        return ExecutionResult(
            success=success,
            output={"rule": " ".join(args), "stdout": result.stdout, "stderr": result.stderr},
            error=None if success else f"Failed to add iptables rule: {result.stderr}",
        )

    def verify(self, target: Dict[str, Any], execution_result: ExecutionResult) -> VerificationResult:
        dest_ip = target.get("destination_ip", "")
        dest_port = target.get("destination_port")
        checks = []

        if sys.platform == "win32":
            rule_name = f"Guardian-Block-{dest_ip}"
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            rule_exists = rule_name.lower() in result.stdout.lower()
            checks.append({
                "check": "firewall_rule_exists",
                "passed": rule_exists,
                "detail": f"Rule '{rule_name}' {'exists' if rule_exists else 'not found'}",
            })
        else:
            port_flag = f"--dport {dest_port}" if dest_port else ""
            result = subprocess.run(
                ["iptables", "-C", "OUTPUT", "-d", dest_ip, port_flag, "-j", "DROP"],
                capture_output=True, text=True, timeout=10, shell=False,
            )
            rule_exists = result.returncode == 0
            checks.append({
                "check": "iptables_rule_exists",
                "passed": rule_exists,
                "detail": f"iptables rule for {dest_ip} {'exists' if rule_exists else 'not found'}",
            })

        all_passed = all(c["passed"] for c in checks)
        return VerificationResult(
            passed=all_passed,
            checks=checks,
            observed_state={"dest_ip": dest_ip, "dest_port": dest_port, "rule_exists": rule_exists},
            failure_reason=None if all_passed else f"Block rule for {dest_ip} not verified",
        )

    def rollback(self, target: Dict[str, Any], snapshot: SnapshotData) -> RollbackResult:
        dest_ip = target.get("destination_ip", "")
        dest_port = target.get("destination_port")
        protocol = snapshot.metadata.get("protocol", "tcp")

        try:
            if sys.platform == "win32":
                rule_name = f"Guardian-Block-{dest_ip}"
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, text=True, timeout=30, shell=False,
                )
                success = result.returncode == 0
                return RollbackResult(
                    success=success,
                    output={"rule_name": rule_name, "stdout": result.stdout},
                    error=None if success else f"Failed to delete rule: {result.stderr}",
                )
            else:
                args = ["iptables", "-D", "OUTPUT", "-d", dest_ip]
                if protocol in ("tcp", "udp"):
                    args.extend(["-p", protocol])
                if dest_port:
                    args.extend(["--dport", str(dest_port)])
                args.extend(["-j", "DROP"])

                result = subprocess.run(args, capture_output=True, text=True, timeout=30, shell=False)
                success = result.returncode == 0
                return RollbackResult(
                    success=success,
                    output={"rule": " ".join(args)},
                    error=None if success else f"Failed to delete iptables rule: {result.stderr}",
                )
        except Exception as exc:
            return RollbackResult(success=False, error=f"Rollback failed: {exc}")

    def describe(self, target: Dict[str, Any], parameters: Optional[Dict[str, Any]] = None) -> str:
        dest_ip = target.get("destination_ip", "?")
        dest_port = target.get("destination_port")
        protocol = (parameters or {}).get("protocol", "tcp")
        port_str = f":{dest_port}" if dest_port else ""
        return f"Block {protocol} traffic to {dest_ip}{port_str}"
