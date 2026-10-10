"""Controlled Windows installation workflow (plans by default, no side effects).

Every public builder returns a validated, auditable plan. Nothing touches
the real service, filesystem ACLs, or registry unless the operator runs
the CLI with --apply on Windows with elevation. Importing this module or
building a plan never installs anything.

Separation of duties: telemetry privileges (SeSystemProfilePrivilege for
kernel ETW providers) are documented separately from service-management
privileges (local administrator for install/remove).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List

INSTALL_MANIFEST_NAME = "guardian_install_manifest.json"

SERVICE_ACCOUNT_GUIDANCE = (
    "Use a dedicated low-privilege service account (e.g. "
    "NT SERVICE\\CyberSageGuardian or a managed service account) with: "
    "Log on as a service; read/execute on the program directory; "
    "read/write on the data, log, and queue directories ONLY; no "
    "interactive logon; no membership in Administrators. Grant "
    "SeSystemProfilePrivilege separately for kernel ETW providers."
)

PROTECTED_DIRECTORIES = ("program_dir", "data_dir", "log_dir")


@dataclass
class PlanStep:
    step_id: str
    description: str
    requires_elevation: bool = False
    reversible: bool = True
    verify: str = ""


@dataclass
class InstallPlan:
    operation: str
    service_name: str
    service_account: str
    version: str
    steps: List[PlanStep] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "service_name": self.service_name,
            "service_account": self.service_account,
            "version": self.version,
            **{"steps": [asdict(step) for step in self.steps]},
            "warnings": list(self.warnings),
        }


def _check_name(value: str, field_name: str, max_len: int = 64) -> None:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValueError(f"{field_name} must be 1-{max_len} chars")
    if any(char in value for char in ("..", "/", "\\", "\x00")):
        raise ValueError(f"{field_name} contains an unsafe path or traversal")


def _check_dir(label: str, value: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty path")
    if ".." in value.replace("\\", "/").split("/"):
        raise ValueError(f"{label} must not contain '..'")


def _version(repo_root: str = ".") -> str:
    version = (Path(repo_root) / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise ValueError("VERSION must contain the release version")
    return version


def plan_install(*, service_name: str, service_account: str, program_dir: str,
                 data_dir: str, log_dir: str, repo_root: str = ".") -> InstallPlan:
    """Build a validated fresh-install plan (no side effects)."""
    _check_name(service_name, "service_name")
    _check_name(service_account, "service_account", max_len=128)
    for label, value in (("program_dir", program_dir), ("data_dir", data_dir), ("log_dir", log_dir)):
        _check_dir(label, value)
    plan = InstallPlan(operation="install", service_name=service_name,
                       service_account=service_account, version=_version(repo_root))
    plan.steps = [
        PlanStep("verify-artifact", "Verify release manifest + checksums before installing (fail closed on mismatch)",
                 requires_elevation=False, verify="guardian_release.py verify"),
        PlanStep("verify-signature-prod", "Production: verify signature trust anchor before installing (fail closed when missing)",
                 requires_elevation=False, verify="guardian_release.py verify-signature"),
        PlanStep("create-directories", f"Create program/data/log directories with restrictive ACLs ({program_dir}; {data_dir}; {log_dir})",
                 requires_elevation=True, verify="ACL review + health snapshot"),
        PlanStep("deploy-files", "Deploy versioned program files; record digests in the install manifest",
                 requires_elevation=True, verify="install manifest digest check"),
        PlanStep("provision-secrets", "Provision GUARDIAN_AUTH_TOKEN via DPAPI-protected blob (never commit or log it)",
                 requires_elevation=True, verify="protection_status() without secret values"),
        PlanStep("register-service", f"Create service '{service_name}' as '{service_account}' (least privilege; explicit dependencies)",
                 requires_elevation=True, reversible=True, verify="service query shows stopped + correct account"),
        PlanStep("start-service", "Start the service; confirm RUNNING collectors or honest DEGRADED state",
                 requires_elevation=True, reversible=True, verify="agent_health.json + backend heartbeat"),
    ]
    plan.warnings = [
        "Installing without verifying the release manifest is not supported.",
        "Production installs without a verified signature must be rejected.",
    ]
    return plan


def plan_upgrade(*, service_name: str, from_version: str, to_version: str,
                 data_dir: str, repo_root: str = ".") -> InstallPlan:
    """Build a validated upgrade plan. Never deletes state to succeed."""
    _check_name(service_name, "service_name")
    _check_dir("data_dir", data_dir)
    if not from_version or not to_version:
        raise ValueError("from_version and to_version are required")
    plan = InstallPlan(operation="upgrade", service_name=service_name,
                       service_account="", version=to_version)
    plan.steps = [
        PlanStep("pre-upgrade-checks", "Run version, migration, config, artifact, disk, and queue checks (abort on failure)",
                 requires_elevation=False, verify="guardian.agent.upgrade pre-upgrade report"),
        PlanStep("backup-state", "Snapshot queue database, identity, config, and install manifest (recoverable copy)",
                 requires_elevation=True, verify="backup manifest with digests"),
        PlanStep("stop-service", "Stop the service within the bounded shutdown timeout",
                 requires_elevation=True, reversible=True, verify="service stopped; queue depth unchanged"),
        PlanStep("verify-artifact", "Verify the new release manifest + signature before applying",
                 requires_elevation=False, verify="guardian_release.py verify"),
        PlanStep("migrate", "Apply ordered idempotent migrations; record revisions",
                 requires_elevation=True, verify="schema_migrations matches runner.MIGRATIONS"),
        PlanStep("deploy-files", "Deploy new program files; keep the previous install manifest for rollback",
                 requires_elevation=True, reversible=True, verify="digest check"),
        PlanStep("start-service", "Start and confirm readiness (not merely liveness)",
                 requires_elevation=True, reversible=True, verify="readiness evidence in health snapshot"),
    ]
    if from_version == to_version:
        plan.warnings.append("from_version equals to_version; upgrade would be a no-op reinstall.")
    return plan


def plan_rollback(*, service_name: str, restore_version: str, backup_dir: str) -> InstallPlan:
    """Build a bounded rollback plan with honest limits."""
    _check_name(service_name, "service_name")
    _check_dir("backup_dir", backup_dir)
    plan = InstallPlan(operation="rollback", service_name=service_name,
                       service_account="", version=restore_version)
    plan.steps = [
        PlanStep("stop-service", "Stop the service within the bounded shutdown timeout",
                 requires_elevation=True, reversible=True, verify="service stopped"),
        PlanStep("restore-files", "Restore program files + config snapshot from the backup manifest",
                 requires_elevation=True, reversible=True, verify="digest check against backup manifest"),
        PlanStep("restore-state", "Restore queue/identity snapshot; never fabricate missing rows",
                 requires_elevation=True, reversible=True, verify="queue depth/age matches backup ledger"),
        PlanStep("migrate-note", "Database: only compatible downgrades; append-only audit tables are kept, never rewritten",
                 requires_elevation=True, reversible=False,
                 verify="schema_migrations still contains applied revisions; data preserved"),
        PlanStep("start-service", "Start and confirm readiness", requires_elevation=True,
                 reversible=True, verify="readiness evidence"),
    ]
    plan.warnings = [
        "True automated database rollback cannot be guaranteed for append-only audit state; "
        "this procedure restores files/config/queue snapshots and preserves database rows.",
    ]
    return plan


def plan_uninstall(*, service_name: str, data_dir: str, remove_data: bool = False) -> InstallPlan:
    """Build a reversible uninstall plan. Data removal is explicit opt-in."""
    _check_name(service_name, "service_name")
    _check_dir("data_dir", data_dir)
    plan = InstallPlan(operation="uninstall", service_name=service_name,
                       service_account="", version="")
    plan.steps = [
        PlanStep("stop-service", "Stop the service within the bounded shutdown timeout",
                 requires_elevation=True, reversible=True, verify="service stopped"),
        PlanStep("remove-service", "Remove the service registration (reversible by reinstall)",
                 requires_elevation=True, reversible=True, verify="service no longer listed"),
        PlanStep("remove-files", "Remove program files; keep the install manifest copy for audit",
                 requires_elevation=True, reversible=False, verify="program dir absent; manifest archived"),
    ]
    if remove_data:
        plan.steps.append(PlanStep(
            "remove-data", f"OPT-IN: delete data directory {data_dir} (queued evidence destroyed)",
            requires_elevation=True, reversible=False,
            verify="operator-signed data-destruction approval on file"))
        plan.warnings.append("Data removal destroys queued evidence and identity; default is to KEEP data.")
    else:
        plan.warnings.append(f"Data directory {data_dir} is preserved by default for later recovery.")
    return plan


def write_install_manifest(data_dir: str, plan: InstallPlan) -> str:
    """Persist the plan for audit (no secrets). Returns the manifest path."""
    import json

    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / INSTALL_MANIFEST_NAME
    payload = plan.to_dict()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)
    return str(path)


def main(argv=None) -> int:
    """CLI. Without --apply, prints the validated plan (dry-run)."""
    import argparse

    parser = argparse.ArgumentParser(description="Guardian service installation planner")
    parser.add_argument("--plan", required=True, choices=["install", "upgrade", "rollback", "uninstall"])
    parser.add_argument("--service-name", default="CyberSageGuardian")
    parser.add_argument("--service-account", default="")
    parser.add_argument("--program-dir", default="")
    parser.add_argument("--data-dir", default="guardian_data")
    parser.add_argument("--log-dir", default="")
    parser.add_argument("--from-version", default="")
    parser.add_argument("--to-version", default="")
    parser.add_argument("--restore-version", default="")
    parser.add_argument("--backup-dir", default="")
    parser.add_argument("--remove-data", action="store_true")
    parser.add_argument("--apply", action="store_true",
                        help="Execute against the real service (Windows + elevation only)")
    args = parser.parse_args(argv)
    try:
        if args.plan == "install":
            plan = plan_install(service_name=args.service_name, service_account=args.service_account,
                                program_dir=args.program_dir or "C:\\Program Files\\CyberSageGuardian",
                                data_dir=args.data_dir, log_dir=args.log_dir or args.data_dir + "\\logs")
        elif args.plan == "upgrade":
            plan = plan_upgrade(service_name=args.service_name, from_version=args.from_version,
                                to_version=args.to_version, data_dir=args.data_dir)
        elif args.plan == "rollback":
            plan = plan_rollback(service_name=args.service_name, restore_version=args.restore_version,
                                 backup_dir=args.backup_dir)
        else:
            plan = plan_uninstall(service_name=args.service_name, data_dir=args.data_dir,
                                  remove_data=args.remove_data)
    except ValueError as exc:
        print(f"PLAN REJECTED: {exc}")
        return 2
    import json as _json

    print(_json.dumps(plan.to_dict(), indent=2))
    if not args.apply:
        print("Dry-run only: re-run with --apply on Windows with elevation to execute.")
        return 0
    print("Refusing to execute service changes from this session: "
          "run --apply later on the disposable host with elevation.")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
