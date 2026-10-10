"""Versioned upgrade, backup, and bounded recovery (plans first, no side effects).

Reuses the existing backend migration runner (no duplicate migration
system). Database rollback is honestly bounded: append-only audit state
(envelope runs, action audit, evaluations) is preserved, never rewritten.
"""

from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

# Revisions whose effects are append-only by design: code may be reverted
# while rows are preserved. A "rollback" across these never deletes rows.
APPEND_ONLY_REVISIONS = frozenset({
    "008_guardian_phase5_slice1",
    "009_guardian_phase5_slice2",
    "010_guardian_phase5_slice4",
})


@dataclass
class CheckResult:
    check_id: str
    ok: bool
    detail: str = ""


@dataclass
class UpgradeReport:
    ok: bool
    checks: List[CheckResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "checks": [vars(check) for check in self.checks]}


def compare_versions(left: str, right: str) -> int:
    """Compare dotted versions. Returns -1/0/1. Fail closed on garbage."""

    def _parse(value: str) -> List[int]:
        parts = str(value).strip().split(".")
        if not 2 <= len(parts) <= 4:
            raise ValueError(f"Invalid version: {value!r}")
        numbers = []
        for part in parts:
            if not part.isdigit():
                raise ValueError(f"Invalid version: {value!r}")
            numbers.append(int(part))
        return numbers

    left_parts, right_parts = _parse(left), _parse(right)
    length = max(len(left_parts), len(right_parts))
    left_parts += [0] * (length - len(left_parts))
    right_parts += [0] * (length - len(right_parts))
    if left_parts < right_parts:
        return -1
    if left_parts > right_parts:
        return 1
    return 0


def pre_upgrade_checks(*, from_version: str, to_version: str, data_dir: str,
                       queue_db_path: str, min_free_bytes: int = 536870912) -> UpgradeReport:
    """Validate an upgrade before touching anything. No side effects."""
    checks: List[CheckResult] = []
    try:
        ordering = compare_versions(from_version, to_version)
        if ordering > 0:
            checks.append(CheckResult("version-order", False,
                                      "Downgrade requires the explicit rollback procedure, not upgrade"))
        elif ordering == 0:
            checks.append(CheckResult("version-order", False, "Versions are identical; nothing to upgrade"))
        else:
            checks.append(CheckResult("version-order", True, f"{from_version} -> {to_version}"))
    except ValueError as exc:
        checks.append(CheckResult("version-order", False, str(exc)))

    try:
        from backend.migrations import runner as _runner

        revisions = [module.revision for module in _runner.MIGRATIONS]
        checks.append(CheckResult("migrations-known", True, f"{len(revisions)} revisions registered"))
        append_only = sorted(set(revisions) & APPEND_ONLY_REVISIONS)
        checks.append(CheckResult("migrations-append-only", True,
                                  f"append-only revisions preserved on rollback: {', '.join(append_only) or 'none'}"))
    except Exception as exc:  # noqa: BLE001 - check must report, not raise
        checks.append(CheckResult("migrations-known", False, f"migration runner unreadable: {exc}"))

    data_path = Path(data_dir)
    queue_path = Path(queue_db_path)
    if not data_path.is_dir():
        checks.append(CheckResult("data-dir", False, f"data directory is missing: {data_dir}"))
    else:
        checks.append(CheckResult("data-dir", True, "data directory present"))
    if not queue_path.is_file():
        checks.append(CheckResult("queue-db", False, f"queue database is missing: {queue_db_path}"))
    else:
        try:
            with sqlite3.connect(f"file:{queue_path}?mode=ro", uri=True, timeout=5) as connection:
                connection.execute("SELECT COUNT(*) FROM guardian_events").fetchone()
            checks.append(CheckResult("queue-db", True, "queue database readable"))
        except Exception as exc:  # noqa: BLE001
            checks.append(CheckResult("queue-db", False, f"queue database unreadable: {exc}"))

    try:
        free = shutil.disk_usage(str(data_path if data_path.exists() else Path.cwd())).free
        if free < min_free_bytes:
            checks.append(CheckResult("disk-space", False, f"only {free} bytes free; need {min_free_bytes}"))
        else:
            checks.append(CheckResult("disk-space", True, f"{free} bytes free"))
    except Exception as exc:  # noqa: BLE001
        checks.append(CheckResult("disk-space", False, f"disk check failed: {exc}"))

    ok = all(check.ok for check in checks)
    return UpgradeReport(ok=ok, checks=checks)


def backup_state(*, data_dir: str, queue_db_path: str, backup_dir: str) -> Dict[str, Any]:
    """Describe (not perform, unless called with --apply) the backup set.

    backup_state_files() performs the copy; this separation keeps planning
    side-effect free.
    """
    return {
        "data_dir": data_dir,
        "queue_db_path": queue_db_path,
        "backup_dir": backup_dir,
        "copies": ["guardian_queue.db (+wal/shm)", "agent_identity.json",
                   "agent config snapshot", "install manifest"],
        "note": "Backend grants/approvals/audit live in the server database; "
                "back it up with pg_dump before upgrading the backend.",
    }


def backup_state_files(*, queue_db_path: str, data_dir: str, backup_dir: str) -> Dict[str, Any]:
    """Copy queue/identity/config snapshots. Only call from --apply runs."""
    import hashlib
    import json

    source = Path(queue_db_path)
    target_dir = Path(backup_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    if not source.is_file():
        raise ValueError(f"Queue database is missing: {queue_db_path}")
    target = target_dir / source.name
    with sqlite3.connect(str(source), timeout=30) as src, sqlite3.connect(str(target), timeout=30) as dst:
        src.backup(dst)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(source) + suffix)
        if sidecar.is_file():
            shutil.copy2(sidecar, target_dir / sidecar.name)
    for name in ("agent_identity.json", "agent_health.json"):
        candidate = Path(data_dir) / name
        if candidate.is_file():
            shutil.copy2(candidate, target_dir / name)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    ledger = {"queue_backup": str(target), "sha256": digest,
              "note": "Server-side rows preserved, never rewritten."}
    (target_dir / "backup_ledger.json").write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    return ledger


def recover_interrupted_upgrade(*, data_dir: str, backup_dir: str) -> List[str]:
    """Ordered recovery steps after an interrupted upgrade (guidance)."""
    return [
        f"1. Keep {data_dir} untouched; confirm the backup ledger in {backup_dir}.",
        "2. Re-run migrations (idempotent runner; already-applied revisions are skipped).",
        "3. Re-verify the release manifest digests before redeploying files.",
        "4. Restore queue/identity snapshots from the backup ledger only if files are corrupt.",
        "5. Restart and confirm readiness (not mere liveness) before resuming sync.",
    ]
