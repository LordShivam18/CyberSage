"""Persistence security checks (PERS-001 … PERS-003)."""
from __future__ import annotations

from typing import Any

from ..models import Category, Confidence, FindingStatus, Severity
from .base import SecurityCheck

_KNOWN_SAFE_SIGNER_PATTERNS = frozenset({
    "microsoft corporation", "microsoft windows", "google llc", "adobe", "mozilla",
})


def _is_likely_third_party(name: str) -> bool:
    lower = (name or "").lower()
    return not any(p in lower for p in _KNOWN_SAFE_SIGNER_PATTERNS)


class RunKeyInventoryCheck(SecurityCheck):
    """PERS-001: Run/RunOnce registry key inventory."""

    check_id = "PERS-001"
    title = "Run/RunOnce registry entries"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        run_entries = data.get("run_entries")
        if run_entries is None:
            return [self._make_unavailable("run_entries not collected", collected_at)]

        findings = []

        for entry in (run_entries or []):
            if not isinstance(entry, dict):
                continue
            hive = str(entry.get("hive") or "")
            key = str(entry.get("key") or "")
            name = str(entry.get("name") or "")
            value = str(entry.get("value") or "")[:512]
            path_hash = str(entry.get("path_hash") or "")

            # Stable finding_id uses path_hash derived from key+name (not PID)
            finding_id = f"{self.check_id}:{path_hash}"

            findings.append(self._make_finding(
                finding_id=finding_id,
                title=f"Run key entry: {name}",
                category=Category.PERSISTENCE,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                evidence={
                    "hive": hive,
                    "key": key,
                    "name": name,
                    "value": value,
                },
                explanation=(
                    f"Registry auto-start entry '{name}' in {hive}\\{key}. "
                    "This is an informational inventory — presence alone does not indicate threat."
                ),
                remediation="Review all Run key entries. Remove any unexpected entries with the assistance of your IT team.",
                collected_at=collected_at,
            ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.PERSISTENCE,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.PASS,
                evidence={"entries_found": 0},
                explanation="No Run/RunOnce registry entries found in the checked locations.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings


class StartupFolderCheck(SecurityCheck):
    """PERS-002: Startup folder contents."""

    check_id = "PERS-002"
    title = "Startup folder entries"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        user_items = data.get("startup_user") or []
        common_items = data.get("startup_common") or []
        all_items = list(user_items) + list(common_items)

        findings = []
        for item in all_items:
            if not isinstance(item, dict):
                continue
            full_name = str(item.get("FullName") or "")[:512]
            name = str(item.get("Name") or "")[:128]
            ext = str(item.get("Extension") or "")

            import hashlib
            path_hash = hashlib.sha256(full_name.encode("utf-8", errors="replace")).hexdigest()[:12]
            finding_id = f"{self.check_id}:{path_hash}"

            findings.append(self._make_finding(
                finding_id=finding_id,
                title=f"Startup folder entry: {name}",
                category=Category.PERSISTENCE,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                status=FindingStatus.INFORMATIONAL,
                evidence={"path": full_name, "name": name, "extension": ext},
                explanation=(
                    f"File '{name}' found in a startup folder. "
                    "Items in startup folders execute at login."
                ),
                remediation="Verify the legitimacy of all startup folder entries.",
                collected_at=collected_at,
            ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.PERSISTENCE,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.PASS,
                evidence={"entries_found": 0},
                explanation="No items found in user or common startup folders.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings


class ScheduledTasksCheck(SecurityCheck):
    """PERS-003: Enabled scheduled tasks (informational inventory)."""

    check_id = "PERS-003"
    title = "Enabled scheduled tasks"

    def _evaluate_impl(self, data: dict[str, Any], collected_at: str) -> list[Any]:
        tasks = data.get("scheduled_tasks")
        if tasks is None:
            return [self._make_unavailable("scheduled_tasks not collected", collected_at)]

        import hashlib
        findings = []

        for task in (tasks or []):
            if not isinstance(task, dict):
                continue
            task_name = str(task.get("TaskName") or "")[:256]
            task_path = str(task.get("TaskPath") or "")[:256]
            actions = task.get("Actions") or []
            if isinstance(actions, str):
                actions = [actions]
            action_str = ", ".join(str(a)[:128] for a in actions[:5])
            key = f"{task_path}\\{task_name}"
            task_hash = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:12]
            finding_id = f"{self.check_id}:{task_hash}"

            findings.append(self._make_finding(
                finding_id=finding_id,
                title=f"Scheduled task: {task_name}",
                category=Category.PERSISTENCE,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.INFORMATIONAL,
                evidence={
                    "task_name": task_name,
                    "task_path": task_path,
                    "actions": action_str[:512],
                },
                explanation=f"Enabled scheduled task '{task_name}' in path '{task_path}'.",
                remediation="Review all scheduled tasks. Remove or disable unexpected entries.",
                collected_at=collected_at,
            ))

        if not findings:
            findings.append(self._make_finding(
                finding_id=f"{self.check_id}:host",
                title=self.title,
                category=Category.PERSISTENCE,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                status=FindingStatus.PASS,
                evidence={"tasks_found": 0},
                explanation="No enabled scheduled tasks found.",
                remediation="No action required.",
                collected_at=collected_at,
            ))

        return findings
