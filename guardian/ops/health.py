"""Shared operational health model (pure, no I/O, no secrets).

Severity ordering (worst wins): fatal > unready > degraded > healthy.
A component is never reported healthier than its worst signal: a fatal
config error stays fatal even when collectors look fine, and a degraded
collector keeps the summary degraded even when the queue is empty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

HEALTH_ORDER = ("healthy", "degraded", "unready", "fatal")

LIVENESS_ALIVE = "alive"

SECRET_KEYS = ("auth_token", "token", "password", "private_key", "secret", "jwt")


@dataclass
class ComponentHealth:
    component: str
    status: str
    detail: str = ""
    signals: Dict[str, Any] = field(default_factory=dict)

    def redacted(self) -> Dict[str, Any]:
        signals = {key: ("***REDACTED***" if any(secret in key.lower() for secret in SECRET_KEYS) else value)
                   for key, value in self.signals.items()}
        return {"component": self.component, "status": self.status,
                "detail": self.detail, "signals": signals}


def _rank(status: str) -> int:
    try:
        return HEALTH_ORDER.index(status)
    except ValueError:
        return HEALTH_ORDER.index("fatal")


def summarize(components: List[ComponentHealth]) -> Dict[str, Any]:
    """Compose a summary that never masks the worst component."""
    if not components:
        return {"status": "unready", "detail": "no health signals reported",
                "components": []}
    worst = max(components, key=lambda item: _rank(item.status))
    return {"status": worst.status,
            "detail": f"worst component: {worst.component} ({worst.detail or worst.status})",
            "components": [item.redacted() for item in components]}


def compose_backend_health(*, database_ok: bool, database_error: str = "",
                           migration_revision: str = "", migrations_expected: List[str] | None = None,
                           rules_error: str = "", queue_backlog: int = 0,
                           audit_write_ok: bool = True) -> Dict[str, Any]:
    """Compose backend health from existing signals (no new I/O here)."""
    components = [
        ComponentHealth("database",
                        "healthy" if database_ok else "fatal",
                        "" if database_ok else (database_error or "database unavailable")[:300]),
        ComponentHealth("migrations",
                        "healthy" if not migrations_expected or migration_revision in migrations_expected else "unready",
                        f"revision={migration_revision or 'unknown'}"),
        ComponentHealth("detection_pipeline",
                        "healthy" if not rules_error else "degraded",
                        (rules_error or "")[:300]),
        ComponentHealth("ingestion_backlog",
                        "healthy" if queue_backlog < 1000 else ("degraded" if queue_backlog < 10000 else "unready"),
                        f"backlog={queue_backlog}"),
        ComponentHealth("audit_writes",
                        "healthy" if audit_write_ok else "fatal",
                        "" if audit_write_ok else "audit writes failing; stop executing actions"),
    ]
    return summarize(components)


def compose_agent_snapshot(*, identity: Dict[str, Any], version: str,
                           collectors: List[Dict[str, Any]], queue: Dict[str, Any],
                           sync: Dict[str, Any], disk_free_bytes: int = -1,
                           disk_min_bytes: int = 536870912,
                           etw_state: str = "unknown", service_state: str = "foreground",
                           config_valid: bool = True, config_error: str = "",
                           auth_ok: bool = True) -> Dict[str, Any]:
    """Compose the agent health snapshot schema (all inputs provided by caller)."""
    components = [
        ComponentHealth("identity",
                        "healthy" if identity.get("agent_key") and identity.get("host_id") else "fatal",
                        "stable identity present" if identity.get("agent_key") else "identity missing"),
        ComponentHealth("config", "healthy" if config_valid else "fatal", (config_error or "")[:300]),
        ComponentHealth("collectors",
                        "healthy" if all((item.get("health") or item.get("status")) == "running" for item in collectors)
                        else ("degraded" if collectors else "unready"),
                        f"{len(collectors)} collector(s) reporting"),
        ComponentHealth("queue",
                        "healthy" if queue.get("total_active", 0) < queue.get("capacity", 1) * 0.8 else "degraded",
                        f"depth={queue.get('total_active', 0)} oldest={queue.get('oldest_created_at', 'unknown')}"),
        ComponentHealth("sync",
                        "healthy" if auth_ok and sync.get("consecutive_failures", 0) == 0
                        else ("degraded" if auth_ok else "unready"),
                        f"failures={sync.get('consecutive_failures', 0)} "
                        f"backoff={sync.get('backoff_seconds', 0)}s "
                        f"last_success={sync.get('last_success_at', 'never')}"),
        ComponentHealth("disk",
                        "healthy" if disk_free_bytes < 0 or disk_free_bytes >= disk_min_bytes else "unready",
                        f"free={disk_free_bytes} min={disk_min_bytes}"),
        ComponentHealth("auth", "healthy" if auth_ok else "unready",
                        "" if auth_ok else "authentication failing; check provisioned credential"),
        ComponentHealth("runtime", "healthy",
                        f"version={version} etw={etw_state} service={service_state}"),
    ]
    snapshot = summarize(components)
    snapshot["agent_key"] = identity.get("agent_key", "")
    snapshot["version"] = version
    return snapshot
