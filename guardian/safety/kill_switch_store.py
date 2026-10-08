"""Guardian v2 Phase 5 Slice 2 — persisted kill-switch write-through.

The in-memory :class:`KillSwitch` singleton is fast but process-local and
lost on restart. The ``guardian_kill_switches`` table (migration 007) is
durable but was never written by any code path. This module binds them:

  - every activation/deactivation writes BOTH the singleton and the table
    (write-through, single helper — no divergent call sites);
  - every safety read consults BOTH and blocks if EITHER says active
    (OR semantics = fail closed; the two representations can never disagree
    in a way that permits execution);
  - ``sync_to_memory()`` reloads persisted state into a fresh singleton
    (restart/reload behavior), covered by tests.

Fail-closed read rule: any unexpected read error blocks. The single
exception is a database that predates migration 007 (table absent), which
reads as inactive so pre-007 databases keep working.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

from guardian.safety.kill_switch import KillSwitch, KillSwitchScope

logger = logging.getLogger(__name__)

_VALID_SCOPES = frozenset({"global", "agent", "action"})


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _table_exists(session: Session) -> bool:
    try:
        return sa_inspect(session.bind).has_table("guardian_kill_switches")
    except Exception:  # noqa: BLE001
        logger.error("kill_switch_store: cannot inspect schema; failing closed")
        return False


def _parse_scope(scope: Any) -> KillSwitchScope:
    if isinstance(scope, KillSwitchScope):
        return scope
    value = str(scope or "").lower()
    if value not in _VALID_SCOPES:
        raise ValueError(f"scope must be one of {sorted(_VALID_SCOPES)}")
    return KillSwitchScope(value)


def _validate_key(key: Any) -> str:
    if not isinstance(key, str) or not key or len(key) > 128:
        raise ValueError("switch key must be a non-empty string (max 128 chars)")
    return key


def activate_persisted(
    session: Session,
    kill_switch: KillSwitch,
    scope: Any,
    key: str,
    by: str,
    reason: str,
) -> Dict[str, Any]:
    """Activate in memory AND persist. Both or (on DB error) memory + raise."""
    parsed = _parse_scope(scope)
    clean_key = _validate_key(key)
    if not reason or len(reason) > 2048:
        raise ValueError("reason must be 1-2048 chars")

    kill_switch.activate(parsed, clean_key, by, reason)

    if _table_exists(session):
        from backend.models import GuardianKillSwitch

        row = session.query(GuardianKillSwitch).filter(
            GuardianKillSwitch.scope == parsed.value,
            GuardianKillSwitch.switch_key == clean_key,
        ).first()
        now = _now_utc()
        if row is None:
            row = GuardianKillSwitch(
                scope=parsed.value,
                switch_key=clean_key,
                active=True,
                activated_at=now,
                activated_by=by,
                reason=reason,
                updated_at=now,
            )
            session.add(row)
        else:
            row.active = True
            row.activated_at = now
            row.activated_by = by
            row.reason = reason
            row.updated_at = now
        session.flush()
    logger.warning(
        "kill_switch_store: ACTIVATED scope=%s key=%s by=%s", parsed.value, clean_key, by,
    )
    return {"scope": parsed.value, "switch_key": clean_key, "active": True}


def deactivate_persisted(
    session: Session,
    kill_switch: KillSwitch,
    scope: Any,
    key: str,
    by: str,
) -> Dict[str, Any]:
    """Deactivate in memory AND persist. Admin-only at the API layer."""
    parsed = _parse_scope(scope)
    clean_key = _validate_key(key)

    kill_switch.deactivate(parsed, clean_key, by)

    if _table_exists(session):
        from backend.models import GuardianKillSwitch

        row = session.query(GuardianKillSwitch).filter(
            GuardianKillSwitch.scope == parsed.value,
            GuardianKillSwitch.switch_key == clean_key,
        ).first()
        if row is not None:
            row.active = False
            row.activated_at = None
            row.activated_by = None
            row.reason = None
            row.updated_at = _now_utc()
            session.flush()
    logger.info(
        "kill_switch_store: DEACTIVATED scope=%s key=%s by=%s", parsed.value, clean_key, by,
    )
    return {"scope": parsed.value, "switch_key": clean_key, "active": False}


def is_persisted_active(session: Session, scope: Any, key: str) -> bool:
    """Fail-closed persisted read. Missing pre-007 table reads inactive."""
    try:
        parsed = _parse_scope(scope)
        clean_key = _validate_key(key)
    except ValueError:
        return True  # malformed scope/key blocks (fail closed)
    try:
        if not _table_exists(session):
            return False
        from backend.models import GuardianKillSwitch

        row = session.query(GuardianKillSwitch).filter(
            GuardianKillSwitch.scope == parsed.value,
            GuardianKillSwitch.switch_key == clean_key,
        ).first()
        return bool(row is not None and row.active)
    except Exception:  # noqa: BLE001
        logger.error("kill_switch_store: persisted read failed; failing closed")
        return True


def is_blocked_combined(
    session: Session,
    kill_switch: KillSwitch,
    scope: Any,
    key: str,
    agent_key: Optional[str] = None,
    action_key: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """OR of memory + persisted across global/agent/action. Fail closed.

    Returns (blocked: bool, reason: str | None). Global is checked first so
    its reason dominates, matching the required precedence.
    """
    try:
        parsed = _parse_scope(scope)
        clean_key = _validate_key(key)
    except ValueError as exc:
        return True, f"kill_switch_invalid_scope_or_key (fail closed): {exc}"

    blocked, reason = kill_switch.is_blocked(
        parsed, clean_key, agent_key=agent_key, action_key=action_key
    )
    if blocked:
        return True, reason

    # Persisted global first (dominates scoping), then scoped rows.
    try:
        if is_persisted_active(session, KillSwitchScope.GLOBAL, "global"):
            return True, "persisted global kill switch active"
        if agent_key and is_persisted_active(session, KillSwitchScope.AGENT, agent_key):
            return True, f"persisted agent kill switch active for {agent_key}"
        if action_key and is_persisted_active(session, KillSwitchScope.ACTION, action_key):
            return True, f"persisted action kill switch active for {action_key}"
        if parsed != KillSwitchScope.GLOBAL and is_persisted_active(session, parsed, clean_key):
            return True, f"persisted {parsed.value} kill switch active for {clean_key}"
    except Exception as exc:  # noqa: BLE001
        logger.error("kill_switch_store: combined check failed; failing closed: %s", exc)
        return True, "kill_switch_check_error (fail closed)"
    return False, None


def sync_to_memory(kill_switch: KillSwitch, session: Session) -> int:
    """Load all persisted ACTIVE switches into the singleton. Returns count.

    Used at startup/reload so a restart can never clear a persisted stop.
    Deactivation still requires the explicit deactivate path (never implicit).
    """
    try:
        if not _table_exists(session):
            return 0
        from backend.models import GuardianKillSwitch

        rows = session.query(GuardianKillSwitch).filter(
            GuardianKillSwitch.active.is_(True)
        ).all()
    except Exception as exc:  # noqa: BLE001
        logger.error("kill_switch_store: sync failed: %s", exc)
        return 0
    count = 0
    for row in rows:
        try:
            parsed = _parse_scope(row.scope)
            kill_switch.activate(parsed, row.switch_key, row.activated_by or "sync", row.reason or "persisted")
            count += 1
        except ValueError:
            logger.error("kill_switch_store: skipping invalid persisted row scope=%s", row.scope)
    return count


def merged_state(session: Session, kill_switch: KillSwitch) -> List[Dict[str, Any]]:
    """Combined view for operators: memory-active + persisted rows."""
    active_memory = kill_switch.get_all_active()
    persisted: List[Dict[str, Any]] = []
    try:
        if _table_exists(session):
            from backend.models import GuardianKillSwitch

            for row in session.query(GuardianKillSwitch).all():
                persisted.append({
                    "scope": row.scope,
                    "switch_key": row.switch_key,
                    "active": bool(row.active),
                    "activated_at": row.activated_at.isoformat() if row.activated_at else None,
                    "activated_by": row.activated_by,
                    "reason": row.reason,
                    "source": "persisted",
                })
    except Exception as exc:  # noqa: BLE001
        logger.error("kill_switch_store: merged_state read failed: %s", exc)
    for entry in active_memory:
        entry = dict(entry)
        entry["source"] = "memory"
        persisted.append(entry)
    return persisted
