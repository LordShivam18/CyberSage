"""Guardian v2 Phase 4 — Kill Switch.

Hierarchy of kill switches:
    global     → blocks ALL automated Guardian actions
    per_agent  → blocks actions for a specific agent
    per_action → blocks a specific action type

All switches default to SAFE (not activated).
All switches fail closed — if the state cannot be determined, block.

Semantics:
    is_blocked(scope, key) → True means BLOCKED (action must not proceed)
    Checking a parent scope that is active blocks all child scopes.
"""

from __future__ import annotations

import enum
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class KillSwitchScope(str, enum.Enum):
    GLOBAL = "global"
    AGENT = "agent"
    ACTION = "action"


class _SwitchState:
    def __init__(self) -> None:
        self.active: bool = False
        self.activated_at: Optional[datetime] = None
        self.activated_by: Optional[str] = None
        self.reason: Optional[str] = None

    def activate(self, activated_by: str, reason: str) -> None:
        self.active = True
        self.activated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        self.activated_by = activated_by
        self.reason = reason

    def deactivate(self) -> None:
        self.active = False
        self.activated_at = None
        self.activated_by = None
        self.reason = None

    def to_dict(self) -> Dict:
        return {
            "active": self.active,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "activated_by": self.activated_by,
            "reason": self.reason,
        }


class KillSwitch:
    """Thread-safe kill switch registry.

    All checks fail closed — if the internal state raises, block.

    Example:
        ks = KillSwitch()
        # Global stop
        ks.activate(KillSwitchScope.GLOBAL, key="global", by="admin", reason="Emergency stop")
        assert ks.is_blocked(KillSwitchScope.GLOBAL, key="global")

        # Per-agent
        ks.activate(KillSwitchScope.AGENT, key="agent-123", by="admin", reason="Compromised")
        assert ks.is_blocked(KillSwitchScope.AGENT, key="agent-123")

        # Per-action type
        ks.activate(KillSwitchScope.ACTION, key="process", by="admin", reason="Safety recall")
        assert ks.is_blocked(KillSwitchScope.ACTION, key="process")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._global = _SwitchState()
        self._agents: Dict[str, _SwitchState] = {}
        self._actions: Dict[str, _SwitchState] = {}

    def activate(
        self,
        scope: KillSwitchScope,
        key: str,
        by: str,
        reason: str,
    ) -> None:
        """Activate a kill switch.

        Args:
            scope: KillSwitchScope.GLOBAL | AGENT | ACTION
            key: "global", agent_id, or action_type
            by: Operator username
            reason: Human-readable reason
        """
        with self._lock:
            state = self._get_or_create(scope, key)
            state.activate(by, reason)
            logger.warning(
                "KillSwitch ACTIVATED: scope=%s key=%s by=%s reason=%s",
                scope.value, key, by, reason,
            )

    def deactivate(self, scope: KillSwitchScope, key: str, by: str) -> None:
        """Deactivate a kill switch."""
        with self._lock:
            state = self._get_or_create(scope, key)
            state.deactivate()
            logger.info(
                "KillSwitch DEACTIVATED: scope=%s key=%s by=%s",
                scope.value, key, by,
            )

    def is_blocked(
        self,
        scope: KillSwitchScope,
        key: str,
        agent_key: Optional[str] = None,
        action_key: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Check if an action is blocked by any active kill switch.

        Global switch blocks everything.
        Agent switch blocks actions for that agent.
        Action switch blocks that action type everywhere.

        Returns:
            (blocked: bool, reason: str | None)
        """
        try:
            with self._lock:
                # 1. Global
                if self._global.active:
                    return True, f"global kill switch active: {self._global.reason}"

                # 2. Specific agent
                if agent_key and agent_key in self._agents:
                    s = self._agents[agent_key]
                    if s.active:
                        return True, f"agent kill switch active for {agent_key}: {s.reason}"

                # 3. Specific action type
                if action_key and action_key in self._actions:
                    s = self._actions[action_key]
                    if s.active:
                        return True, f"action kill switch active for {action_key}: {s.reason}"

                # 4. The requested key itself
                state = self._get_or_create(scope, key)
                if state.active:
                    return True, f"{scope.value} kill switch active for {key}: {state.reason}"

                return False, None
        except Exception as exc:  # noqa: BLE001
            # Fail closed
            logger.error("KillSwitch.is_blocked raised; failing closed: %s", exc)
            return True, "kill_switch_check_error (fail closed)"

    def get_state(self, scope: KillSwitchScope, key: str) -> Dict:
        """Return the current state dict for a specific switch."""
        with self._lock:
            state = self._get_or_create(scope, key)
            return {
                "scope": scope.value,
                "key": key,
                **state.to_dict(),
            }

    def get_all_active(self) -> list:
        """Return all currently active kill switches."""
        result = []
        with self._lock:
            if self._global.active:
                result.append({"scope": "global", "key": "global", **self._global.to_dict()})
            for k, s in self._agents.items():
                if s.active:
                    result.append({"scope": "agent", "key": k, **s.to_dict()})
            for k, s in self._actions.items():
                if s.active:
                    result.append({"scope": "action", "key": k, **s.to_dict()})
        return result

    def _get_or_create(self, scope: KillSwitchScope, key: str) -> _SwitchState:
        if scope == KillSwitchScope.GLOBAL:
            return self._global
        elif scope == KillSwitchScope.AGENT:
            if key not in self._agents:
                self._agents[key] = _SwitchState()
            return self._agents[key]
        else:  # ACTION
            if key not in self._actions:
                self._actions[key] = _SwitchState()
            return self._actions[key]


# Module-level default kill switch (singleton for process lifetime)
_default_kill_switch = KillSwitch()


def get_default_kill_switch() -> KillSwitch:
    """Return the process-wide default KillSwitch instance."""
    return _default_kill_switch
