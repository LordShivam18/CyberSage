"""Action registry — central lookup for all registered Guardian response actions.

Actions are registered at module load time and discovered by action_type + action_name.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from guardian.actions.base import BaseAction


_REGISTRY: Dict[str, BaseAction] = {}


def register_action(action: BaseAction) -> None:
    """Register an action instance."""
    key = f"{action.action_type}:{action.action_name}"
    _REGISTRY[key] = action


def get_action(action_type: str, action_name: str) -> Optional[BaseAction]:
    """Look up a registered action by type and name."""
    return _REGISTRY.get(f"{action_type}:{action_name}")


def list_actions() -> List[Dict[str, str]]:
    """List all registered actions."""
    return [
        {
            "action_type": action.action_type,
            "action_name": action.action_name,
            "rollback_supported": action.rollback_supported,
            "requires_snapshot": action.requires_snapshot,
        }
        for action in _REGISTRY.values()
    ]


def list_action_names() -> List[str]:
    """List all registered action names (type:name format)."""
    return list(_REGISTRY.keys())


def is_registered(action_type: str, action_name: str) -> bool:
    """Check if an action is registered."""
    return f"{action_type}:{action_name}" in _REGISTRY


# ── Register built-in actions ────────────────────────────────────────

def _register_builtins() -> None:
    """Register all built-in action implementations."""
    from guardian.actions.process import TerminateProcessAction
    from guardian.actions.network import BlockDestinationAction
    from guardian.actions.persistence import DisablePersistenceEntryAction

    register_action(TerminateProcessAction())
    register_action(BlockDestinationAction())
    register_action(DisablePersistenceEntryAction())


_register_builtins()
