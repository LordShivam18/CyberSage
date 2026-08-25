"""Snapshot manager — captures and stores immutable pre-execution state.

Snapshots must contain enough information to:
- Identify the target
- Identify the prior state
- Reconstruct rollback operation
- Prove what state existed before execution

Snapshots are immutable once action execution begins.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from guardian.actions.base import SnapshotData, compute_snapshot_id


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SnapshotManager:
    """Manages pre-execution snapshots for rollback-capable actions."""

    def create_snapshot(
        self,
        action_id: str,
        action_type: str,
        target: Dict[str, Any],
        prior_state: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SnapshotData:
        """Create an immutable snapshot.

        Args:
            action_id: The action attempt ID.
            action_type: Type of action.
            target: Target specification.
            prior_state: State before execution.
            metadata: Additional metadata.

        Returns:
            SnapshotData with generated snapshot_id.
        """
        snapshot_id = compute_snapshot_id(action_id)

        # Compute integrity hash of the snapshot content
        content = json.dumps({
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "prior_state": prior_state,
        }, sort_keys=True, default=str)
        integrity_hash = hashlib.sha256(content.encode()).hexdigest()

        merged_metadata = metadata or {}
        merged_metadata["integrity_hash"] = integrity_hash
        merged_metadata["schema_version"] = "guardian.snapshot.v1"

        return SnapshotData(
            snapshot_id=snapshot_id,
            action_id=action_id,
            action_type=action_type,
            target=target,
            prior_state=prior_state,
            metadata=merged_metadata,
            immutable=True,
            created_at=_now_utc(),
        )

    def verify_integrity(self, snapshot: SnapshotData) -> bool:
        """Verify snapshot has not been tampered with.

        Args:
            snapshot: The snapshot to verify.

        Returns:
            True if integrity is intact.
        """
        stored_hash = snapshot.metadata.get("integrity_hash")
        if not stored_hash:
            return False

        content = json.dumps({
            "action_id": snapshot.action_id,
            "action_type": snapshot.action_type,
            "target": snapshot.target,
            "prior_state": snapshot.prior_state,
        }, sort_keys=True, default=str)
        computed_hash = hashlib.sha256(content.encode()).hexdigest()

        return stored_hash == computed_hash
