"""Backend synchronization client for Guardian v2.

Uploads events from the local queue to the Guardian backend API.
Runs asynchronously — the collector never waits on the backend.

Architecture:
    collector → local queue → SyncWorker → backend API

If the backend is unavailable:
    * The collector continues collecting events.
    * The queue continues accumulating within configured bounds.
    * The sync worker retries with exponential backoff.

Events are removed from the pending queue only after server acknowledgement.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from guardian.transport.local_queue import EventQueue, STATE_PENDING
from guardian.transport.safe_url import validate_url_scheme

logger = logging.getLogger(__name__)

DEFAULT_SYNC_INTERVAL = 10  # seconds
DEFAULT_BATCH_SIZE = 100
DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_MAX_BACKOFF = 60  # seconds
DEFAULT_BACKOFF_BASE = 2  # seconds
DEFAULT_MAX_BATCH_BYTES = 1_048_576  # 1 MiB per upload batch


class SyncError(Exception):
    """Base class for sync failures."""


class TransientSyncError(SyncError):
    """A temporary failure that should be retried."""


class PermanentSyncError(SyncError):
    """A failure that should not be retried (e.g., authentication error)."""


class SyncWorker:
    """Asynchronous event synchronization worker.

    Periodically drains the local queue and uploads events to the backend.
    """

    def __init__(
        self,
        queue: EventQueue,
        backend_url: str,
        auth_token: str,
        *,
        agent_key: str = "",
        sync_interval: float = DEFAULT_SYNC_INTERVAL,
        batch_size: int = DEFAULT_BATCH_SIZE,
        timeout: int = DEFAULT_TIMEOUT,
        max_batch_bytes: int = DEFAULT_MAX_BATCH_BYTES,
        max_backoff: float = DEFAULT_MAX_BACKOFF,
        lease_seconds: int = 300,
        on_sync_complete: Optional[Callable[[int], None]] = None,
    ) -> None:
        self._queue = queue
        self._backend_url = backend_url.rstrip("/")
        self._auth_token = auth_token
        self._agent_key = agent_key
        self._sync_interval = sync_interval
        self._batch_size = batch_size
        self._timeout = timeout
        self._max_batch_bytes = max_batch_bytes
        self._max_backoff = max_backoff
        self._lease_seconds = lease_seconds
        self._on_sync_complete = on_sync_complete
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._backoff_seconds = DEFAULT_BACKOFF_BASE
        self._consecutive_failures = 0
        self._last_error: Optional[str] = None
        self._last_success_at: Optional[float] = None

    def start(self) -> None:
        """Start the sync worker in a background thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="guardian-sync"
        )
        self._thread.start()
        logger.info("SyncWorker: started (interval=%ss).", self._sync_interval)

    def stop(self) -> None:
        """Stop the sync worker and wait for the thread to finish."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        logger.info("SyncWorker: stopped.")

    def _run_loop(self) -> None:
        """Main sync loop — runs in a background thread."""
        while self._running and not self._stop_event.is_set():
            try:
                self._sync_once()
            except Exception as exc:
                logger.error("SyncWorker: unexpected error in sync loop: %s", exc)
            self._stop_event.wait(timeout=self._sync_interval)

    def _sync_once(self) -> int:
        """Perform one sync cycle.

        Returns the number of events durably acknowledged (created or
        duplicate). An HTTP 200 alone is never treated as acceptance:
        per-event results are parsed and only acknowledged events are
        marked sent.
        """
        events = self._queue.dequeue(batch_size=self._batch_size, lease_seconds=self._lease_seconds)
        if not events:
            self._consecutive_failures = 0
            self._backoff_seconds = DEFAULT_BACKOFF_BASE
            return 0

        events = self._trim_to_byte_bound(events)
        event_ids = [e.get("event_id", "") for e in events]

        try:
            acknowledged, quarantined = self._upload_batch(events)
            if acknowledged:
                self._queue.mark_sent(acknowledged)
            if quarantined:
                self._queue.mark_failed(quarantined, "permanent backend rejection", permanent=True)
            # Anything neither acknowledged nor quarantined stays leased and
            # is recovered by lease expiry (transient path below).
            pending = [eid for eid in event_ids if eid not in acknowledged and eid not in quarantined]
            if pending:
                raise TransientSyncError(f"{len(pending)} event(s) not acknowledged; will retry on lease expiry")
            self._consecutive_failures = 0
            self._backoff_seconds = DEFAULT_BACKOFF_BASE
            self._last_error = None
            self._last_success_at = time.time()
            logger.debug("SyncWorker: acknowledged %d events.", len(acknowledged))
            if self._on_sync_complete:
                self._on_sync_complete(len(acknowledged))
            return len(acknowledged)

        except PermanentSyncError as exc:
            logger.error("SyncWorker: permanent sync failure: %s", exc)
            self._queue.mark_failed(event_ids, str(exc), permanent=True)
            self._consecutive_failures += 1
            self._last_error = str(exc)[:512]
            return 0

        except TransientSyncError as exc:
            logger.warning("SyncWorker: transient sync failure: %s", exc)
            self._queue.mark_failed(event_ids, str(exc))
            self._consecutive_failures += 1
            self._last_error = str(exc)[:512]
            self._backoff_seconds = min(self._backoff_seconds * 2, self._max_backoff)
            self._backoff_seconds = self._apply_jitter(self._backoff_seconds)
            # Sleep with backoff before next attempt
            self._stop_event.wait(timeout=self._backoff_seconds)
            return 0

    def _trim_to_byte_bound(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Bound upload memory: keep FIFO prefix within max_batch_bytes."""
        kept: List[Dict[str, Any]] = []
        total = 0
        for event in events:
            size = len(json.dumps(event, default=str).encode("utf-8"))
            if kept and total + size > self._max_batch_bytes:
                break
            kept.append(event)
            total += size
        # Return unkept events to pending so leases do not strand them.
        if len(kept) != len(events):
            leftover = [e.get("event_id", "") for e in events[len(kept):]]
            if leftover:
                self._queue.mark_failed(leftover, "deferred for byte-bound batching")
        return kept or events[:1]

    @staticmethod
    def _apply_jitter(delay: float) -> float:
        """Add ±20% jitter to backoff (bounded, no new dependencies)."""
        import random

        factor = 0.8 + random.random() * 0.4
        return max(1.0, delay * factor)

    def health(self) -> Dict[str, Any]:
        """Observable sync health (no secrets)."""
        return {
            "running": self._running,
            "consecutive_failures": self._consecutive_failures,
            "backoff_seconds": round(self._backoff_seconds, 1),
            "last_error": self._last_error,
            "last_success_at": self._last_success_at,
            "batch_size": self._batch_size,
            "max_batch_bytes": self._max_batch_bytes,
        }

    def _upload_batch(self, events: List[Dict[str, Any]]) -> tuple:
        """Upload a batch and parse per-event acknowledgement.

        Returns (acknowledged_ids, quarantined_ids). HTTP 200 alone never
        implies acceptance: only events with result created/duplicate are
        acknowledged. Anything else is quarantined (permanent) or left for
        lease-expiry retry (transient).

        Raises TransientSyncError on network/timeout/5xx/429 failures.
        Raises PermanentSyncError on auth or batch schema errors.
        """
        validate_url_scheme(self._backend_url)
        body: Dict[str, Any] = {"events": events}
        if self._agent_key:
            body["agent_key"] = self._agent_key
        payload = json.dumps(body, default=str).encode("utf-8")
        url = urljoin(self._backend_url + "/", "api/v1/guardian/events")

        request = Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._auth_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=self._timeout) as response:  # nosec B310
                status = response.getcode()
                raw = response.read().decode("utf-8", errors="replace")[:65536]
                if status == 401 or status == 403:
                    raise PermanentSyncError(f"Authentication/authorization failed ({status})")
                if status == 422:
                    raise PermanentSyncError("Schema validation failed (422)")
                if status == 429:
                    raise TransientSyncError("Throttled (429): honor backoff and retry")
                if 500 <= status < 600:
                    raise TransientSyncError(f"Server error ({status})")
                if status != 200:
                    raise TransientSyncError(f"Unexpected status ({status})")
                return self._parse_acknowledgement(raw, [e.get("event_id", "") for e in events])

        except HTTPError as exc:
            try:
                exc.read().decode("utf-8", errors="replace")[:2048]
            except Exception:  # noqa: BLE001
                pass
            if exc.code == 401 or exc.code == 403:
                raise PermanentSyncError(f"Authentication/authorization failed ({exc.code})") from exc
            if exc.code == 422:
                raise PermanentSyncError(f"Schema validation failed ({exc.code})") from exc
            if exc.code == 429:
                raise TransientSyncError("Throttled (429): honor backoff and retry") from exc
            if 500 <= exc.code < 600:
                raise TransientSyncError(f"Server error ({exc.code})") from exc
            raise TransientSyncError(f"HTTP {exc.code}") from exc

        except (URLError, OSError, TimeoutError) as exc:
            raise TransientSyncError(f"Network error: {exc}") from exc

    @staticmethod
    def _parse_acknowledgement(raw: str, sent_ids: List[str]) -> tuple:
        """Parse GuardianEventIngestResponse into (acked, quarantined).

        Accepted: results with status created/duplicate. Quarantined: the
        response explicitly marks failures (future contract) — currently any
        sent id absent from results is left for retry, never marked sent.
        Unparseable bodies fail closed as transient (no silent acceptance).
        """
        try:
            data = json.loads(raw) if raw else {}
        except ValueError as exc:
            raise TransientSyncError(f"Unparseable ingestion response: {exc}") from exc
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            # Backward-compatible strictness: without per-event results we
            # cannot prove acceptance — retry on lease expiry.
            raise TransientSyncError("Ingestion response missing per-event results")
        acked = [r.get("event_id") for r in results
                 if isinstance(r, dict) and r.get("status") in ("created", "duplicate")
                 and r.get("event_id") in sent_ids]
        quarantined = [r.get("event_id") for r in results
                       if isinstance(r, dict) and r.get("status") not in ("created", "duplicate")
                       and r.get("event_id") in sent_ids]
        return acked, quarantined

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def backoff_seconds(self) -> float:
        return self._backoff_seconds
