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
        on_sync_complete: Optional[Callable[[int], None]] = None,
    ) -> None:
        self._queue = queue
        self._backend_url = backend_url.rstrip("/")
        self._auth_token = auth_token
        self._agent_key = agent_key
        self._sync_interval = sync_interval
        self._batch_size = batch_size
        self._timeout = timeout
        self._on_sync_complete = on_sync_complete
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._backoff_seconds = DEFAULT_BACKOFF_BASE
        self._consecutive_failures = 0

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

        Returns the number of events successfully synced.
        """
        events = self._queue.dequeue(batch_size=self._batch_size)
        if not events:
            self._consecutive_failures = 0
            self._backoff_seconds = DEFAULT_BACKOFF_BASE
            return 0

        event_ids = [e.get("event_id", "") for e in events]

        try:
            self._upload_batch(events)
            self._queue.mark_sent(event_ids)
            self._consecutive_failures = 0
            self._backoff_seconds = DEFAULT_BACKOFF_BASE
            logger.debug("SyncWorker: synced %d events.", len(events))
            if self._on_sync_complete:
                self._on_sync_complete(len(events))
            return len(events)

        except PermanentSyncError as exc:
            logger.error("SyncWorker: permanent sync failure: %s", exc)
            self._queue.mark_failed(event_ids, str(exc), permanent=True)
            self._consecutive_failures += 1
            return 0

        except TransientSyncError as exc:
            logger.warning("SyncWorker: transient sync failure: %s", exc)
            self._queue.mark_failed(event_ids, str(exc))
            self._consecutive_failures += 1
            self._backoff_seconds = min(
                self._backoff_seconds * 2, DEFAULT_MAX_BACKOFF
            )
            # Sleep with backoff before next attempt
            self._stop_event.wait(timeout=self._backoff_seconds)
            return 0

    def _upload_batch(self, events: List[Dict[str, Any]]) -> None:
        """Upload a batch of events to the backend API.

        Raises TransientSyncError on network/timeout failures.
        Raises PermanentSyncError on auth or schema errors.
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
                if status == 200:
                    return
                body = response.read().decode("utf-8", errors="replace")[:2048]
                if status == 401 or status == 403:
                    raise PermanentSyncError(
                        f"Authentication/authorization failed ({status}): {body}"
                    )
                if status == 422:
                    raise PermanentSyncError(
                        f"Schema validation failed ({status}): {body}"
                    )
                if 500 <= status < 600:
                    raise TransientSyncError(
                        f"Server error ({status}): {body}"
                    )
                raise TransientSyncError(
                    f"Unexpected status ({status}): {body}"
                )

        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:2048]
            if exc.code == 401 or exc.code == 403:
                raise PermanentSyncError(
                    f"Authentication/authorization failed ({exc.code}): {body}"
                ) from exc
            if exc.code == 422:
                raise PermanentSyncError(
                    f"Schema validation failed ({exc.code}): {body}"
                ) from exc
            if 500 <= exc.code < 600:
                raise TransientSyncError(
                    f"Server error ({exc.code}): {body}"
                ) from exc
            raise TransientSyncError(
                f"HTTP {exc.code}: {body}"
            ) from exc

        except (URLError, OSError, TimeoutError) as exc:
            raise TransientSyncError(
                f"Network error: {exc}"
            ) from exc

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    @property
    def backoff_seconds(self) -> float:
        return self._backoff_seconds
