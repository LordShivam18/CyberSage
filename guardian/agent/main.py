"""Guardian agent entry point.

Responsibilities:
* Load configuration
* Initialize local storage (SQLite queue)
* Initialize collector(s)
* Initialize synchronization loop
* Register agent with backend
* Send periodic heartbeats
* Cleanly stop all components

The agent remains useful if the backend is temporarily unavailable.
Detection, approval, and remediation are NOT implemented in Phase 1.
"""

from __future__ import annotations

import logging
import platform
import signal
import sys
import time
import uuid
from typing import Optional

from guardian.agent.config import AgentConfig
from guardian.collectors.process_monitor import ProcessMonitorCollector
from guardian.transport.local_queue import EventQueue, QueueOverflow
from guardian.transport.safe_url import validate_url_scheme
from guardian.transport.sync import SyncWorker

logger = logging.getLogger("guardian")


def _generate_host_id() -> str:
    """Generate a stable host identifier from machine-specific data."""
    # Use machine ID if available, otherwise generate a UUID
    import hashlib
    import os

    candidates = []
    # Windows: MACHINE GUID
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            candidates.append(str(value))
        except Exception:
            pass

    # Fallback: hostname + username
    candidates.append(platform.node())
    try:
        import getpass
        candidates.append(getpass.getuser())
    except Exception:
        pass

    # Use hostname if nothing else available
    if not candidates:
        candidates = [platform.node() or "unknown-host"]

    payload = "|".join(candidates)
    return f"host-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


class GuardianAgent:
    """Guardian v2 host protection agent.

    Phase 1 scope: event collection, local queue, backend synchronization.
    """

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        self._config = config or AgentConfig()
        self._queue: Optional[EventQueue] = None
        self._collector: Optional[ProcessMonitorCollector] = None
        self._sync_worker: Optional[SyncWorker] = None
        self._running = False
        self._start_time: Optional[float] = None

    def start(self) -> None:
        """Start the Guardian agent."""
        logger.info("Guardian agent starting...")

        # Validate configuration
        self._config.validate()

        # Generate host ID if not provided
        host_id = self._config.host_id or _generate_host_id()

        # Initialize local queue
        self._queue = EventQueue(
            db_path=self._config.queue_db_path,
            max_size=self._config.queue_max_size,
        )
        logger.info(
            "Local queue initialized (db=%s, max_size=%d)",
            self._config.queue_db_path,
            self._config.queue_max_size,
        )

        # Initialize collector
        self._collector = ProcessMonitorCollector(
            host_id=host_id,
            host_hostname=self._config.host_hostname or platform.node(),
            agent_version=self._config.agent_version,
        )
        self._collector.start()
        logger.info("Process monitor collector started.")

        # Initialize sync worker
        self._sync_worker = SyncWorker(
            queue=self._queue,
            backend_url=self._config.backend_url,
            auth_token=self._config.auth_token,
            agent_key=self._config.agent_key,
            sync_interval=self._config.sync_interval_seconds,
            batch_size=self._config.sync_batch_size,
            timeout=self._config.sync_timeout_seconds,
        )

        # Register agent with backend
        self._register_agent(host_id)

        # Start sync worker
        self._sync_worker.start()

        self._running = True
        self._start_time = time.monotonic()
        logger.info("Guardian agent started successfully.")

    def _register_agent(self, host_id: str) -> None:
        """Register the agent with the backend.

        Registration is idempotent — the same agent can re-register safely.
        If the backend is unavailable, the agent continues in offline mode.
        """
        import json
        from urllib.error import HTTPError, URLError
        from urllib.parse import urljoin
        from urllib.request import Request, urlopen

        validate_url_scheme(self._config.backend_url)
        payload = json.dumps({
            "agent_key": self._config.agent_key,
            "hostname": self._config.host_hostname or platform.node(),
            "os_name": platform.system(),
            "os_version": platform.version(),
            "agent_version": self._config.agent_version,
            "host_id": host_id,
        }).encode("utf-8")

        url = urljoin(self._config.backend_url.rstrip("/") + "/", "api/v1/guardian/agents/register")

        request = Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._config.auth_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=10) as response:  # nosec B310
                if response.getcode() == 200:
                    logger.info("Agent registered with backend successfully.")
                else:
                    logger.warning(
                        "Agent registration returned status %d — continuing in offline mode.",
                        response.getcode(),
                    )
        except (HTTPError, URLError, OSError, TimeoutError) as exc:
            logger.warning(
                "Agent registration failed (%s) — continuing in offline mode.",
                exc,
            )

    def _collect_cycle(self) -> int:
        """Run one collection cycle.

        Returns the number of events collected.
        """
        if not self._collector or not self._queue:
            return 0

        events = self._collector.collect()
        if not events:
            return 0

        count = 0
        for event in events:
            try:
                inserted = self._queue.enqueue(event.to_dict())
                if inserted:
                    count += 1
            except QueueOverflow:
                logger.warning(
                    "Queue overflow — %d events will be collected but not queued.",
                    len(events) - count,
                )
                break
            except Exception as exc:
                logger.error("Failed to enqueue event: %s", exc)

        return count

    def _heartbeat(self) -> None:
        """Send a heartbeat to the backend.

        Heartbeats are best-effort — failure does not stop the agent.
        """
        if not self._queue or not self._config.auth_token:
            return

        import json
        from urllib.error import HTTPError, URLError
        from urllib.parse import urljoin
        from urllib.request import Request, urlopen

        stats = self._queue.queue_stats()
        uptime = int(time.monotonic() - self._start_time) if self._start_time else 0

        payload = json.dumps({
            "agent_key": self._config.agent_key,
            "timestamp": time.time(),
            "agent_version": self._config.agent_version,
            "uptime_seconds": uptime,
            "queue_stats": stats,
            "events_queued": stats.get("pending", 0),
            "events_processed": stats.get("sent", 0),
            "metadata": {
                "platform": platform.system(),
                "python_version": platform.python_version(),
            },
        }).encode("utf-8")

        validate_url_scheme(self._config.backend_url)
        # Use a generic heartbeat endpoint (agent_id resolved server-side)
        url = urljoin(
            self._config.backend_url.rstrip("/") + "/",
            "api/v1/guardian/heartbeat",
        )

        request = Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._config.auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(request, timeout=10) as response:  # nosec B310
                if response.getcode() == 200:
                    logger.debug("Heartbeat sent successfully.")
        except (HTTPError, URLError, OSError, TimeoutError) as exc:
            logger.debug("Heartbeat failed (non-critical): %s", exc)

    def run(self) -> None:
        """Run the agent main loop.

        Collects events, sends heartbeats, and handles shutdown signals.
        """
        self.start()

        # Set up signal handlers for clean shutdown
        def _shutdown_handler(signum, frame):
            logger.info("Received signal %d, shutting down...", signum)
            self._running = False

        signal.signal(signal.SIGINT, _shutdown_handler)
        signal.signal(signal.SIGTERM, _shutdown_handler)

        heartbeat_interval = self._config.heartbeat_interval_seconds
        last_heartbeat = 0.0

        try:
            while self._running:
                # Collect events
                self._collect_cycle()

                # Send heartbeat if interval elapsed
                now = time.monotonic()
                if now - last_heartbeat >= heartbeat_interval:
                    self._heartbeat()
                    last_heartbeat = now

                # Brief sleep to avoid busy-waiting
                time.sleep(0.1)
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the Guardian agent and all components."""
        if not self._running and self._queue is None:
            return

        self._running = False
        logger.info("Guardian agent stopping...")

        if self._sync_worker:
            self._sync_worker.stop()

        if self._collector:
            self._collector.stop()

        if self._queue:
            self._queue.close()

        logger.info("Guardian agent stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def uptime_seconds(self) -> float:
        if self._start_time:
            return time.monotonic() - self._start_time
        return 0.0


def main() -> None:
    """CLI entry point for the Guardian agent."""
    import argparse

    parser = argparse.ArgumentParser(description="CyberSage Guardian Agent")
    parser.add_argument(
        "--config",
        help="Path to configuration file (optional, env vars take precedence)",
    )
    args = parser.parse_args()

    # Load configuration from environment
    config = AgentConfig()

    # Set up logging
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Create and run the agent
    agent = GuardianAgent(config=config)

    try:
        agent.run()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        logger.critical("Guardian agent crashed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
