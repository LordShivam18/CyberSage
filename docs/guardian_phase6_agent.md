# Guardian Phase 6 — Production-Grade Windows Endpoint Agent (IMPLEMENTED — NOT TESTED)

## Real ETW integration

- Library: `etw` (pywintrace) via soft import; import names verified from
  source: `etw.ETW`, `etw.ProviderInfo`, `etw.GUID`. Install on Windows only.
- Providers:
  - Process: `Microsoft-Windows-Kernel-Process`
    `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` (CreateProcess/ProcessStop subset).
  - Network: `Microsoft-Windows-TCPIP`
    `{2F07E2EE-15DB-40F1-90EF-9D7ABA282188}` (TCP/UDP connect/accept/
    disconnect where exposed; GUID configurable via
    `GUARDIAN_ETW_NETWORK_GUID`).
  - File telemetry: NOT claimed live. Kernel-File GUID is documented in
    `etw_provider.py` for future extension only.
- Supported: Python >= 3.11, Windows 10/11 and Server 2016+.
- Privileges: elevation or `SeSystemProfilePrivilege` for kernel providers;
  documented separately from service privileges.
- Lifecycle: session start/stop, callback exception isolation, degraded
  health on failure, exponential reconnect with back-off, graceful shutdown.
- No kernel drivers, no shell, no packet payloads, no weakened settings.

## Telemetry

- Process: PID/PPID, image path/name, command line, start/stop type,
  host identity, provider + source identity, UTC timestamp. File hash is
  best-effort local read (None when unreadable). PID reuse handled by
  deterministic event IDs that exclude PID (`guardian/models/event.py`).
- Network: local/remote IP (v4+v6), ports, protocol, process association
  ONLY when provided, host identity, timestamp, provider metadata.
  Missing attribution is explicit (`process_attribution: unavailable`).
- Normalization: `guardian.event.v1` via `normalize_process_event` /
  `normalize_network_event`; malformed fields become None, never crash.

## Identity / storage / queue / sync / service

- Identity (`guardian/agent/identity.py`): persisted
  `agent_identity.json` (agent_key, host_id, server agent_id), reused
  across restarts; explicit agent_key always sent; backend most-recent
  fallback never relied upon.
- Storage (`secure_storage.py`): data-dir ACLs (icacls / 0o700), DB+WAL
  same protections, DPAPI CURRENT_USER for the auth token where available,
  POSIX degraded warning (never pretends encryption), no colocated keys,
  redacted logs. Rotation = overwrite blob; loss = re-provision token.
- Queue (`local_queue.py`, additive): WAL, UNIQUE event_id, FIFO, states
  pending/sending/failed/sent, sending leases + `recover_expired_leases()`
  at startup, `queue_depth_age()` monitoring, byte_size accounting,
  explicit overflow counts, no silent deletion of undelivered events.
- Sync (`sync.py`): authenticated HTTPS, timeouts, batch count + byte
  bounds, jittered exponential backoff (max configurable), 429/5xx
  transient vs 401/403/422 permanent, auth-degraded health, invalid
  payloads quarantined after max retries (never infinite), stable IDs,
  per-event acknowledgement parsing of `GuardianEventIngestResponse`
  (`created`/`duplicate` only), crash-safe leases, bounded memory,
  graceful shutdown, observable health.
- Service (`service.py`, `windows_service.py`): foreground dev mode +
  explicit install/remove/start/stop (pywin32, Windows-only, reversible),
  bounded shutdown, health snapshot, config validation, restart recovery.
- Config: backend URL/paths/limits/batches/retry/heartbeat/ETW/logging
  validated; unsafe paths (`..`, NUL) rejected; no credentials in examples.

## Status

- IMPLEMENTED — NOT TESTED. Live ETW, service lifecycle, outage, and
  recovery harnesses provided for the developer on a disposable Windows
  host; nothing here claims live collection.
