# Live Windows End-to-End Checklist (disposable host only)

## Prerequisites

- [ ] Disposable Windows 10/11 or Server 2016+ (revertible snapshot).
- [ ] Python 3.11+, `etw` (pywintrace) installed, elevation or
      `SeSystemProfilePrivilege` for kernel providers.
- [ ] Isolated backend + database (never production data).
- [ ] Test-only credentials; no production secrets on the host.
- [ ] Isolated test server for the benign connection (host:port you control).

## Evidence chain to capture per scenario

```text
Observed Windows activity → real ETW callback → normalized event identity →
persisted queue record → authenticated upload + acknowledgement → backend
GuardianEvent row → detector output → evidence/incident behavior →
risk + policy outcome → authorization decision → safe test action →
verification → audit record
```

## Steps

1. [ ] Record backend row counts (events/detections/incidents/evals/execs/audit).
2. [ ] Start the agent in foreground mode; confirm `RUNNING` collector health.
3. [ ] Benign process: launch/stop the dedicated test process; confirm a
      normalized `guardian.event.v1` row with stable identity and NO
      suspicious detection/incident/approval/execution.
4. [ ] Benign connection: connect to the isolated server; confirm network
      normalization with honest attribution and no false detection.
5. [ ] Suspicious-but-benign: emit the corpus fixture (e.g. isolated
      `mimikatz.exe` name, `svchost→cmd`, port 4444, Run-key test value);
      confirm expected detector + severity and the expected stopping point
      (approval-required, no execution without authorization).
6. [ ] Controlled authorization: approve (manual) or activate a bounded
      grant (admin), run the harmless `test:noop_safe` action once,
      confirm verification + audit; replay and confirm no repeat.
7. [ ] Kill/revocation: activate kill switch (or revoke grant) before a
      second attempt; confirm block with the failing gate recorded.
8. [ ] Outage: stop the backend with queued events; restart agent and
      backend; reconcile generated/observed/queued/batches/acked/persisted.
9. [ ] Duplicates: resubmit one `event_id`; confirm idempotent rows.
10. [ ] Export the reconciliation table and attach backend row evidence.

## Stopping points

A benign event legitimately stops before incident/execution — assert the
stop, do not force incidents. Where live execution is unsafe, use
`test:noop_safe` and document the limitation.
