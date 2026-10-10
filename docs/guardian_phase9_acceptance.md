# Guardian Phase 9 Acceptance Checklist (HUMAN-RUN, NOT EXECUTED)

Prerequisites: reviewed Slice 4–Phase 8 implementation; disposable endpoints; isolated backend;
operator approvals recorded; blank evidence templates ready. Nothing below has been executed here.

## Governance
- [ ] Pilot config validates (`validate_pilot_config`); inventory starts empty; modes ⊆ {monitoring,
      approved_manual}; stop conditions + benign workloads present; unknown modes rejected.
- [ ] Forbidden mode names (`autonomous`, `unrestricted`, …) rejected; `GLOBAL_AUTONOMY_DISABLED` true.
- [ ] Future bounded use has no activation path except a separate signed authorization (none performed).

## Measurement
- [ ] Evidence schema reconciles a trial synthetic row as labeled-synthetic (never counted as pilot data).
- [ ] Precision/recall return inconclusive without valid labeling (no fabricated scores).
- [ ] Latency distributions count censored attempts openly; no difficult cases excluded.
- [ ] Resource summaries carry hardware/condition provenance; thresholds recorded as pilot decisions.
- [ ] Action ledger separates blocked/awaiting/executed/verified/failed/rollback/revoked; API 200 alone
      never counts as verified.

## Runbooks and scorecards
- [ ] Onboarding enrolls an endpoint in monitoring only with identity + health + backend row evidence.
- [ ] Daily review bundle, incident handling (no-execution proof), emergency stop, revocation,
      disablement/removal, recovery, and end-of-pilot reconciliation procedures are readable and scoped.
- [ ] Scorecard templates filled only from recorded evidence; missing data forces extend/stop per row.
- [ ] Sign-off records carry decision + rationale + named signers + date; broader rollout needs them.

## Stop rules understood
- [ ] Immediate-stop triggers (unexpected execution, unauthorized access, audit gaps, resource runaway,
      telemetry loss, unsafe authorization) are posted where operators will see them.
