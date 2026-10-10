# Guardian Pilot Scorecard (TEMPLATE — RESULTS BLANK UNTIL REAL EVIDENCE)

How to use: after the pilot window, fill one row per metric with the measured result,
the evidence bundle reference, and the decision. Missing data forces `extend` (or `stop`
for safety rows), never a passing score. Sign-off requires named signers + rationale.

## Monitoring scorecard

| Metric | Calculation | Evidence source | Window | Threshold / approval | Missing-data treatment | Owner | Result (blank) | Decision (blank) |
|---|---|---|---|---|---|---|---|---|
| Telemetry completeness | persisted / observed | agent queue + backend event rows | full window | ≥ 0.99, every gap explained | gaps block proceed | pilot_owner |  |  |
| Detection precision | TP / (TP + FP), labeled scenarios only | corpus labels + detections | full window | owner-reviewed, no universal bar | inconclusive → extend | detection_owner |  |  |
| False-positive load | FPs per endpoint-day (benign workloads) | workload observations | full window | operator-reviewed acceptable load | missing logs block proceed | operator_lead |  |  |
| Non-execution | zero executed envelope runs | executions listing | full window | zero executed | any executed row → stop + review | security_lead |  |  |
| Resource impact | p50/p95 CPU/mem/disk vs pilot thresholds | agent/backend telemetry | full window | within configured thresholds | missing provenance blocks proceed | platform_owner |  |  |
| Audit completeness | reconciled chains, zero unexplained gaps | reconciliation reports | full window | complete | unresolved blocks proceed | security_lead |  |  |

## Approved-manual scorecard (adds)

| Metric | Calculation | Evidence source | Window | Threshold / approval | Missing-data treatment | Owner | Result | Decision |
|---|---|---|---|---|---|---|---|---|
| Approval discipline | 100% authorized, replays safe | approvals + gates + audit | controlled window | zero stale/mismatched | any unauthorized → stop | security_lead |  |  |
| Verification rate | verified_ok / executed | verification results | controlled window | reviewed + rollback evidence for failures | missing verification blocks proceed | operator_lead |  |  |
| Action latency | stage distributions incl. censored | stage timestamps | controlled window | reported with censoring | excluded cases → remediate | operator_lead |  |  |
| Kill/revoke drill | drill blocks at expected gate | drill records + gates | drill day | blocked as specified | failed drill → stop | security_lead |  |  |

## Future bounded-preauthorization entry gate (NOT enabled in this pilot)

| Metric | Calculation | Evidence source | Window | Threshold / approval | Missing-data treatment | Owner | Result | Decision |
|---|---|---|---|---|---|---|---|---|
| Evidence threshold | monitoring + manual scorecards reviewed | signed scorecards | full window | 3-role sign-off | no sign-off → no grant | security_lead |  |  |
| Scope approval | explicit actions/targets/risk/duration/limits | grant proposal | per proposal | recorded approval pre-activation | missing scope blocks activation | policy_owner |  |  |

## Sign-off record (template)

- Decision: proceed | extend | remediate | stop (circle one; requires rationale + named signers + date).
- Rationale (evidence references required):
- Signers:
- Date:
