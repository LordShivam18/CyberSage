# Guardian Controlled Pilot Plan (GOVERNANCE — NOT EXECUTED)

Status: pilot readiness implemented; the pilot itself is NOT conducted here.
Endpoint inventory starts empty; no endpoint is enrolled by any code or document.

## 1. Objectives and scope

- Objectives (operator fills): e.g. (a) prove telemetry completeness on isolated endpoints,
  (b) measure detection quality on labeled scenarios, (c) assess operator workload, (d) validate
  approved-manual discipline. Objectives must be written before any endpoint joins.
- Scope: a small number of dedicated, isolated, non-production test endpoints (suggested 3–5).
- Owner, duration (default 14 days, 1–90 allowed), baseline period (default 7 days, within duration).
- Authorized data sources: process + network ETW collectors only (file telemetry excluded until supported).

## 2. Eligibility and prerequisites

- Eligible OS: Windows 10, Windows 11, Server 2016/2019/2022.
- Per endpoint: disposable/revertible image, Python 3.11+, `etw` (pywintrace) installed,
  elevation or `SeSystemProfilePrivilege`, isolated backend URL + test-only credentials,
  explicit operator consent recorded.
- Backend: isolated database, migrations through `010`, known-good release manifest verified,
  retention config recorded.

## 3. Modes (enforced, not assumed)

- **Monitoring** (default, only permitted initial mode): collect + evaluate; response actions must not
  execute; non-execution is proven per window with `modes.assert_no_executions` (zero executed rows).
- **Approved-manual**: entered only by change control; every action needs an authorized approval with
  identity/target/version/scope revalidation; kill-switch and revocation keep precedence.
- **Bounded pre-authorization**: DISABLED by default and NOT part of this pilot. Any future narrowly
  scoped use needs the evidence threshold, three-role sign-off, explicit scope/limits/duration, and a
  separate future activation via `POST /preauth/activate`. Simulation success or fixture passes never
  enable it. **Global/unrestricted autonomy stays disabled** (`modes.GLOBAL_AUTONOMY_DISABLED`).

## 4. Baseline and workloads

- Baseline period first (monitoring only): capture telemetry completeness, resource baselines, benign
  workload behavior with no test scenarios injected.
- Known-good benign workloads (operator records, e.g. office productivity профиле, build pipeline run):
  must be documented per endpoint before suspicious scenarios run.
- Approved suspicious scenarios: Phase 7 corpus `e2e-*` fixtures adapted to the isolated host
  (benignly generated, documentation IPs/ports, isolated files only).

## 5. Exclusions and prohibitions

Production enrollment, unrestricted execution, global autonomy, destructive testing on
non-disposable hosts, real credential use, packet-payload collection, kernel drivers, and
security-setting weakening are prohibited. `validate_pilot_config` rejects unknown modes.

## 6. Change control, responsibilities, evidence, stop conditions

- Change control: written approval for mode transitions, grant proposals (future), and scope changes.
- Responsibilities: pilot owner (schedule/evidence), endpoint owners (host readiness/consent),
  operator lead (triage/approvals), security lead (kill/revocation/audit), platform owner (backend/infra).
- Evidence rules: every scenario carries `scenario_id` + `correlation_id`; reconciliation schema in
  `guardian/pilot/evidence.py`; synthetic rows labeled and never counted.
- Stop conditions (immediate stop): unexpected response execution, unauthorized access, unexplained
  audit gaps, uncontrolled resource use, repeated telemetry loss, unsafe authorization behavior.
  See `docs/guardian_pilot_runbooks.md` for the stop/rollback procedure.
