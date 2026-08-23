# Threat Model

## Assets

- Analyst accounts and JWTs.
- PostgreSQL alert, incident, audit, and telemetry records.
- Local indicator lists and cached threat-intel results.
- Model and scaler artifacts when present.

## Trust Boundaries

- Browser to FastAPI API.
- API and worker to PostgreSQL.
- Worker to Kafka.
- Optional future threat-intel providers.

## Primary Risks

- Unauthorized workflow changes to alerts or incidents.
- Ingestion of malformed or duplicate telemetry.
- Overclaiming low-confidence threat-intel matches.
- Model artifact absence or incompatibility.
- Data leakage during training and evaluation.

## Mitigations

- JWT authentication and role checks for sensitive operations.
- PBKDF2 password hashing with per-user salts.
- Strict Pydantic request models for API inputs.
- Dead-letter persistence and topic publishing for invalid Kafka messages.
- Idempotent event and alert keys.
- Disabled-by-default external threat-intel lookups.
- Migration-controlled schema changes.
- Training split before preprocessing fit.

## Release and Distribution Threats

Additional v1.1 assets are release archives, dependency declarations and the
frontend lockfile, CycloneDX SBOMs, release manifests, archive checksums, and
Windows signing credentials when signing is explicitly requested. GitHub-hosted
build runners form a trust boundary between source control, dependency
registries, build tools, and distributed artifacts.

| Threat | Current mitigation |
| --- | --- |
| A secret reaches source control or CI diagnostics | Gitleaks scans committed content, CI credentials are generated per run and masked, and failure diagnostics are sanitized. |
| A dependency or workflow action changes unexpectedly | Direct Python and build dependencies are exact pins, the frontend uses its committed lockfile with `npm ci`, and third-party actions use immutable commit SHAs. |
| A vulnerable dependency is released | `pip-audit --strict` and production `npm audit` run in the release gate; Bandit and zizmor provide static checks. |
| An archive is modified or lacks provenance | The release includes an archive SHA-256 checksum, CycloneDX SBOM, and validated manifest with source revision, build identity, environment, and dependency-input hashes. |
| An unsigned executable is presented as trusted | The release manifest records `unsigned` unless a manually required signing run successfully produces and validates an Authenticode signature. |

## Residual Risk

CyberSage is a local development and portfolio platform, not a production
internet service. It does not yet provide managed secrets, TLS termination,
centralized rate limiting, backup and recovery, independently reproducible
binaries, container image digest pinning, image vulnerability scanning, or a
reviewed vulnerability-exception process. A checksum detects modification but
does not establish publisher identity. Unsigned portable builds are not
represented as code-signed software.
