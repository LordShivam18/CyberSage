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

## Residual Risk

This is a local development and portfolio platform. It is not hardened for internet exposure without additional secrets management, TLS, centralized rate limiting, observability, backup strategy, and security review.
