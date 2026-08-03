# Architecture

The platform is intentionally modular without introducing unnecessary microservices.

## Runtime Processes

- API service: `backend.main`, serving FastAPI HTTP and WebSocket APIs.
- Detection worker: `backend.worker`, consuming Kafka events using an explicit consumer group.
- Database: PostgreSQL for normalized events, detections, alerts, incidents, audit logs, threat-intel cache, and user records.
- Frontend: React SOC dashboard.

## Kafka Topics

- `raw.network-events`: primary telemetry input.
- `network_traffic`: legacy synthetic input topic still consumed by the worker.
- `normalized.network-events`: normalized event fan-out.
- `detections`: hybrid detection fan-out.
- `dead-letter-events`: invalid or failed messages.

## Processing Flow

1. A connector or producer writes JSON telemetry to Kafka.
2. The worker normalizes the payload.
3. The worker persists the normalized event by deterministic `event_id`.
4. ML, anomaly, rule, and threat-intel detectors evaluate the same event.
5. A transparent risk score is computed and stored with components.
6. Alerts are created only when the event is suspicious enough.
7. Alerts are deterministically correlated into incidents.
8. The API and dashboard read from PostgreSQL and publish live updates for API-created changes.

## Detection Quality And Governance

1. An authorized local CSV export is described by a versioned dataset manifest rather than a hard-coded path.
2. The benchmark runner resolves only local files, validates taxonomy and numeric features, then prepares group, capture-day, or time partitions without sharing sequence groups.
3. Logistic Regression, Random Forest, Isolation Forest, and the Transformer are evaluated under the same prepared data; only supervised classifiers share class metrics.
4. Artifact metadata binds the model and scaler checksums to feature order, class map, split evidence, validation threshold, held-out metrics, software versions, limitations, and a training-feature reference distribution.
5. The registry validates a candidate against configured quality gates, then an administrator explicitly promotes it. A promotion archives the prior active model for the same task and emits an audit event.
6. Runtime inference verifies the versioned artifact contract and active status. Invalid metadata, checksum mismatch, candidate status, or unsupported model type yields an explicit degraded fallback state.
7. Recent normalized-event features are compared with the active artifact's training reference using PSI. Missing baseline data and undersized windows remain `degraded` or `insufficient_data`.

## Database Migration Strategy

The app uses a small migration runner in `backend/migrations`. Revision `001_platform_schema` creates new platform tables and expands legacy `alerts` without destructive schema recreation. Revision `002_model_governance` adds model lifecycle, validation, and activation fields while preserving existing model rows as archived records.
