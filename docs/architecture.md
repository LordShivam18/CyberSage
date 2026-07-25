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

## Database Migration Strategy

The app uses a small migration runner in `backend/migrations`. Revision `001_platform_schema` creates new platform tables and expands legacy `alerts` without destructive schema recreation.
