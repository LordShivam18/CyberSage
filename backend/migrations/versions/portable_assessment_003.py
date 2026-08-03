"""
Migration 003 — Portable Assessment tables.

Creates:
  * assessment_runs   — one row per portable assessment import
  * assessment_findings — individual check findings; UNIQUE(assessment_run_id, finding_id)

Design notes
------------
* ``assessment_id`` is the UUID from the portable scanner JSON report.
* ``finding_id`` is the stable entity key from the scanner (never PID-based).
* The UNIQUE constraint on (assessment_run_id, finding_id) enforces import idempotency.
* posture_score_components and posture_score_caveat are stored separately so
  the backend can recompute and verify the score independently.
* The checksum stored is the SHA-256 of the canonical JSON payload (sorted keys,
  compact separators, checksum field excluded, UTF-8).  Integrity only — not
  publisher authenticity.
* ``detection_source`` for any derived alerts is always ``portable_assessment``.
"""

from sqlalchemy import inspect, text

revision = "003_portable_assessment"
depends_on = "002_model_governance"


def _col(engine, table: str, col: str) -> bool:
    insp = inspect(engine)
    return col in {c["name"] for c in insp.get_columns(table)} if insp.has_table(table) else False


def _table_exists(engine, table: str) -> bool:
    return inspect(engine).has_table(table)


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _json_type(engine) -> str:
    return "JSONB" if engine.dialect.name == "postgresql" else "JSON"


def upgrade(engine, _base=None) -> None:
    json_type = _json_type(engine)

    with engine.begin() as conn:
        # ----------------------------------------------------------------
        # assessment_runs
        # ----------------------------------------------------------------
        if not _table_exists(engine, "assessment_runs"):
            conn.execute(text(f"""
                CREATE TABLE {_quote("assessment_runs")} (
                    id SERIAL PRIMARY KEY,
                    assessment_id VARCHAR(128) NOT NULL,
                    scanner_version VARCHAR(64) NOT NULL,
                    schema_version VARCHAR(32) NOT NULL DEFAULT 'assessment.v1',
                    score_algorithm VARCHAR(64) NOT NULL DEFAULT 'posture_score_v1',
                    privacy_mode VARCHAR(32) NOT NULL DEFAULT 'standard',
                    privilege_level VARCHAR(32) NOT NULL DEFAULT 'standard',
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP NOT NULL,
                    imported_at TIMESTAMP NOT NULL,
                    imported_by VARCHAR(255),
                    host_hostname VARCHAR(255),
                    host_os_name VARCHAR(128),
                    host_os_version VARCHAR(128),
                    host_os_build VARCHAR(64),
                    host_architecture VARCHAR(64),
                    checks_attempted INTEGER NOT NULL DEFAULT 0,
                    coverage_pct FLOAT,
                    coverage_failed INTEGER NOT NULL DEFAULT 0,
                    coverage_unavailable INTEGER NOT NULL DEFAULT 0,
                    coverage_permission_required INTEGER NOT NULL DEFAULT 0,
                    coverage_errors INTEGER NOT NULL DEFAULT 0,
                    posture_score INTEGER NOT NULL DEFAULT 0,
                    posture_score_components {json_type},
                    posture_score_caveat TEXT,
                    report_checksum VARCHAR(128) NOT NULL,
                    report_checksum_algorithm VARCHAR(32) NOT NULL DEFAULT 'sha256',
                    checksum_verified BOOLEAN NOT NULL DEFAULT FALSE,
                    full_report {json_type},
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))

        # assessment_runs indexes
        for idx_name, col_name, unique in [
            ("ux_assessment_runs_assessment_id", "assessment_id", True),
            ("ix_assessment_runs_imported_at", "imported_at", False),
            ("ix_assessment_runs_posture_score", "posture_score", False),
            ("ix_assessment_runs_imported_by", "imported_by", False),
        ]:
            try:
                unique_sql = "UNIQUE " if unique else ""
                conn.execute(text(
                    f"CREATE {unique_sql}INDEX {_quote(idx_name)} "
                    f"ON {_quote('assessment_runs')} ({_quote(col_name)})"
                ))
            except Exception:
                conn.rollback()

        # ----------------------------------------------------------------
        # assessment_findings
        # ----------------------------------------------------------------
        if not _table_exists(engine, "assessment_findings"):
            conn.execute(text(f"""
                CREATE TABLE {_quote("assessment_findings")} (
                    id SERIAL PRIMARY KEY,
                    assessment_run_id INTEGER NOT NULL
                        REFERENCES {_quote("assessment_runs")} (id) ON DELETE CASCADE,
                    check_id VARCHAR(32) NOT NULL,
                    finding_id VARCHAR(512) NOT NULL,
                    title VARCHAR(512) NOT NULL,
                    category VARCHAR(64) NOT NULL,
                    severity VARCHAR(32) NOT NULL DEFAULT 'informational',
                    confidence VARCHAR(32) NOT NULL DEFAULT 'medium',
                    status VARCHAR(32) NOT NULL DEFAULT 'informational',
                    evidence {json_type},
                    explanation TEXT,
                    remediation TEXT,
                    device_impact VARCHAR(512),
                    admin_required BOOLEAN NOT NULL DEFAULT FALSE,
                    may_disrupt BOOLEAN NOT NULL DEFAULT FALSE,
                    references_json {json_type},
                    collected_at TIMESTAMP,
                    collector_version VARCHAR(32),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT uq_assessment_run_finding
                        UNIQUE (assessment_run_id, finding_id)
                )
            """))

        # assessment_findings indexes
        for idx_name, col_name in [
            ("ix_assessment_findings_run_id", "assessment_run_id"),
            ("ix_assessment_findings_check_id", "check_id"),
            ("ix_assessment_findings_status", "status"),
            ("ix_assessment_findings_severity", "severity"),
            ("ix_assessment_findings_category", "category"),
        ]:
            try:
                conn.execute(text(
                    f"CREATE INDEX {_quote(idx_name)} "
                    f"ON {_quote('assessment_findings')} ({_quote(col_name)})"
                ))
            except Exception:
                conn.rollback()


def downgrade(engine) -> None:
    with engine.begin() as conn:
        conn.execute(text(f"DROP TABLE IF EXISTS {_quote('assessment_findings')}"))
        conn.execute(text(f"DROP TABLE IF EXISTS {_quote('assessment_runs')}"))
