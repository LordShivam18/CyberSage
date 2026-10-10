"""Phase 8 operations harness (PROVIDED — NOT EXECUTED).

Genuine contract checks for the developer to run later. Pure functions,
temporary files, and local plan builders only. No service installation,
no live ETW, no backend mutation, no network use.
"""

import json

import pytest

from guardian.agent import install as install_mod
from guardian.agent import upgrade as upgrade_mod
from guardian.agent.config_file import (
    CONFIG_SCHEMA_VERSION,
    migrate_config_dict,
    to_redacted_dict,
    validate_production,
)
from guardian.agent.config import AgentConfig
from guardian.ops.health import compose_agent_snapshot, summarize, ComponentHealth
from scripts.guardian_release import verify_manifest, write_manifest


def test_release_manifest_round_trip(tmp_path):
    import backend  # noqa: F401  (ensures backend package import path exists)
    manifest_path = tmp_path / "agent.manifest.json"
    manifest = write_manifest(".", manifest_path)
    assert manifest["input_count"] >= 1
    result = verify_manifest(".", manifest_path)
    assert result["ok"] is True


def test_release_verify_rejects_tamper(tmp_path):
    manifest_path = tmp_path / "agent.manifest.json"
    write_manifest(".", manifest_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["inputs"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="mismatch"):
        verify_manifest(".", manifest_path)


def test_signature_gate_fails_closed_without_trust(tmp_path):
    manifest_path = tmp_path / "agent.manifest.json"
    manifest = write_manifest(".", manifest_path)
    manifest["signing"] = "signed"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    from scripts.guardian_release import verify_signature

    with pytest.raises(ValueError, match="[Pp]rerequisite|fingerprint|signature"):
        verify_signature(manifest_path, expect_fingerprint="")


def test_install_plans_validate_and_dry_run():
    plan = install_mod.plan_install(service_name="GuardianTest", service_account="svc-test",
                                    program_dir="C:\\Guardian", data_dir="guardian_data",
                                    log_dir="guardian_data\\logs")
    assert plan.operation == "install" and len(plan.steps) >= 5
    with pytest.raises(ValueError):
        install_mod.plan_install(service_name="Bad/../Name", service_account="svc",
                                 program_dir="C:\\G", data_dir="d", log_dir="l")
    uninstall = install_mod.plan_uninstall(service_name="GuardianTest", data_dir="guardian_data")
    assert any("preserved by default" in warning for warning in uninstall.warnings)


def test_upgrade_version_ordering():
    assert upgrade_mod.compare_versions("1.1.0", "1.2.0") == -1
    assert upgrade_mod.compare_versions("1.2.0", "1.2.0") == 0
    with pytest.raises(ValueError):
        upgrade_mod.compare_versions("not-a-version", "1.2.0")


def test_config_redaction_and_production_gate(monkeypatch):
    monkeypatch.setenv("GUARDIAN_AGENT_KEY", "key")
    monkeypatch.setenv("GUARDIAN_HOST_ID", "host")
    monkeypatch.setenv("GUARDIAN_BACKEND_URL", "http://localhost:8000")
    monkeypatch.setenv("GUARDIAN_AUTH_TOKEN", "super-secret")
    config = AgentConfig()
    redacted = to_redacted_dict(config)
    assert redacted["auth_token"] == "***REDACTED***"
    missing = validate_production(config)
    # Capitalization is not part of the contract; match case-insensitively.
    assert any("https" in item.lower() or "auth" in item.lower() for item in missing)


def test_config_migration_rejects_unknown_keys():
    with pytest.raises(ValueError, match="unknown"):
        migrate_config_dict({"schema_version": 1, "bogus_key": 1})
    assert migrate_config_dict({"schema_version": 1})["schema_version"] == CONFIG_SCHEMA_VERSION


def test_retention_config_validation():
    from backend.retention import RETENTION_POLICIES, validate_retention_config

    effective = validate_retention_config({})
    assert set(effective) == set(RETENTION_POLICIES)
    with pytest.raises(ValueError):
        validate_retention_config({"audit_events": 1})
    with pytest.raises(ValueError):
        validate_retention_config({"unknown_category": 30})


def test_health_never_masks_worst_signal():
    summary = summarize([ComponentHealth("a", "healthy"), ComponentHealth("b", "fatal", "disk dead")])
    assert summary["status"] == "fatal"
    snapshot = compose_agent_snapshot(identity={"agent_key": "k", "host_id": "h"}, version="1.1.0",
                                      collectors=[], queue={"total_active": 0, "capacity": 100},
                                      sync={"consecutive_failures": 0, "backoff_seconds": 0,
                                            "last_success_at": "never"})
    assert snapshot["status"] == "unready"
