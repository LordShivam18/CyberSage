import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base
from backend.inference import ModelDetector
from backend.model_benchmark import run_benchmark
from backend.model_governance import (
    MODEL_METADATA_SCHEMA_VERSION,
    GovernanceError,
    canonical_json_checksum,
    evaluate_drift,
    file_checksum,
    load_dataset_manifest,
    load_manifest_dataset,
    prepare_partitions,
    select_threshold,
    validate_model_metadata,
)
from backend.model_registry import archive_model, promote_model, register_model, validate_registered_model


def _write_manifest(tmp_path: Path, *, task_mode: str = "multiclass") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    rows = []
    for group in range(15):
        for offset in range(6):
            rows.append(
                {
                    "label": "BENIGN" if offset % 2 == 0 else "DOS HULK",
                    "timestamp": f"2026-01-{group + 1:02d}T00:00:{offset:02d}Z",
                    "scenario": f"scenario-{group:02d}",
                    "capture_day": f"2026-01-{group + 1:02d}",
                    "flow": f"flow-{group:02d}",
                    "bytes": 100 + group * 5 + offset,
                    "packets": 2 + offset,
                }
            )
    pd.DataFrame(rows).to_csv(tmp_path / "flows.csv", index=False)
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "\n".join(
            [
                "schema_version: cybersage.dataset-manifest.v1",
                "dataset_id: temporary-authorized-fixture",
                "files:",
                "  - flows.csv",
                "label_column: label",
                "timestamp_column: timestamp",
                "group_column: scenario",
                "capture_day_column: capture_day",
                "sequence_group_column: flow",
                "feature_columns: [bytes, packets]",
                "exclude_columns: []",
                "label_taxonomy:",
                "  BENIGN: BENIGN",
                "  DOS HULK: DOS_DDOS",
                "benign_labels: [BENIGN]",
                "unknown_label_policy: reject",
                f"task_mode: {task_mode}",
                "licence_notes: temporary test fixture",
                "source_notes: generated only for unit testing",
            ]
        ),
        encoding="utf-8",
    )
    return manifest


def _artifact_metadata(tmp_path: Path, version: str, *, split_strategy: str = "group") -> Path:
    model_path = tmp_path / f"{version}.pth"
    scaler_path = tmp_path / f"{version}.joblib"
    model_path.write_bytes(f"model:{version}".encode("ascii"))
    scaler_path.write_bytes(f"scaler:{version}".encode("ascii"))
    training = {"seed": 42, "sequence_length": 2}
    metrics = {
        "macro_f1": 0.8,
        "weighted_f1": 0.8,
        "false_positive_rate": 0.1,
        "inference_latency_ms": 2.0,
        "per_class": [
            {"class": "BENIGN", "recall": 0.9},
            {"class": "ATTACK", "recall": 0.7},
        ],
    }
    metadata = {
        "metadata_schema_version": MODEL_METADATA_SCHEMA_VERSION,
        "registry_status": "candidate",
        "task": "network_detection",
        "model_type": "transformer",
        "model_version": version,
        "dataset_identifier": "temporary-authorized-fixture",
        "dataset_manifest_checksum": "a" * 64,
        "source_file_checksums": {"temporary.csv": "b" * 64},
        "training_config_checksum": canonical_json_checksum(training),
        "feature_names": ["bytes", "packets"],
        "class_mapping": {"0": "BENIGN", "1": "ATTACK"},
        "sequence_length": 2,
        "split": {"strategy": split_strategy, "counts": {"train": {"rows": 10}}},
        "training_timestamp": "2026-01-01T00:00:00+00:00",
        "threshold_selection": {"selected_threshold": 0.5, "source": "validation"},
        "validation_metrics": metrics,
        "test_metrics": metrics,
        "artifact_checksums": {"model": file_checksum(model_path), "scaler": file_checksum(scaler_path)},
        "artifact_paths": {"model": model_path.name, "scaler": scaler_path.name},
        "framework_versions": {"python": "test"},
        "known_limitations": ["temporary fixture"],
        "drift_baseline": {},
        "architecture": {"d_model": 128, "nhead": 8, "nlayers": 3},
    }
    path = tmp_path / f"{version}.metadata.json"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    return path


def _session_factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def test_manifest_multiclass_binary_and_leakage_safe_partitions(tmp_path):
    multiclass_manifest = load_dataset_manifest(_write_manifest(tmp_path))
    dataset = load_manifest_dataset(multiclass_manifest)
    assert set(dataset.class_mapping.values()) == {"BENIGN", "DOS_DDOS"}

    prepared = prepare_partitions(dataset, "group", sequence_length=2, seed=7)
    partition_groups = [set(partition.groups.astype(str)) for partition in prepared.row_partitions.values()]
    assert not partition_groups[0].intersection(partition_groups[1])
    assert not partition_groups[0].intersection(partition_groups[2])
    assert not partition_groups[1].intersection(partition_groups[2])
    assert prepared.scaler.data_min_.tolist() == prepared.row_partitions["train"].features.min().tolist()
    assert all(len(partition.sequences) > 0 for partition in prepared.sequence_partitions.values())

    time_prepared = prepare_partitions(dataset, "time", sequence_length=2, seed=7)
    assert time_prepared.row_partitions["train"].timestamps.max() < time_prepared.row_partitions["validation"].timestamps.min()
    assert time_prepared.row_partitions["validation"].timestamps.max() < time_prepared.row_partitions["test"].timestamps.min()

    binary_manifest = load_dataset_manifest(_write_manifest(tmp_path / "binary", task_mode="binary"))
    binary_dataset = load_manifest_dataset(binary_manifest)
    assert set(binary_dataset.class_mapping.values()) == {"BENIGN", "ATTACK"}


def test_manifest_rejects_duplicate_keys_and_unknown_labels(tmp_path):
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text("schema_version: cybersage.dataset-manifest.v1\nschema_version: other\n", encoding="utf-8")
    with pytest.raises(GovernanceError, match="Duplicate manifest key"):
        load_dataset_manifest(duplicate)

    unsafe = tmp_path / "unsafe.yaml"
    unsafe.write_text("!!python/object/apply:os.system ['echo unsafe']\n", encoding="utf-8")
    with pytest.raises(GovernanceError, match="not valid YAML"):
        load_dataset_manifest(unsafe)

    manifest_path = _write_manifest(tmp_path)
    csv_path = tmp_path / "flows.csv"
    frame = pd.read_csv(csv_path)
    frame.loc[0, "label"] = "unmapped-class"
    frame.to_csv(csv_path, index=False)
    with pytest.raises(GovernanceError, match="no taxonomy mapping"):
        load_manifest_dataset(load_dataset_manifest(manifest_path))

    leakage_manifest = _write_manifest(tmp_path / "leakage")
    leakage_text = leakage_manifest.read_text(encoding="utf-8").replace(
        "feature_columns: [bytes, packets]", "feature_columns: [bytes, label]"
    )
    leakage_manifest.write_text(leakage_text, encoding="utf-8")
    with pytest.raises(GovernanceError, match="cannot include the label"):
        load_manifest_dataset(load_dataset_manifest(leakage_manifest))


def test_transformer_state_dict_loader_uses_weights_only_and_rejects_non_tensor_values(tmp_path, monkeypatch):
    from backend import inference as inference_module

    artifact_path = tmp_path / "transformer_model.pth"
    expected = {"decoder.weight": inference_module.torch.zeros((2, 2))}
    calls = {}

    def safe_load(path, *, map_location, weights_only):
        calls.update(path=path, map_location=map_location, weights_only=weights_only)
        return expected

    monkeypatch.setattr(inference_module.torch, "load", safe_load)
    assert inference_module._load_transformer_state_dict(artifact_path) is expected
    assert calls == {"path": artifact_path, "map_location": "cpu", "weights_only": True}

    monkeypatch.setattr(inference_module.torch, "load", lambda *args, **kwargs: {"decoder.weight": "unsafe"})
    with pytest.raises(GovernanceError, match="only named tensors"):
        inference_module._load_transformer_state_dict(artifact_path)


def test_validation_thresholds_and_drift_states():
    probabilities = np.asarray([[0.8, 0.2], [0.3, 0.7], [0.4, 0.6], [0.9, 0.1]])
    selection = select_threshold([0, 1, 1, 0], probabilities, {0: "BENIGN", 1: "ATTACK"})
    assert selection["selection_dataset"] == "validation"
    assert 0.05 <= selection["selected_threshold"] <= 0.95

    insufficient = evaluate_drift({"bytes": {"histogram": {"bins": [0, 1], "counts": [2]}}}, pd.DataFrame(), "v1")
    assert insufficient["status"] == "insufficient_data"
    degraded = evaluate_drift({"bytes": {"histogram": {"bins": [0, 1], "counts": [2]}}}, pd.DataFrame({"packets": list(range(30))}), "v1")
    assert degraded["status"] == "degraded"


def test_benchmark_uses_manifest_and_writes_baseline_evidence(tmp_path):
    manifest = _write_manifest(tmp_path)
    report = run_benchmark(
        manifest,
        tmp_path / "benchmark-output",
        split_strategy="group",
        sequence_length=2,
        seed=11,
        skip_transformer=True,
        run_id="fixture-run",
    )
    assert report["split"]["strategy"] == "group"
    assert report["models"]["logistic_regression"]["status"] == "completed"
    assert report["models"]["random_forest"]["status"] == "completed"
    assert report["models"]["transformer"]["status"] == "skipped"
    artifact = tmp_path / "benchmark-output" / "fixture-run" / "artifacts" / "logistic_regression.metadata.json"
    validated = validate_model_metadata(json.loads(artifact.read_text(encoding="utf-8")), artifact_root=artifact.parent, verify_files=True)
    assert validated["split"]["strategy"] == "group"


def test_metadata_rejection_registry_lifecycle_and_checksum_enforcement(tmp_path):
    first_metadata = _artifact_metadata(tmp_path, "candidate-one")
    first = json.loads(first_metadata.read_text(encoding="utf-8"))
    first["artifact_checksums"]["model"] = "0" * 64
    with pytest.raises(GovernanceError, match="checksum"):
        validate_model_metadata(first, artifact_root=tmp_path, verify_files=True)

    SessionTesting = _session_factory()
    db = SessionTesting()
    try:
        row_one = register_model(db, first_metadata)
        row_one = validate_registered_model(db, row_one.version)
        assert row_one.status == "validated"
        promote_model(db, row_one.version)
        assert row_one.status == "active"
        active_metadata = json.loads(first_metadata.read_text(encoding="utf-8"))
        assert active_metadata["registry_status"] == "active"
        assert active_metadata["artifact_paths"]["model"] == "candidate-one.pth"

        second_metadata = _artifact_metadata(tmp_path, "candidate-two")
        row_two = register_model(db, second_metadata)
        validate_registered_model(db, row_two.version)
        promote_model(db, row_two.version)
        assert row_one.status == "archived"
        assert row_two.status == "active"
        archive_model(db, row_two.version)
        assert row_two.status == "archived"

        development_only = register_model(db, _artifact_metadata(tmp_path, "development-only", split_strategy="random_dev_only"))
        rejected = validate_registered_model(db, development_only.version)
        assert rejected.status == "rejected"
        with pytest.raises(GovernanceError, match="passing validation"):
            promote_model(db, rejected.version)
    finally:
        db.close()


def test_ungoverned_runtime_metadata_enters_explicit_degraded_state(tmp_path, monkeypatch):
    from backend import inference as inference_module

    model_path = tmp_path / "model.pth"
    scaler_path = tmp_path / "scaler.joblib"
    metadata_path = tmp_path / "metadata.json"
    model_path.write_bytes(b"not-a-torch-model")
    scaler_path.write_bytes(b"not-a-scaler")
    metadata_path.write_text(json.dumps({"metadata_schema_version": "invalid"}), encoding="utf-8")
    original_paths = (
        inference_module.settings.model_path,
        inference_module.settings.scaler_path,
        inference_module.settings.model_metadata_path,
    )
    object.__setattr__(inference_module.settings, "model_path", model_path)
    object.__setattr__(inference_module.settings, "scaler_path", scaler_path)
    object.__setattr__(inference_module.settings, "model_metadata_path", metadata_path)
    try:
        detector = ModelDetector()
        assert not detector.available
        assert detector.status()["state"] == "degraded_fallback"
        assert "ungoverned" in detector.status()["fallback_reason"]
    finally:
        object.__setattr__(inference_module.settings, "model_path", original_paths[0])
        object.__setattr__(inference_module.settings, "scaler_path", original_paths[1])
        object.__setattr__(inference_module.settings, "model_metadata_path", original_paths[2])
