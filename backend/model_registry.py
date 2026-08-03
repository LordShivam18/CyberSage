"""Explicit model lifecycle operations backed by the existing model_versions table."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from sqlalchemy.orm import Session

from .model_governance import GovernanceError, validate_model_metadata
from .models import AuditEvent, ModelVersion


MODEL_STATES = {"candidate", "validated", "active", "rejected", "archived"}
PROMOTABLE_SPLITS = {"group", "capture_day", "time"}
DEFAULT_QUALITY_GATES = {
    "minimum_macro_f1": 0.5,
    "maximum_false_positive_rate": 0.2,
    "maximum_inference_latency_ms": 1000.0,
    "minimum_recall_by_class": {},
}


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _audit(db: Session, action: str, version: str, details: Mapping[str, Any], actor: Optional[str]) -> None:
    db.add(
        AuditEvent(
            username=actor,
            action=action,
            target_type="model_version",
            target_id=version,
            details=dict(details),
        )
    )
    db.flush()


def _metadata_for_storage(metadata: Mapping[str, Any], metadata_path: Path) -> Dict[str, Any]:
    stored = dict(metadata)
    stored["_artifact_root"] = str(metadata_path.parent.resolve())
    stored["_metadata_path"] = str(metadata_path.resolve())
    return stored


def _metadata_for_public(metadata: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in metadata.items() if not key.startswith("_") and key != "artifact_paths"}


def _write_artifact_metadata(metadata: Mapping[str, Any], status: str) -> None:
    """Persist the lifecycle state while retaining the artifact validation manifest."""
    metadata_path = Path(metadata.get("_metadata_path", ""))
    if not metadata_path.is_file():
        raise GovernanceError("Registered metadata file is unavailable for lifecycle update")
    artifact_metadata = {key: value for key, value in metadata.items() if not key.startswith("_")}
    artifact_metadata["registry_status"] = status
    metadata_path.write_text(json.dumps(artifact_metadata, indent=2, sort_keys=True), encoding="utf-8")


def model_version_to_public(row: ModelVersion, include_details: bool = True) -> Dict[str, Any]:
    payload = {
        "id": row.id,
        "task": row.task,
        "name": row.name,
        "version": row.version,
        "model_type": row.model_type,
        "status": row.status,
        "checksum": row.checksum,
        "dataset_identifier": row.dataset_identifier,
        "feature_count": len(row.feature_list or []),
        "class_mapping": row.class_mapping or {},
        "evaluation_summary": row.metrics or {},
        "validation_result": row.validation_result or {},
        "rejection_reason": row.rejection_reason,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "activated_at": row.activated_at.isoformat() if row.activated_at else None,
    }
    if include_details:
        metadata = _metadata_for_public(row.metadata_json or {})
        payload["metadata"] = {
            "metadata_schema_version": metadata.get("metadata_schema_version"),
            "split": metadata.get("split", {}),
            "threshold_selection": metadata.get("threshold_selection", {}),
            "known_limitations": metadata.get("known_limitations", []),
            "framework_versions": metadata.get("framework_versions", {}),
            "validation_metrics": metadata.get("validation_metrics", {}),
            "test_metrics": metadata.get("test_metrics", {}),
        }
    return payload


def _load_metadata(metadata_path: str | Path, verify_files: bool = True) -> tuple[Dict[str, Any], Path]:
    path = Path(metadata_path).resolve()
    if not path.is_file():
        raise GovernanceError("Model metadata file does not exist")
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GovernanceError(f"Model metadata is not valid JSON: {exc}") from exc
    return validate_model_metadata(metadata, artifact_root=path.parent, verify_files=verify_files), path


def register_model(db: Session, metadata_path: str | Path, actor: Optional[str] = "cli") -> ModelVersion:
    metadata, path = _load_metadata(metadata_path, verify_files=True)
    checksums = metadata["artifact_checksums"]
    duplicate = (
        db.query(ModelVersion)
        .filter(
            (ModelVersion.checksum == checksums["model"])
            | ((ModelVersion.task == metadata.get("task", "network_detection")) & (ModelVersion.version == metadata["model_version"]))
        )
        .first()
    )
    if duplicate:
        raise GovernanceError("A model with this artifact checksum or task/version is already registered")
    row = ModelVersion(
        name=metadata.get("task", "network_detection"),
        task=metadata.get("task", "network_detection"),
        version=metadata["model_version"],
        model_type=metadata["model_type"],
        status="candidate",
        checksum=checksums["model"],
        dataset_identifier=metadata["dataset_identifier"],
        feature_list=list(metadata["feature_names"]),
        class_mapping=dict(metadata["class_mapping"]),
        metrics={"validation": metadata["validation_metrics"], "test": metadata["test_metrics"]},
        metadata_json=_metadata_for_storage(metadata, path),
    )
    db.add(row)
    db.flush()
    _audit(db, "model_registered", row.version, {"task": row.task, "model_type": row.model_type}, actor)
    return row


def _criterion(name: str, required: Any, actual: Any, passed: bool, reason: Optional[str] = None) -> Dict[str, Any]:
    return {"name": name, "required": required, "actual": actual, "passed": bool(passed), "reason": reason}


def evaluate_quality_gates(metadata: Mapping[str, Any], quality_gates: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    gates = {**DEFAULT_QUALITY_GATES, **dict(quality_gates or {})}
    test_metrics = metadata.get("test_metrics") or {}
    split = metadata.get("split") or {}
    criteria = []
    strategy = split.get("strategy")
    criteria.append(
        _criterion(
            "required_split_strategy",
            sorted(PROMOTABLE_SPLITS),
            strategy,
            strategy in PROMOTABLE_SPLITS,
            "random_dev_only is prohibited for validated and active models" if strategy == "random_dev_only" else None,
        )
    )
    macro = test_metrics.get("macro_f1")
    criteria.append(
        _criterion("minimum_macro_f1", gates["minimum_macro_f1"], macro, macro is not None and macro >= gates["minimum_macro_f1"]))
    fpr = test_metrics.get("false_positive_rate")
    criteria.append(
        _criterion(
            "maximum_false_positive_rate",
            gates["maximum_false_positive_rate"],
            fpr,
            fpr is not None and fpr <= gates["maximum_false_positive_rate"],
        )
    )
    latency = test_metrics.get("inference_latency_ms")
    criteria.append(
        _criterion(
            "maximum_inference_latency_ms",
            gates["maximum_inference_latency_ms"],
            latency,
            latency is not None and latency <= gates["maximum_inference_latency_ms"],
        )
    )
    per_class = {row.get("class"): row.get("recall") for row in test_metrics.get("per_class", [])}
    for class_name, minimum in dict(gates.get("minimum_recall_by_class", {})).items():
        actual = per_class.get(class_name)
        criteria.append(
            _criterion(f"minimum_recall:{class_name}", minimum, actual, actual is not None and actual >= minimum)
        )
    return {"passed": all(item["passed"] for item in criteria), "criteria": criteria, "evaluated_at": _utcnow().isoformat()}


def _get_version(db: Session, version: str) -> ModelVersion:
    row = db.query(ModelVersion).filter(ModelVersion.version == version).first()
    if not row:
        raise GovernanceError("Model version was not found")
    return row


def validate_registered_model(
    db: Session,
    version: str,
    quality_gates: Optional[Mapping[str, Any]] = None,
    actor: Optional[str] = "cli",
) -> ModelVersion:
    row = _get_version(db, version)
    metadata = dict(row.metadata_json or {})
    validate_model_metadata(metadata, artifact_root=Path(metadata["_artifact_root"]), verify_files=True)
    result = evaluate_quality_gates(metadata, quality_gates)
    row.validation_result = result
    row.status = "validated" if result["passed"] else "rejected"
    row.rejection_reason = None if result["passed"] else "One or more promotion quality gates failed"
    metadata["registry_status"] = row.status
    metadata["validation_result"] = result
    row.metadata_json = metadata
    row.updated_at = _utcnow()
    _audit(db, "model_validated", row.version, {"passed": result["passed"], "criteria": result["criteria"]}, actor)
    db.flush()
    return row


def _verify_registered_artifacts(row: ModelVersion) -> Dict[str, Any]:
    metadata = dict(row.metadata_json or {})
    root = Path(metadata.get("_artifact_root", ""))
    validated = validate_model_metadata(metadata, artifact_root=root, verify_files=True)
    if validated["artifact_checksums"]["model"] != row.checksum:
        raise GovernanceError("Registered model checksum does not match the verified artifact")
    return metadata


def promote_model(db: Session, version: str, actor: Optional[str] = "cli") -> ModelVersion:
    row = _get_version(db, version)
    if row.status != "validated" or not (row.validation_result or {}).get("passed"):
        raise GovernanceError("Only a model with passing validation criteria can be promoted")
    metadata = _verify_registered_artifacts(row)
    previous_active = db.query(ModelVersion).filter(
        ModelVersion.task == row.task,
        ModelVersion.status == "active",
        ModelVersion.id != row.id,
    ).all()
    for previous in previous_active:
        previous_metadata = dict(previous.metadata_json or {})
        previous_metadata["registry_status"] = "archived"
        _write_artifact_metadata(previous_metadata, "archived")
        previous.metadata_json = previous_metadata
        previous.status = "archived"
        previous.updated_at = _utcnow()
    row.status = "active"
    row.activated_at = _utcnow()
    row.updated_at = _utcnow()
    metadata["registry_status"] = "active"
    _write_artifact_metadata(metadata, "active")
    row.metadata_json = metadata
    _audit(db, "model_promoted", row.version, {"task": row.task, "checksum": row.checksum}, actor)
    db.flush()
    return row


def archive_model(db: Session, version: str, actor: Optional[str] = "cli") -> ModelVersion:
    row = _get_version(db, version)
    row.status = "archived"
    row.updated_at = _utcnow()
    metadata = dict(row.metadata_json or {})
    metadata["registry_status"] = "archived"
    _write_artifact_metadata(metadata, "archived")
    row.metadata_json = metadata
    _audit(db, "model_archived", row.version, {"task": row.task}, actor)
    db.flush()
    return row


def active_model(db: Session, task: str = "network_detection") -> Optional[ModelVersion]:
    return (
        db.query(ModelVersion)
        .filter(ModelVersion.task == task, ModelVersion.status == "active")
        .order_by(ModelVersion.activated_at.desc(), ModelVersion.id.desc())
        .first()
    )


def list_models(db: Session, limit: int = 50, offset: int = 0, task: Optional[str] = None) -> Dict[str, Any]:
    query = db.query(ModelVersion)
    if task:
        query = query.filter(ModelVersion.task == task)
    total = query.count()
    rows = query.order_by(ModelVersion.created_at.desc(), ModelVersion.id.desc()).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [model_version_to_public(row, include_details=False) for row in rows]}
