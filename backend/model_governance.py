"""Reproducible model preparation, evaluation, and artifact contracts.

The functions in this module deliberately keep datasets and trained artifacts
outside the repository. They are shared by the benchmark runner, registry, and
inference loader so model quality claims always describe the same contract.
"""

from __future__ import annotations

import glob
import hashlib
import json
import math
import random
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import MinMaxScaler


MANIFEST_SCHEMA_VERSION = "cybersage.dataset-manifest.v1"
MODEL_METADATA_SCHEMA_VERSION = "cybersage.model-metadata.v1"
DEFAULT_TAXONOMY = (
    "BENIGN",
    "BRUTE_FORCE",
    "DOS_DDOS",
    "RECONNAISSANCE",
    "BOTNET_C2",
    "WEB_ATTACK",
    "INFILTRATION",
    "EXFILTRATION",
    "OTHER_ATTACK",
)
SPLIT_STRATEGIES = {"group", "time", "capture_day", "random_dev_only"}
UNKNOWN_LABEL_POLICIES = {"reject", "other_attack"}


class GovernanceError(ValueError):
    """Raised when a reproducibility or model-governance contract is invalid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise GovernanceError(f"Duplicate manifest key '{key}' is not allowed")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_unique_safe_yaml(source: str) -> Any:
    """Parse YAML with SafeLoader semantics and duplicate-key rejection."""
    loader = _UniqueKeyLoader(source)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_checksum(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalise_label(value: Any) -> str:
    return str(value).strip().upper()


@dataclass(frozen=True)
class DatasetManifest:
    path: Path
    dataset_id: str
    files: Tuple[str, ...]
    label_column: str
    timestamp_column: Optional[str]
    group_column: Optional[str]
    capture_day_column: Optional[str]
    sequence_group_column: Optional[str]
    exclude_columns: Tuple[str, ...]
    feature_columns: Tuple[str, ...]
    label_taxonomy: Mapping[str, str]
    benign_labels: Tuple[str, ...]
    unknown_label_policy: str
    task_mode: str
    licence_notes: str
    source_notes: str
    schema_version: str

    @property
    def checksum(self) -> str:
        return file_checksum(self.path)

    @property
    def sequence_column(self) -> Optional[str]:
        return self.sequence_group_column or self.group_column or self.capture_day_column


@dataclass
class SourceDataset:
    manifest: DatasetManifest
    source_file_checksums: Dict[str, str]
    features: pd.DataFrame
    labels: pd.Series
    source_labels: pd.Series
    sequence_groups: pd.Series
    timestamps: Optional[pd.Series]
    split_groups: Dict[str, pd.Series]
    class_mapping: Dict[int, str]


@dataclass
class PartitionRows:
    name: str
    indices: np.ndarray
    features: pd.DataFrame
    labels: np.ndarray
    groups: pd.Series
    timestamps: Optional[pd.Series]


@dataclass
class SequencePartition:
    name: str
    sequences: np.ndarray
    labels: np.ndarray
    baseline_features: np.ndarray
    groups: List[str]


@dataclass
class PreparedPartitions:
    source: SourceDataset
    strategy: str
    seed: int
    scaler: MinMaxScaler
    row_partitions: Dict[str, PartitionRows]
    sequence_partitions: Dict[str, SequencePartition]
    split_counts: Dict[str, Dict[str, int]]
    warnings: List[str]


def set_deterministic_seeds(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        return


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GovernanceError(f"Manifest field '{field}' must be a mapping")
    return value


def _optional_string(data: Mapping[str, Any], field: str) -> Optional[str]:
    value = data.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"Manifest field '{field}' must be a non-empty string when supplied")
    return value.strip()


def load_dataset_manifest(path: str | Path) -> DatasetManifest:
    manifest_path = Path(path).resolve()
    if not manifest_path.is_file():
        raise GovernanceError(f"Dataset manifest does not exist: {manifest_path}")
    try:
        data = _load_unique_safe_yaml(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise GovernanceError(f"Dataset manifest is not valid YAML: {exc}") from exc
    if not isinstance(data, Mapping):
        raise GovernanceError("Dataset manifest root must be a mapping")

    required = {"dataset_id", "files", "label_column", "label_taxonomy", "benign_labels", "schema_version"}
    missing = sorted(field for field in required if not data.get(field))
    if missing:
        raise GovernanceError(f"Dataset manifest is missing required fields: {', '.join(missing)}")
    schema_version = str(data["schema_version"])
    if schema_version != MANIFEST_SCHEMA_VERSION:
        raise GovernanceError(
            f"Unsupported dataset manifest schema '{schema_version}'; expected '{MANIFEST_SCHEMA_VERSION}'"
        )

    files = data["files"]
    if isinstance(files, str):
        files = [files]
    if not isinstance(files, list) or not files or not all(isinstance(item, str) and item.strip() for item in files):
        raise GovernanceError("Manifest field 'files' must be a non-empty list of local paths or glob patterns")
    taxonomy_data = _require_mapping(data["label_taxonomy"], "label_taxonomy")
    taxonomy: Dict[str, str] = {}
    for raw_label, mapped_label in taxonomy_data.items():
        raw = _normalise_label(raw_label)
        mapped = _normalise_label(mapped_label)
        if not raw or not mapped:
            raise GovernanceError("Label taxonomy cannot contain empty source or destination labels")
        if raw in taxonomy:
            raise GovernanceError(f"Duplicate taxonomy mapping for source label '{raw}'")
        if mapped not in DEFAULT_TAXONOMY and mapped != "ATTACK":
            raise GovernanceError(f"Taxonomy destination '{mapped}' is not a supported class")
        taxonomy[raw] = mapped

    benign_labels = tuple(_normalise_label(value) for value in data["benign_labels"])
    if not benign_labels or any(not value for value in benign_labels):
        raise GovernanceError("Manifest field 'benign_labels' must contain at least one non-empty label")
    for label in benign_labels:
        if label in taxonomy and taxonomy[label] != "BENIGN":
            raise GovernanceError(f"Benign label '{label}' must map to BENIGN")

    policy = str(data.get("unknown_label_policy", "reject")).strip().lower()
    if policy not in UNKNOWN_LABEL_POLICIES:
        raise GovernanceError(f"unknown_label_policy must be one of {sorted(UNKNOWN_LABEL_POLICIES)}")
    task_mode = str(data.get("task_mode", "multiclass")).strip().lower()
    if task_mode not in {"binary", "multiclass"}:
        raise GovernanceError("task_mode must be either 'binary' or 'multiclass'")

    excluded = data.get("exclude_columns", [])
    features = data.get("feature_columns", [])
    if not isinstance(excluded, list) or not all(isinstance(value, str) for value in excluded):
        raise GovernanceError("exclude_columns must be a list of column names")
    if not isinstance(features, list) or not all(isinstance(value, str) for value in features):
        raise GovernanceError("feature_columns must be a list of column names")

    licence_notes = str(data.get("licence_notes", "")).strip()
    source_notes = str(data.get("source_notes", "")).strip()
    if not licence_notes or not source_notes:
        raise GovernanceError("Dataset manifest must include non-empty licence_notes and source_notes")

    return DatasetManifest(
        path=manifest_path,
        dataset_id=str(data["dataset_id"]).strip(),
        files=tuple(item.strip() for item in files),
        label_column=str(data["label_column"]).strip(),
        timestamp_column=_optional_string(data, "timestamp_column"),
        group_column=_optional_string(data, "group_column"),
        capture_day_column=_optional_string(data, "capture_day_column"),
        sequence_group_column=_optional_string(data, "sequence_group_column"),
        exclude_columns=tuple(value.strip() for value in excluded),
        feature_columns=tuple(value.strip() for value in features),
        label_taxonomy=taxonomy,
        benign_labels=benign_labels,
        unknown_label_policy=policy,
        task_mode=task_mode,
        licence_notes=licence_notes,
        source_notes=source_notes,
        schema_version=schema_version,
    )


def _resolve_manifest_files(manifest: DatasetManifest) -> List[Path]:
    repo_root = Path(__file__).resolve().parent.parent
    matched: List[Path] = []
    for pattern in manifest.files:
        candidates: List[str] = []
        candidate_path = Path(pattern)
        if candidate_path.is_absolute():
            candidates = glob.glob(str(candidate_path))
        else:
            candidates = glob.glob(str(manifest.path.parent / pattern))
            if not candidates:
                candidates = glob.glob(str(repo_root / pattern))
        if not candidates:
            raise GovernanceError(f"Manifest file pattern matched no files: {pattern}")
        matched.extend(Path(value).resolve() for value in candidates if Path(value).is_file())
    unique = sorted(set(matched))
    if not unique:
        raise GovernanceError("Manifest did not resolve to any readable dataset files")
    return unique


def _map_labels(raw_labels: pd.Series, manifest: DatasetManifest) -> pd.Series:
    mapped: List[str] = []
    unmapped = set()
    for value in raw_labels:
        raw = _normalise_label(value)
        if raw in manifest.benign_labels:
            label = "BENIGN"
        else:
            label = manifest.label_taxonomy.get(raw)
        if label is None:
            if manifest.unknown_label_policy == "other_attack":
                label = "OTHER_ATTACK"
            else:
                unmapped.add(raw)
                label = "__UNMAPPED__"
        if manifest.task_mode == "binary" and label != "BENIGN" and label != "__UNMAPPED__":
            label = "ATTACK"
        mapped.append(label)
    if unmapped:
        preview = ", ".join(sorted(unmapped)[:8])
        raise GovernanceError(
            f"Source labels have no taxonomy mapping: {preview}. Map them explicitly or use unknown_label_policy: other_attack"
        )
    result = pd.Series(mapped, index=raw_labels.index, dtype="object")
    if result.empty or result.nunique() == 0:
        raise GovernanceError("Taxonomy mapping produced no usable classes")
    if (result == "").any():
        raise GovernanceError("Taxonomy mapping produced an empty class")
    return result


def _class_mapping(labels: pd.Series, task_mode: str) -> Dict[int, str]:
    observed = set(labels.astype(str))
    if not observed:
        raise GovernanceError("Dataset has no classes after taxonomy mapping")
    order = ["BENIGN", "ATTACK"] if task_mode == "binary" else list(DEFAULT_TAXONOMY)
    classes = [name for name in order if name in observed]
    classes.extend(sorted(observed.difference(classes)))
    return {index: label for index, label in enumerate(classes)}


def load_manifest_dataset(manifest: DatasetManifest) -> SourceDataset:
    frames = []
    source_paths = _resolve_manifest_files(manifest)
    for path in source_paths:
        try:
            frame = pd.read_csv(path, low_memory=False)
        except Exception as exc:
            raise GovernanceError(f"Could not read dataset file '{path.name}': {exc}") from exc
        frame.columns = [str(column).strip() for column in frame.columns]
        frames.append(frame)
    frame = pd.concat(frames, ignore_index=True)
    required_columns = [manifest.label_column]
    required_columns.extend(
        value
        for value in (
            manifest.timestamp_column,
            manifest.group_column,
            manifest.capture_day_column,
            manifest.sequence_group_column,
        )
        if value
    )
    missing = sorted(set(required_columns).difference(frame.columns))
    if missing:
        raise GovernanceError(f"Dataset is missing manifest columns: {', '.join(missing)}")
    if frame.empty:
        raise GovernanceError("Dataset contains no rows")

    source_labels = frame[manifest.label_column].copy()
    labels = _map_labels(source_labels, manifest)
    excluded = set(manifest.exclude_columns) | set(required_columns)
    feature_names = list(manifest.feature_columns) if manifest.feature_columns else [
        column for column in frame.columns if column not in excluded
    ]
    if not feature_names:
        raise GovernanceError("No feature columns remain after manifest exclusions")
    missing_features = sorted(set(feature_names).difference(frame.columns))
    if missing_features:
        raise GovernanceError(f"Dataset is missing required feature columns: {', '.join(missing_features)}")
    forbidden_features = sorted(set(feature_names).intersection(required_columns))
    if forbidden_features:
        raise GovernanceError(
            "Feature columns cannot include the label, timestamp, or split/sequence fields: "
            + ", ".join(forbidden_features)
        )
    non_numeric = [column for column in feature_names if not pd.api.types.is_numeric_dtype(frame[column])]
    if non_numeric:
        raise GovernanceError(
            "Required model features must be numeric; invalid columns: " + ", ".join(non_numeric)
        )
    features = frame[feature_names].replace([np.inf, -np.inf], np.nan)
    if features.isna().all(axis=0).any():
        invalid = features.columns[features.isna().all(axis=0)].tolist()
        raise GovernanceError("Required feature columns contain no finite values: " + ", ".join(invalid))
    features = features.fillna(features.median(numeric_only=True)).fillna(0.0)

    sequence_column = manifest.sequence_column
    if not sequence_column:
        raise GovernanceError(
            "Manifest requires sequence_group_column, group_column, or capture_day_column to prevent cross-entity sequences"
        )
    sequence_groups = frame[sequence_column].fillna("__missing_group__").astype(str)
    if (sequence_groups == "__missing_group__").all():
        raise GovernanceError(f"Sequence grouping column '{sequence_column}' contains no usable values")
    timestamps = None
    if manifest.timestamp_column:
        timestamps = pd.to_datetime(frame[manifest.timestamp_column], errors="coerce", utc=True)
        if timestamps.isna().any():
            raise GovernanceError(f"Timestamp column '{manifest.timestamp_column}' contains invalid values")

    split_groups: Dict[str, pd.Series] = {"group": frame[manifest.group_column].fillna("__missing_group__").astype(str) if manifest.group_column else sequence_groups}
    if manifest.capture_day_column:
        split_groups["capture_day"] = frame[manifest.capture_day_column].fillna("__missing_day__").astype(str)
    return SourceDataset(
        manifest=manifest,
        source_file_checksums={path.name: file_checksum(path) for path in source_paths},
        features=features,
        labels=labels,
        source_labels=source_labels,
        sequence_groups=sequence_groups,
        timestamps=timestamps,
        split_groups=split_groups,
        class_mapping=_class_mapping(labels, manifest.task_mode),
    )


def _split_sizes(size: int) -> Tuple[int, int, int]:
    if size < 3:
        raise GovernanceError("At least three samples or groups are required for train, validation, and test partitions")
    train_size = max(1, int(math.floor(size * 0.6)))
    validation_size = max(1, int(math.floor(size * 0.2)))
    test_size = size - train_size - validation_size
    if test_size < 1:
        test_size = 1
        train_size = max(1, train_size - 1)
    return train_size, validation_size, test_size


def _group_split_indices(groups: pd.Series, seed: int) -> Dict[str, np.ndarray]:
    unique_groups = groups.astype(str).nunique()
    if unique_groups < 3:
        raise GovernanceError("Group-aware splitting requires at least three distinct groups")
    indices = np.arange(len(groups))
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    train_validation_indices, test_indices = next(splitter.split(indices, groups=groups.astype(str)))
    remaining_groups = groups.iloc[train_validation_indices].astype(str)
    relative_validation = max(1 / len(train_validation_indices), 0.25)
    splitter = GroupShuffleSplit(n_splits=1, test_size=relative_validation, random_state=seed + 1)
    train_relative, validation_relative = next(
        splitter.split(train_validation_indices, groups=remaining_groups)
    )
    return {
        "train": train_validation_indices[train_relative],
        "validation": train_validation_indices[validation_relative],
        "test": test_indices,
    }


def _time_split_indices(dataset: SourceDataset) -> Dict[str, np.ndarray]:
    if dataset.timestamps is None:
        raise GovernanceError("time split requires timestamp_column in the dataset manifest")
    order = np.argsort(dataset.timestamps.astype("int64").to_numpy(), kind="stable")
    train_size, validation_size, _test_size = _split_sizes(len(order))
    return {
        "train": order[:train_size],
        "validation": order[train_size : train_size + validation_size],
        "test": order[train_size + validation_size :],
    }


def _random_dev_indices(labels: pd.Series, seed: int) -> Dict[str, np.ndarray]:
    indices = np.arange(len(labels))
    counts = labels.value_counts()
    stratify = labels if labels.nunique() > 1 and int(counts.min()) >= 3 else None
    train_validation, test = train_test_split(
        indices, test_size=0.2, random_state=seed, shuffle=True, stratify=stratify
    )
    remaining = labels.iloc[train_validation]
    remaining_counts = remaining.value_counts()
    remaining_stratify = remaining if remaining.nunique() > 1 and int(remaining_counts.min()) >= 2 else None
    train, validation = train_test_split(
        train_validation,
        test_size=0.25,
        random_state=seed + 1,
        shuffle=True,
        stratify=remaining_stratify,
    )
    return {"train": train, "validation": validation, "test": test}


def _assert_partition_integrity(dataset: SourceDataset, indices: Mapping[str, np.ndarray]) -> None:
    seen = set()
    for name, values in indices.items():
        if len(values) == 0:
            raise GovernanceError(f"{name} partition is empty")
        overlap = seen.intersection(int(value) for value in values)
        if overlap:
            raise GovernanceError(f"{name} partition overlaps another partition")
        seen.update(int(value) for value in values)
    if len(seen) != len(dataset.features):
        raise GovernanceError("Split partitions do not cover the complete dataset")
    groups_by_partition = {
        name: set(dataset.sequence_groups.iloc[values].astype(str)) for name, values in indices.items()
    }
    names = list(groups_by_partition)
    for offset, name in enumerate(names):
        for other in names[offset + 1 :]:
            overlap = groups_by_partition[name].intersection(groups_by_partition[other])
            if overlap:
                example = sorted(overlap)[0]
                raise GovernanceError(
                    f"Sequence group '{example}' appears in both {name} and {other}; choose a grouping-compatible split"
                )


def _partition_rows(dataset: SourceDataset, indices: Mapping[str, np.ndarray]) -> Dict[str, PartitionRows]:
    partitions = {}
    for name, values in indices.items():
        partitions[name] = PartitionRows(
            name=name,
            indices=np.asarray(values, dtype=int),
            features=dataset.features.iloc[values].copy(),
            labels=dataset.labels.iloc[values].map(
                {label: index for index, label in dataset.class_mapping.items()}
            ).to_numpy(dtype=int),
            groups=dataset.sequence_groups.iloc[values].copy(),
            timestamps=dataset.timestamps.iloc[values].copy() if dataset.timestamps is not None else None,
        )
    return partitions


def _build_sequences(
    partition: PartitionRows,
    scaled_features: pd.DataFrame,
    sequence_length: int,
) -> SequencePartition:
    sequences: List[np.ndarray] = []
    labels: List[int] = []
    baselines: List[np.ndarray] = []
    sequence_groups: List[str] = []
    local = pd.DataFrame(
        {
            "group": partition.groups.astype(str).to_numpy(),
            "label": partition.labels,
            "position": partition.indices,
        },
        index=partition.indices,
    )
    if partition.timestamps is not None:
        local["timestamp"] = partition.timestamps.to_numpy()
    for group, group_rows in local.groupby("group", sort=True):
        group_rows = group_rows.sort_values("timestamp" if "timestamp" in group_rows else "position", kind="stable")
        positions = group_rows["position"].to_numpy(dtype=int)
        values = scaled_features.loc[positions].to_numpy(dtype=float)
        group_labels = group_rows["label"].to_numpy(dtype=int)
        for offset in range(0, len(values) - sequence_length + 1):
            sequence = values[offset : offset + sequence_length]
            sequences.append(sequence)
            baselines.append(sequence[-1])
            labels.append(int(group_labels[offset + sequence_length - 1]))
            sequence_groups.append(str(group))
    if not sequences:
        raise GovernanceError(
            f"{partition.name} partition has no usable sequences at sequence_length={sequence_length}; add more rows per group"
        )
    return SequencePartition(
        name=partition.name,
        sequences=np.asarray(sequences, dtype=float),
        labels=np.asarray(labels, dtype=int),
        baseline_features=np.asarray(baselines, dtype=float),
        groups=sequence_groups,
    )


def prepare_partitions(
    dataset: SourceDataset,
    strategy: str,
    sequence_length: int,
    seed: int = 42,
) -> PreparedPartitions:
    if strategy not in SPLIT_STRATEGIES:
        raise GovernanceError(f"Unsupported split strategy '{strategy}'; choose one of {sorted(SPLIT_STRATEGIES)}")
    if sequence_length < 1:
        raise GovernanceError("sequence_length must be at least one")
    set_deterministic_seeds(seed)
    warnings: List[str] = []
    if strategy == "group":
        indices = _group_split_indices(dataset.split_groups["group"], seed)
    elif strategy == "capture_day":
        if "capture_day" not in dataset.split_groups:
            raise GovernanceError("capture_day split requires capture_day_column in the dataset manifest")
        indices = _group_split_indices(dataset.split_groups["capture_day"], seed)
    elif strategy == "time":
        indices = _time_split_indices(dataset)
    else:
        indices = _group_split_indices(dataset.sequence_groups, seed)
        warnings.append(
            "random_dev_only randomizes sequence groups for deterministic development fixtures only and is unsuitable for accuracy claims or promotion"
        )
    _assert_partition_integrity(dataset, indices)
    row_partitions = _partition_rows(dataset, indices)
    scaler = MinMaxScaler()
    scaler.fit(row_partitions["train"].features)
    scaled = pd.DataFrame(
        scaler.transform(dataset.features),
        index=np.arange(len(dataset.features)),
        columns=list(dataset.features.columns),
    )
    sequence_partitions = {
        name: _build_sequences(partition, scaled, sequence_length) for name, partition in row_partitions.items()
    }
    split_counts = {
        name: {
            "rows": int(len(partition.indices)),
            "groups": int(partition.groups.astype(str).nunique()),
            "sequences": int(len(sequence_partitions[name].labels)),
        }
        for name, partition in row_partitions.items()
    }
    return PreparedPartitions(
        source=dataset,
        strategy=strategy,
        seed=seed,
        scaler=scaler,
        row_partitions=row_partitions,
        sequence_partitions=sequence_partitions,
        split_counts=split_counts,
        warnings=warnings,
    )


def _safe_float(value: Any) -> Optional[float]:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    return float(value)


def _metric_unavailable(metrics: Dict[str, Any], name: str, reason: str) -> None:
    metrics[name] = None
    metrics.setdefault("metric_notes", {})[name] = reason


def _confidence_quality(y_true: np.ndarray, probabilities: np.ndarray) -> Dict[str, Any]:
    if probabilities.ndim != 2 or len(probabilities) != len(y_true):
        return {"brier_score": None, "calibration_error": None, "confidence_histogram": [], "reason": "probabilities unavailable"}
    class_count = probabilities.shape[1]
    one_hot = np.eye(class_count)[y_true]
    brier = float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))
    confidence = probabilities.max(axis=1)
    correct = probabilities.argmax(axis=1) == y_true
    bins = np.linspace(0.0, 1.0, 11)
    histogram = []
    ece = 0.0
    for left, right in zip(bins[:-1], bins[1:]):
        mask = (confidence >= left) & (confidence < right if right < 1.0 else confidence <= right)
        count = int(mask.sum())
        if not count:
            histogram.append({"start": float(left), "end": float(right), "count": 0, "accuracy": None, "confidence": None})
            continue
        accuracy = float(correct[mask].mean())
        mean_confidence = float(confidence[mask].mean())
        ece += abs(accuracy - mean_confidence) * (count / len(confidence))
        histogram.append(
            {
                "start": float(left),
                "end": float(right),
                "count": count,
                "accuracy": accuracy,
                "confidence": mean_confidence,
            }
        )
    return {"brier_score": brier, "calibration_error": float(ece), "confidence_histogram": histogram}


def evaluate_predictions(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    class_mapping: Mapping[int, str],
    probabilities: Optional[np.ndarray] = None,
    inference_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    truth = np.asarray(y_true, dtype=int)
    predicted = np.asarray(y_pred, dtype=int)
    labels = sorted(class_mapping)
    class_names = [class_mapping[index] for index in labels]
    precision, recall, f1, support = precision_recall_fscore_support(
        truth, predicted, labels=labels, zero_division=0
    )
    matrix = confusion_matrix(truth, predicted, labels=labels)
    per_class = []
    rates = []
    for offset, index in enumerate(labels):
        tp = int(matrix[offset, offset])
        fp = int(matrix[:, offset].sum() - tp)
        fn = int(matrix[offset, :].sum() - tp)
        tn = int(matrix.sum() - tp - fp - fn)
        fpr = float(fp / (fp + tn)) if fp + tn else None
        fnr = float(fn / (fn + tp)) if fn + tp else None
        if fpr is not None:
            rates.append(fpr)
        per_class.append(
            {
                "class": class_mapping[index],
                "precision": _safe_float(precision[offset]),
                "recall": _safe_float(recall[offset]),
                "f1": _safe_float(f1[offset]),
                "support": int(support[offset]),
                "false_positive_rate": fpr,
                "false_negative_rate": fnr,
            }
        )
    metrics: Dict[str, Any] = {
        "per_class": per_class,
        "macro_f1": float(np.mean(f1)),
        "weighted_f1": float(np.average(f1, weights=support)) if int(support.sum()) else None,
        "balanced_accuracy": float(balanced_accuracy_score(truth, predicted)),
        "confusion_matrix": {"labels": class_names, "matrix": matrix.tolist()},
        "false_positive_rate": float(np.mean(rates)) if rates else None,
        "false_negative_rate": float(np.mean([row["false_negative_rate"] for row in per_class if row["false_negative_rate"] is not None])) if per_class else None,
        "sample_count": int(len(truth)),
        "metric_notes": {},
    }
    if probabilities is None:
        _metric_unavailable(metrics, "pr_auc", "probabilities are unavailable")
        _metric_unavailable(metrics, "pr_auc_ovr_macro", "probabilities are unavailable")
        metrics.update(_confidence_quality(truth, np.empty((0, 0))))
    else:
        probabilities = np.asarray(probabilities, dtype=float)
        if probabilities.shape != (len(truth), len(labels)):
            raise GovernanceError("Probability matrix shape does not match evaluated samples and class mapping")
        metrics.update(_confidence_quality(truth, probabilities))
        observed = set(truth.tolist())
        if len(labels) == 2 and len(observed) == 2:
            metrics["pr_auc"] = float(average_precision_score(truth == labels[1], probabilities[:, 1]))
        else:
            _metric_unavailable(metrics, "pr_auc", "binary PR-AUC requires exactly two observed classes")
        if len(observed) >= 2:
            one_hot = np.eye(len(labels))[truth]
            try:
                metrics["pr_auc_ovr_macro"] = float(average_precision_score(one_hot, probabilities, average="macro"))
            except ValueError as exc:
                _metric_unavailable(metrics, "pr_auc_ovr_macro", str(exc))
        else:
            _metric_unavailable(metrics, "pr_auc_ovr_macro", "one-vs-rest PR-AUC requires at least two observed classes")
    if inference_seconds is None:
        _metric_unavailable(metrics, "inference_latency_ms", "inference duration was not measured")
        _metric_unavailable(metrics, "throughput_per_second", "inference duration was not measured")
    else:
        metrics["inference_latency_ms"] = float((inference_seconds / max(len(truth), 1)) * 1000)
        metrics["throughput_per_second"] = float(len(truth) / inference_seconds) if inference_seconds > 0 else None
    return metrics


def _binary_predictions(probabilities: np.ndarray, threshold: float) -> np.ndarray:
    if probabilities.shape[1] != 2:
        raise GovernanceError("Binary threshold selection requires exactly two probability columns")
    return (probabilities[:, 1] >= threshold).astype(int)


def select_threshold(
    validation_labels: Sequence[int],
    validation_probabilities: np.ndarray,
    class_mapping: Mapping[int, str],
    policy: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    policy = dict(policy or {"name": "maximize_macro_f1"})
    policy_name = policy.get("name", "maximize_macro_f1")
    probabilities = np.asarray(validation_probabilities, dtype=float)
    labels = np.asarray(validation_labels, dtype=int)
    if len(class_mapping) != 2:
        return {
            "policy": "argmax_multiclass",
            "selection_dataset": "validation",
            "selected_threshold": None,
            "candidate_thresholds": [],
            "validation_result": {"reason": "multiclass models use argmax to avoid contradictory class thresholds"},
        }
    candidates = [round(value, 2) for value in np.linspace(0.05, 0.95, 19)]
    evaluations = []
    for threshold in candidates:
        predicted = _binary_predictions(probabilities, threshold)
        metrics = evaluate_predictions(labels, predicted, class_mapping, probabilities)
        attack = next((row for row in metrics["per_class"] if row["class"] != "BENIGN"), metrics["per_class"][1])
        evaluations.append(
            {
                "threshold": threshold,
                "macro_f1": metrics["macro_f1"],
                "false_positive_rate": metrics["false_positive_rate"],
                "attack_recall": attack["recall"],
            }
        )
    eligible = evaluations
    if policy_name == "max_false_positive_rate":
        limit = float(policy.get("max_false_positive_rate", 0.05))
        eligible = [item for item in evaluations if item["false_positive_rate"] is not None and item["false_positive_rate"] <= limit]
    elif policy_name == "min_recall_high_risk":
        minimum = float(policy.get("minimum_recall", 0.8))
        eligible = [item for item in evaluations if item["attack_recall"] is not None and item["attack_recall"] >= minimum]
    elif policy_name != "maximize_macro_f1":
        raise GovernanceError("Unsupported threshold policy; use maximize_macro_f1, max_false_positive_rate, or min_recall_high_risk")
    if not eligible:
        eligible = evaluations
        fallback_reason = "No candidate satisfied the configured validation constraint; selected best macro F1."
    else:
        fallback_reason = None
    selected = max(eligible, key=lambda item: (item["macro_f1"], -item["threshold"]))
    return {
        "policy": policy,
        "selection_dataset": "validation",
        "selected_threshold": selected["threshold"],
        "candidate_thresholds": evaluations,
        "validation_result": selected,
        "warning": fallback_reason,
    }


def feature_reference_statistics(features: pd.DataFrame, bins: int = 10) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for name in features.columns:
        values = pd.to_numeric(features[name], errors="coerce")
        finite = values.replace([np.inf, -np.inf], np.nan).dropna().to_numpy(dtype=float)
        if not len(finite):
            result[name] = {"count": 0, "missing_rate": 1.0, "mean": None, "std": None, "quantiles": {}, "min": None, "max": None, "histogram": {"bins": [], "counts": []}}
            continue
        histogram_counts, histogram_bins = np.histogram(finite, bins=bins)
        result[name] = {
            "count": int(len(finite)),
            "missing_rate": float(values.isna().mean()),
            "mean": float(np.mean(finite)),
            "std": float(np.std(finite)),
            "quantiles": {str(key): float(value) for key, value in zip((0.01, 0.25, 0.5, 0.75, 0.99), np.quantile(finite, (0.01, 0.25, 0.5, 0.75, 0.99)))},
            "min": float(np.min(finite)),
            "max": float(np.max(finite)),
            "histogram": {"bins": [float(value) for value in histogram_bins.tolist()], "counts": [int(value) for value in histogram_counts.tolist()]},
        }
    return result


def evaluate_drift(
    reference: Mapping[str, Mapping[str, Any]],
    recent_features: pd.DataFrame,
    model_version: str,
    minimum_samples: int = 30,
) -> Dict[str, Any]:
    if len(recent_features) < minimum_samples:
        return {"status": "insufficient_data", "model_version": model_version, "sample_window": int(len(recent_features)), "minimum_samples": minimum_samples, "features": {}, "reason": "Not enough recent events for a stable drift estimate"}
    missing = [name for name in reference if name not in recent_features.columns]
    if missing:
        return {"status": "degraded", "model_version": model_version, "sample_window": int(len(recent_features)), "features": {}, "reason": "Recent events are missing baseline features: " + ", ".join(missing[:8])}
    feature_results = {}
    psi_values = []
    for name, stats in reference.items():
        bins = np.asarray(stats.get("histogram", {}).get("bins", []), dtype=float)
        expected_counts = np.asarray(stats.get("histogram", {}).get("counts", []), dtype=float)
        values = pd.to_numeric(recent_features[name], errors="coerce").dropna().to_numpy(dtype=float)
        if len(bins) < 2 or not len(expected_counts) or not len(values):
            feature_results[name] = {"psi": None, "reason": "insufficient comparable values"}
            continue
        actual_counts, _ = np.histogram(values, bins=bins)
        expected = np.clip(expected_counts / max(expected_counts.sum(), 1), 1e-6, None)
        actual = np.clip(actual_counts / max(actual_counts.sum(), 1), 1e-6, None)
        psi = float(np.sum((actual - expected) * np.log(actual / expected)))
        feature_results[name] = {"psi": psi, "sample_count": int(len(values))}
        psi_values.append(psi)
    return {
        "status": "ok" if psi_values else "degraded",
        "model_version": model_version,
        "sample_window": int(len(recent_features)),
        "metric": "population_stability_index",
        "summary_psi": float(np.mean(psi_values)) if psi_values else None,
        "features": feature_results,
        "reason": None if psi_values else "No compatible feature distributions were available",
    }


def framework_versions() -> Dict[str, str]:
    versions = {"python": sys.version.split()[0]}
    for package in ("numpy", "pandas", "scikit-learn", "torch", "joblib"):
        try:
            versions[package] = importlib_metadata.version(package)
        except importlib_metadata.PackageNotFoundError:
            versions[package] = "unavailable"
    return versions


def git_commit_sha(repo_root: Optional[Path] = None) -> Optional[str]:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(repo_root or Path(__file__).resolve().parent.parent), text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def validate_model_metadata(
    metadata: Mapping[str, Any],
    artifact_root: Optional[Path] = None,
    verify_files: bool = False,
    allow_legacy: bool = False,
) -> Dict[str, Any]:
    data = dict(metadata)
    if data.get("metadata_schema_version") != MODEL_METADATA_SCHEMA_VERSION:
        if allow_legacy and not data.get("metadata_schema_version"):
            return {"legacy": True, **data}
        raise GovernanceError(
            f"Unsupported model metadata schema '{data.get('metadata_schema_version')}'; expected '{MODEL_METADATA_SCHEMA_VERSION}'"
        )
    required = {
        "model_type",
        "model_version",
        "dataset_identifier",
        "dataset_manifest_checksum",
        "source_file_checksums",
        "training_config_checksum",
        "feature_names",
        "class_mapping",
        "sequence_length",
        "split",
        "training_timestamp",
        "threshold_selection",
        "validation_metrics",
        "test_metrics",
        "artifact_checksums",
        "framework_versions",
        "known_limitations",
    }
    missing = sorted(name for name in required if data.get(name) in (None, "", [], {}))
    if missing:
        raise GovernanceError("Model metadata is missing required fields: " + ", ".join(missing))
    features = data["feature_names"]
    if not isinstance(features, list) or not features or len(features) != len(set(features)):
        raise GovernanceError("Model metadata feature_names must be a non-empty list with unique names")
    try:
        class_mapping = {int(key): str(value) for key, value in data["class_mapping"].items()}
    except (AttributeError, TypeError, ValueError) as exc:
        raise GovernanceError("Model metadata class_mapping must map integer indexes to class names") from exc
    if sorted(class_mapping) != list(range(len(class_mapping))) or not class_mapping:
        raise GovernanceError("Model metadata class_mapping indexes must be contiguous from zero")
    if int(data["sequence_length"]) < 1:
        raise GovernanceError("Model metadata sequence_length must be positive")
    split = data["split"]
    if not isinstance(split, Mapping) or split.get("strategy") not in SPLIT_STRATEGIES:
        raise GovernanceError("Model metadata split.strategy is missing or unsupported")
    checksums = data["artifact_checksums"]
    if not isinstance(checksums, Mapping) or not checksums.get("model") or not checksums.get("scaler"):
        raise GovernanceError("Model metadata must include model and scaler checksums")
    source_checksums = data["source_file_checksums"]
    if not isinstance(source_checksums, Mapping) or not source_checksums or not all(source_checksums.values()):
        raise GovernanceError("Model metadata must include source_file_checksums")
    if verify_files:
        paths = data.get("artifact_paths")
        if not isinstance(paths, Mapping) or not paths.get("model") or not paths.get("scaler"):
            raise GovernanceError("Model metadata must include relative artifact_paths when verifying files")
        root = artifact_root or Path.cwd()
        for name in ("model", "scaler"):
            artifact_path = (root / str(paths[name])).resolve()
            if not artifact_path.is_file():
                raise GovernanceError(f"Required {name} artifact is missing")
            if file_checksum(artifact_path) != checksums[name]:
                raise GovernanceError(f"{name.capitalize()} artifact checksum does not match metadata")
    return {**data, "class_mapping": {str(key): value for key, value in class_mapping.items()}}
