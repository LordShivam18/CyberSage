"""Run a reproducible, leakage-resistant defensive model benchmark."""

from __future__ import annotations

import argparse
import json
import time
import tracemalloc
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

import joblib
import numpy as np
import torch
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from torch.utils.data import DataLoader, TensorDataset

from .model_architecture import ThreatTransformer
from .model_governance import (
    MODEL_METADATA_SCHEMA_VERSION,
    GovernanceError,
    canonical_json_checksum,
    evaluate_predictions,
    feature_reference_statistics,
    file_checksum,
    framework_versions,
    git_commit_sha,
    load_dataset_manifest,
    load_manifest_dataset,
    prepare_partitions,
    select_threshold,
    set_deterministic_seeds,
    utcnow_iso,
    validate_model_metadata,
)


def _json_dump(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _align_probabilities(estimator, values: np.ndarray, class_count: int) -> np.ndarray:
    raw = estimator.predict_proba(values)
    aligned = np.zeros((len(values), class_count), dtype=float)
    for column, class_index in enumerate(estimator.classes_):
        if int(class_index) < class_count:
            aligned[:, int(class_index)] = raw[:, column]
    return aligned


def _predict_transformer(model, sequences: np.ndarray) -> Tuple[np.ndarray, float]:
    started = time.perf_counter()
    model.eval()
    with torch.no_grad():
        output = model(torch.tensor(sequences, dtype=torch.float32))
        probabilities = torch.softmax(output, dim=1).cpu().numpy()
    return probabilities, time.perf_counter() - started


def _thresholded_predictions(probabilities: np.ndarray, threshold: Optional[float]) -> np.ndarray:
    if threshold is None or probabilities.shape[1] != 2:
        return probabilities.argmax(axis=1)
    return (probabilities[:, 1] >= threshold).astype(int)


def _measure_fit(factory, train_x: np.ndarray, train_y: np.ndarray):
    tracemalloc.start()
    started = time.perf_counter()
    model = factory()
    model.fit(train_x, train_y)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return model, elapsed, int(peak)


def _artifact_metadata(
    *,
    run_id: str,
    model_type: str,
    model_filename: str,
    scaler_filename: str,
    artifact_dir: Path,
    prepared,
    threshold_selection: Mapping[str, Any],
    validation_metrics: Mapping[str, Any],
    test_metrics: Mapping[str, Any],
    training_config: Mapping[str, Any],
    limitations: list[str],
) -> Dict[str, Any]:
    model_path = artifact_dir / model_filename
    scaler_path = artifact_dir / scaler_filename
    return {
        "metadata_schema_version": MODEL_METADATA_SCHEMA_VERSION,
        "registry_status": "candidate",
        "task": "network_detection",
        "model_type": model_type,
        "model_version": f"{run_id}-{model_type}",
        "dataset_identifier": prepared.source.manifest.dataset_id,
        "dataset_manifest_checksum": prepared.source.manifest.checksum,
        "source_file_checksums": prepared.source.source_file_checksums,
        "training_config_checksum": canonical_json_checksum(training_config),
        "feature_names": list(prepared.source.features.columns),
        "feature_list": list(prepared.source.features.columns),
        "class_mapping": {str(key): value for key, value in prepared.source.class_mapping.items()},
        "sequence_length": int(training_config["sequence_length"]),
        "split": {"strategy": prepared.strategy, "counts": prepared.split_counts, "seed": prepared.seed},
        "training_timestamp": utcnow_iso(),
        "threshold_selection": dict(threshold_selection),
        "validation_metrics": dict(validation_metrics),
        "test_metrics": dict(test_metrics),
        "artifact_checksums": {"model": file_checksum(model_path), "scaler": file_checksum(scaler_path)},
        "artifact_paths": {"model": model_filename, "scaler": scaler_filename},
        "framework_versions": framework_versions(),
        "known_limitations": limitations,
        "drift_baseline": feature_reference_statistics(prepared.row_partitions["train"].features),
        "architecture": {"d_model": 128, "nhead": 8, "nlayers": 3},
    }


def _evaluate_supervised_model(
    estimator,
    prepared,
    policy: Optional[Mapping[str, Any]],
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    validation = prepared.sequence_partitions["validation"]
    test = prepared.sequence_partitions["test"]
    validation_probabilities = _align_probabilities(
        estimator, validation.baseline_features, len(prepared.source.class_mapping)
    )
    threshold = select_threshold(validation.labels, validation_probabilities, prepared.source.class_mapping, policy)
    validation_predictions = _thresholded_predictions(validation_probabilities, threshold["selected_threshold"])
    validation_metrics = evaluate_predictions(
        validation.labels, validation_predictions, prepared.source.class_mapping, validation_probabilities
    )
    started = time.perf_counter()
    test_probabilities = _align_probabilities(estimator, test.baseline_features, len(prepared.source.class_mapping))
    inference_seconds = time.perf_counter() - started
    test_predictions = _thresholded_predictions(test_probabilities, threshold["selected_threshold"])
    test_metrics = evaluate_predictions(
        test.labels,
        test_predictions,
        prepared.source.class_mapping,
        test_probabilities,
        inference_seconds,
    )
    return threshold, validation_metrics, test_metrics


def _evaluate_isolation_forest(prepared, artifact_dir: Path) -> Dict[str, Any]:
    train = prepared.sequence_partitions["train"]
    validation = prepared.sequence_partitions["validation"]
    test = prepared.sequence_partitions["test"]
    class_mapping = prepared.source.class_mapping
    benign_index = next((index for index, label in class_mapping.items() if label == "BENIGN"), 0)
    benign_training = train.baseline_features[train.labels == benign_index]
    fit_values = benign_training if len(benign_training) >= 2 else train.baseline_features
    model, training_seconds, peak_memory = _measure_fit(
        lambda: IsolationForest(n_estimators=50, contamination="auto", random_state=prepared.seed), fit_values, np.zeros(len(fit_values))
    )
    started = time.perf_counter()
    predicted = (model.predict(test.baseline_features) == -1).astype(int)
    elapsed = time.perf_counter() - started
    binary_truth = (test.labels != benign_index).astype(int)
    metrics = evaluate_predictions(
        binary_truth,
        predicted,
        {0: "BENIGN", 1: "ATTACK"},
        probabilities=None,
        inference_seconds=elapsed,
    )
    path = artifact_dir / "isolation_forest.joblib"
    joblib.dump(model, path)
    return {
        "status": "completed",
        "model_type": "isolation_forest_anomaly_only",
        "training_seconds": training_seconds,
        "peak_memory_bytes": peak_memory,
        "test_metrics": metrics,
        "artifact_checksum": file_checksum(path),
        "notes": ["Isolation Forest is evaluated only as benign-versus-anomalous detection, not attack-family classification."],
    }


def _train_transformer(prepared, epochs: int, policy: Optional[Mapping[str, Any]]):
    train = prepared.sequence_partitions["train"]
    validation = prepared.sequence_partitions["validation"]
    test = prepared.sequence_partitions["test"]
    model = ThreatTransformer(
        input_dim=train.sequences.shape[2],
        d_model=128,
        nhead=8,
        nlayers=3,
        num_classes=len(prepared.source.class_mapping),
    )
    loader = DataLoader(
        TensorDataset(
            torch.tensor(train.sequences, dtype=torch.float32),
            torch.tensor(train.labels, dtype=torch.long),
        ),
        batch_size=min(32, max(1, len(train.labels))),
        shuffle=True,
    )
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.0001)
    tracemalloc.start()
    started = time.perf_counter()
    model.train()
    for _epoch in range(epochs):
        for values, labels in loader:
            optimizer.zero_grad()
            loss = criterion(model(values), labels)
            loss.backward()
            optimizer.step()
    training_seconds = time.perf_counter() - started
    _current, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    validation_probabilities, _validation_seconds = _predict_transformer(model, validation.sequences)
    threshold = select_threshold(validation.labels, validation_probabilities, prepared.source.class_mapping, policy)
    validation_predictions = _thresholded_predictions(validation_probabilities, threshold["selected_threshold"])
    validation_metrics = evaluate_predictions(
        validation.labels, validation_predictions, prepared.source.class_mapping, validation_probabilities
    )
    test_probabilities, inference_seconds = _predict_transformer(model, test.sequences)
    test_predictions = _thresholded_predictions(test_probabilities, threshold["selected_threshold"])
    test_metrics = evaluate_predictions(
        test.labels, test_predictions, prepared.source.class_mapping, test_probabilities, inference_seconds
    )
    return model, threshold, validation_metrics, test_metrics, training_seconds, int(peak_memory)


def _render_markdown(report: Mapping[str, Any]) -> str:
    rows = [
        "# CyberSage Model Benchmark",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Dataset: `{report['dataset_identifier']}`",
        f"- Split strategy: `{report['split']['strategy']}`",
        f"- Timestamp: `{report['created_at']}`",
        "",
        "## Results",
        "",
        "| Model | Status | Macro F1 | Weighted F1 | FPR | Latency ms |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for name, result in report["models"].items():
        metrics = result.get("test_metrics", {})
        rows.append(
            "| {name} | {status} | {macro} | {weighted} | {fpr} | {latency} |".format(
                name=name,
                status=result.get("status", "unknown"),
                macro=_format_metric(metrics.get("macro_f1")),
                weighted=_format_metric(metrics.get("weighted_f1")),
                fpr=_format_metric(metrics.get("false_positive_rate")),
                latency=_format_metric(metrics.get("inference_latency_ms")),
            )
        )
    rows.extend(["", "## Limitations", ""])
    rows.extend(f"- {item}" for item in report.get("limitations", []))
    return "\n".join(rows) + "\n"


def _format_metric(value: Any) -> str:
    return "n/a" if value is None else f"{float(value):.4f}"


def run_benchmark(
    manifest_path: str | Path,
    output_directory: str | Path,
    *,
    split_strategy: str = "group",
    sequence_length: int = 4,
    seed: int = 42,
    epochs: int = 3,
    skip_transformer: bool = False,
    threshold_policy: Optional[Mapping[str, Any]] = None,
    run_id: Optional[str] = None,
    overwrite: bool = False,
) -> Dict[str, Any]:
    manifest = load_dataset_manifest(manifest_path)
    dataset = load_manifest_dataset(manifest)
    prepared = prepare_partitions(dataset, split_strategy, sequence_length, seed)
    run_id = run_id or f"benchmark-{datetime_now_compact()}-{uuid.uuid4().hex[:8]}"
    run_dir = Path(output_directory).resolve() / run_id
    if run_dir.exists() and (run_dir / "benchmark.json").exists() and not overwrite:
        raise GovernanceError(f"Completed benchmark run already exists: {run_dir}. Use --overwrite to replace it.")
    run_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(prepared.scaler, artifact_dir / "scaler.joblib")

    train = prepared.sequence_partitions["train"]
    models: Dict[str, Dict[str, Any]] = {}
    training_config = {
        "split_strategy": split_strategy,
        "sequence_length": sequence_length,
        "seed": seed,
        "transformer_epochs": epochs,
        "threshold_policy": dict(threshold_policy or {"name": "maximize_macro_f1"}),
    }
    limitations = list(prepared.warnings) + [
        "Benchmark outputs are evaluation evidence, not a claim of production readiness.",
        "No model is promoted automatically by this benchmark.",
    ]
    baseline_factories = {
        "logistic_regression": lambda: LogisticRegression(max_iter=500, random_state=seed),
        "random_forest": lambda: RandomForestClassifier(n_estimators=75, random_state=seed, n_jobs=1),
    }
    for name, factory in baseline_factories.items():
        try:
            model, training_seconds, peak_memory = _measure_fit(factory, train.baseline_features, train.labels)
            threshold, validation_metrics, test_metrics = _evaluate_supervised_model(model, prepared, threshold_policy)
            artifact_path = artifact_dir / f"{name}.joblib"
            joblib.dump(model, artifact_path)
            artifact_metadata = _artifact_metadata(
                run_id=run_id,
                model_type=name,
                model_filename=artifact_path.name,
                scaler_filename="scaler.joblib",
                artifact_dir=artifact_dir,
                prepared=prepared,
                threshold_selection=threshold,
                validation_metrics=validation_metrics,
                test_metrics=test_metrics,
                training_config=training_config,
                limitations=limitations,
            )
            metadata_path = artifact_dir / f"{name}.metadata.json"
            _json_dump(metadata_path, artifact_metadata)
            validate_model_metadata(artifact_metadata, artifact_root=artifact_dir, verify_files=True)
            models[name] = {
                "status": "completed",
                "training_seconds": training_seconds,
                "peak_memory_bytes": peak_memory,
                "threshold_selection": threshold,
                "validation_metrics": validation_metrics,
                "test_metrics": test_metrics,
                "artifact": {"checksum": file_checksum(artifact_path), "metadata_file": metadata_path.name},
            }
        except Exception as exc:
            models[name] = {"status": "failed", "reason": str(exc)}

    try:
        models["isolation_forest"] = _evaluate_isolation_forest(prepared, artifact_dir)
    except Exception as exc:
        models["isolation_forest"] = {"status": "failed", "reason": str(exc)}

    if skip_transformer:
        models["transformer"] = {
            "status": "skipped",
            "reason": "Transformer training was explicitly skipped; baseline results remain valid.",
        }
    else:
        try:
            transformer, threshold, validation_metrics, test_metrics, training_seconds, peak_memory = _train_transformer(
                prepared, epochs, threshold_policy
            )
            artifact_path = artifact_dir / "transformer_model.pth"
            torch.save(transformer.state_dict(), artifact_path)
            artifact_metadata = _artifact_metadata(
                run_id=run_id,
                model_type="transformer",
                model_filename=artifact_path.name,
                scaler_filename="scaler.joblib",
                artifact_dir=artifact_dir,
                prepared=prepared,
                threshold_selection=threshold,
                validation_metrics=validation_metrics,
                test_metrics=test_metrics,
                training_config=training_config,
                limitations=limitations,
            )
            metadata_path = artifact_dir / "transformer.metadata.json"
            _json_dump(metadata_path, artifact_metadata)
            validate_model_metadata(artifact_metadata, artifact_root=artifact_dir, verify_files=True)
            models["transformer"] = {
                "status": "completed",
                "training_seconds": training_seconds,
                "peak_memory_bytes": peak_memory,
                "threshold_selection": threshold,
                "validation_metrics": validation_metrics,
                "test_metrics": test_metrics,
                "artifact": {"checksum": file_checksum(artifact_path), "metadata_file": metadata_path.name},
            }
        except Exception as exc:
            models["transformer"] = {"status": "failed", "reason": str(exc)}

    report = {
        "schema_version": "cybersage.benchmark-report.v1",
        "run_id": run_id,
        "created_at": utcnow_iso(),
        "dataset_identifier": manifest.dataset_id,
        "dataset_manifest_checksum": manifest.checksum,
        "source_file_checksums": dataset.source_file_checksums,
        "git_commit_sha": git_commit_sha(),
        "framework_versions": framework_versions(),
        "split": {"strategy": prepared.strategy, "counts": prepared.split_counts, "seed": prepared.seed},
        "class_mapping": {str(key): value for key, value in dataset.class_mapping.items()},
        "feature_names": list(dataset.features.columns),
        "training_config": training_config,
        "training_config_checksum": canonical_json_checksum(training_config),
        "models": models,
        "limitations": limitations,
    }
    _json_dump(run_dir / "benchmark.json", report)
    _json_dump(
        run_dir / "confusion_matrices.json",
        {name: result.get("test_metrics", {}).get("confusion_matrix") for name, result in models.items()},
    )
    (run_dir / "benchmark.md").write_text(_render_markdown(report), encoding="utf-8")
    return report


def datetime_now_compact() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark CyberSage models from a validated local dataset manifest")
    parser.add_argument("--manifest", required=True, help="Path to a dataset manifest YAML file")
    parser.add_argument("--output", required=True, help="Directory where a unique benchmark run will be created")
    parser.add_argument("--split-strategy", choices=["group", "time", "capture_day", "random_dev_only"], default="group")
    parser.add_argument("--sequence-length", type=int, default=4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--skip-transformer", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = run_benchmark(
        args.manifest,
        args.output,
        split_strategy=args.split_strategy,
        sequence_length=args.sequence_length,
        seed=args.seed,
        epochs=args.epochs,
        skip_transformer=args.skip_transformer,
        run_id=args.run_id,
        overwrite=args.overwrite,
    )
    print(f"Completed benchmark {report['run_id']} with {len(report['models'])} model results")


if __name__ == "__main__":
    main()
