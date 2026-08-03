"""Compatibility entry point for manifest-driven defensive model training.

Training no longer accepts an ungoverned shuffled CSV. Use a dataset manifest
and review benchmark outputs before registering or promoting an artifact.
"""

import argparse

from .model_benchmark import run_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CyberSage manifest-driven model benchmark")
    parser.add_argument("--manifest", required=True, help="Validated dataset manifest YAML")
    parser.add_argument("--output", default="results/benchmarks", help="Benchmark output directory")
    parser.add_argument("--split-strategy", choices=["group", "time", "capture_day", "random_dev_only"], default="group")
    parser.add_argument("--sequence-length", type=int, default=4)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--skip-transformer", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
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
    print(f"Benchmark complete: {report['run_id']}. Register a reviewed artifact explicitly before promotion.")


if __name__ == "__main__":
    main()
