import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .telemetry import LEGACY_FEATURES, features_from_event, normalize_event


OUTPUT_DIR = Path("./results/anomaly")
MODEL_PATH = OUTPUT_DIR / "isolation_forest.joblib"
METADATA_PATH = OUTPUT_DIR / "metadata.json"


def synthetic_fixture():
    normal = []
    rng = np.random.default_rng(42)
    for _ in range(120):
        normal.append(
            {
                "flow_duration": float(rng.integers(20, 1000)),
                "tot_fwd_pkts": float(rng.integers(1, 10)),
                "tot_bwd_pkts": float(rng.integers(1, 12)),
                "totlen_fwd_pkts": float(rng.integers(20, 2000)),
                "fwd_pkt_len_max": float(rng.integers(20, 800)),
                "fwd_pkt_len_min": 0.0,
                "fwd_pkt_len_mean": float(rng.integers(20, 300)),
                "bwd_pkt_len_max": float(rng.integers(20, 900)),
                "flow_iat_mean": float(rng.integers(1, 100)),
                "flow_iat_max": float(rng.integers(10, 1000)),
                "fwd_iat_tot": float(rng.integers(20, 1000)),
            }
        )
    return normal


def load_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            event = normalize_event(json.loads(text))
            rows.append(features_from_event(event))
    return rows


def main():
    parser = argparse.ArgumentParser(description="Train a lightweight Isolation Forest anomaly detector")
    parser.add_argument("--jsonl", help="Optional authorized lab telemetry JSONL file")
    args = parser.parse_args()
    rows = load_jsonl(Path(args.jsonl)) if args.jsonl else synthetic_fixture()
    matrix = np.array([[float(row.get(name, 0.0) or 0.0) for name in LEGACY_FEATURES] for row in rows])
    detector = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    detector.fit(matrix)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(detector, MODEL_PATH)
    with METADATA_PATH.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "name": "IsolationForest",
                "version": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
                "feature_list": LEGACY_FEATURES,
                "training_date": datetime.now(timezone.utc).isoformat(),
                "rows": len(rows),
                "source": args.jsonl or "built-in synthetic fixture",
                "note": "This artifact is for lightweight demo/testing, not production baselining.",
            },
            handle,
            indent=2,
        )
    print(f"Saved anomaly detector to {MODEL_PATH}")


if __name__ == "__main__":
    main()
