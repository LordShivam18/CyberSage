# Model Card

## Model Family

- Candidate classifier: PyTorch Transformer sequence classifier.
- Mandatory benchmarks: Logistic Regression and Random Forest under the same prepared partitions.
- Auxiliary anomaly baseline: Isolation Forest, reported separately from supervised class quality.
- Runtime fallback: deterministic heuristic, visibly degraded and never represented as a trained model.

## Intended Use

Assist authorized defensive analysts in a lab or portfolio setting by classifying normalized network flows and adding evidence to triage. Outputs support, but never replace, analyst judgement.

## Data And Taxonomy

Training accepts only a versioned local dataset manifest. The manifest identifies source files, source licence notes, labels, benign aliases, unknown-label policy, numeric feature selection/exclusions, and group/time fields. The supported multiclass taxonomy is `BENIGN`, `BRUTE_FORCE`, `DOS_DDOS`, `RECONNAISSANCE`, `BOTNET_C2`, `WEB_ATTACK`, `INFILTRATION`, `EXFILTRATION`, and `OTHER_ATTACK`; binary training maps every non-benign class to `ATTACK`.

## Evaluation Protocol

- Group, capture-day, or chronological time partitions prevent sequence groups from crossing train, validation, and test data.
- Scaling fits train rows only. Sequences are generated independently within each partition and group.
- Threshold selection uses validation data only. Test metrics are held out from selection.
- Reported fields include per-class precision/recall/F1/support, macro and weighted F1, balanced accuracy, confusion matrix, false-positive and false-negative rates, PR-AUC when defined, Brier score, calibration error, latency, throughput, and benchmark resource measurements.
- `random_dev_only` exists only for deterministic fixtures; it cannot pass promotion validation.

## Artifact And Registry Contract

Every benchmark artifact carries a metadata schema version, dataset manifest checksum, training configuration checksum, feature order, class mapping, model/scaler checksums, split evidence, threshold record, framework versions, known limitations, and a train-feature drift baseline. A candidate moves through `candidate`, `validated`, `active`, `rejected`, or `archived`. Promotion requires checksum verification and records an audit event.

The default development gates require held-out macro F1 >= `0.50`, macro false-positive rate <= `0.20`, and average held-out inference latency <= `1000 ms`; reviewers may require per-class recall floors. These defaults are guardrails, not deployment or performance claims.

## Limitations

- No accuracy, robustness, or production-readiness claim is made without reviewing the specific benchmark report and source-data representativeness.
- A dataset with weak scenario, host, flow, capture-day, or time evidence may still produce misleading quality estimates.
- Production drift reporting is PSI-based and returns `insufficient_data` or `degraded` instead of fabricating a result.
- The legacy binary artifact format is supported only as an explicit compatibility state.
