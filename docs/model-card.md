# Model Card

## Model Family

- Existing supported model: PyTorch Transformer sequence classifier.
- Fallback model: deterministic heuristic used only when artifacts are missing or incompatible.
- Baselines: Logistic Regression and Random Forest support in `backend/train_model.py`.
- Anomaly model: Isolation Forest trained by `backend.train_anomaly_model`.

## Intended Use

Assist defensive analysts in a lab or portfolio setting by classifying normalized network events and supporting transparent alert triage.

## Not Intended For

- Autonomous enforcement decisions.
- Production accuracy claims without representative validation.
- Detecting all attack classes or all network protocols.

## Training Notes

The training script:

- Sets random seeds.
- Splits before fitting the scaler.
- Builds sequences separately per split to avoid overlapping train/test sequences.
- Saves feature order, class mapping, training date, metrics, and split notes.

## Reported Metrics

When training is run, metadata includes per-class precision and recall, macro F1, weighted F1, confusion matrix, PR-AUC where applicable, false-positive rate, and baseline metrics.

## Limitations

The original CIC-style CSV may not preserve capture-day or scenario boundaries. Prefer scenario, host, flow, or time-window grouping for serious evaluation.
