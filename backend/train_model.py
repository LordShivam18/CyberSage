import argparse
import json
import math
import os
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from torch.utils.data import DataLoader, TensorDataset


DATA_FILE_PATH = "./data/MachineLearningCVE.csv"
MODEL_OUTPUT_DIR = Path("./results/model")
SCALER_OUTPUT_PATH = Path("./results/scaler.gz")
METADATA_OUTPUT_PATH = MODEL_OUTPUT_DIR / "metadata.json"
BASELINE_OUTPUT_DIR = Path("./results/baselines")

SEQUENCE_LENGTH = 10
TEST_SIZE = 0.2
BATCH_SIZE = 32
EPOCHS = 3
D_MODEL = 128
N_HEAD = 8
N_LAYERS = 3
RANDOM_SEED = 42


def set_seeds(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=5000):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        self.register_buffer("pe", pe)

    def forward(self, x):
        return x + self.pe[: x.size(0), :]


class ThreatTransformer(nn.Module):
    def __init__(self, input_dim, d_model, nhead, nlayers, num_classes=2):
        super().__init__()
        self.d_model = d_model
        self.encoder = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model)
        encoder_layers = nn.TransformerEncoderLayer(d_model, nhead, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, nlayers)
        self.decoder = nn.Linear(d_model, num_classes)

    def forward(self, src):
        src = self.encoder(src) * math.sqrt(self.d_model)
        src = self.pos_encoder(src)
        output = self.transformer_encoder(src)
        output = output[:, -1, :]
        return self.decoder(output)


def load_dataset(filepath: str, sample_frac: float) -> Tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(filepath, encoding="latin1", low_memory=False)
    df.columns = df.columns.str.strip()
    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=RANDOM_SEED)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    if "Label" not in df:
        raise ValueError("Expected CIC-style dataset with a Label column")
    y = df["Label"].apply(lambda value: 0 if str(value).upper() == "BENIGN" else 1)
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
    feature_frame = df[numeric_cols].copy()
    return feature_frame, y


def split_and_scale(features: pd.DataFrame, labels: pd.Series):
    train_x, test_x, train_y, test_y = train_test_split(
        features,
        labels,
        test_size=TEST_SIZE,
        random_state=RANDOM_SEED,
        stratify=labels if labels.nunique() > 1 else None,
        shuffle=True,
    )
    scaler = MinMaxScaler()
    train_scaled = scaler.fit_transform(train_x)
    test_scaled = scaler.transform(test_x)
    scaler.feature_names_in_ = np.array(features.columns)
    return train_scaled, test_scaled, train_y.values, test_y.values, scaler, list(features.columns)


def create_sequences(features, labels, seq_length):
    sequences, sequence_labels = [], []
    for i in range(len(features) - seq_length + 1):
        sequences.append(features[i : i + seq_length])
        sequence_labels.append(labels[i + seq_length - 1])
    return np.array(sequences), np.array(sequence_labels)


def evaluate_predictions(y_true, y_pred, y_score=None) -> Dict:
    report = classification_report(
        y_true,
        y_pred,
        target_names=["BENIGN", "ATTACK"],
        output_dict=True,
        zero_division=0,
    )
    metrics = {
        "classification_report": report,
        "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "weighted_f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "false_positive_rate": _false_positive_rate(y_true, y_pred),
    }
    if y_score is not None and len(set(y_true)) > 1:
        metrics["pr_auc"] = average_precision_score(y_true, y_score)
    return metrics


def _false_positive_rate(y_true, y_pred) -> float:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, _fn, _tp = matrix.ravel()
    return float(fp / (fp + tn)) if (fp + tn) else 0.0


def train_baselines(train_x, test_x, train_y, test_y) -> Dict:
    BASELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    baselines = {
        "logistic_regression": LogisticRegression(max_iter=500, random_state=RANDOM_SEED),
        "random_forest": RandomForestClassifier(n_estimators=50, random_state=RANDOM_SEED, n_jobs=-1),
    }
    metrics = {}
    for name, estimator in baselines.items():
        estimator.fit(train_x, train_y)
        predictions = estimator.predict(test_x)
        scores = estimator.predict_proba(test_x)[:, 1] if hasattr(estimator, "predict_proba") else None
        metrics[name] = evaluate_predictions(test_y, predictions, scores)
        joblib.dump(estimator, BASELINE_OUTPUT_DIR / f"{name}.joblib")
    return metrics


def train_transformer(train_x, test_x, train_y, test_y, input_dim):
    train_sequences, train_labels = create_sequences(train_x, train_y, SEQUENCE_LENGTH)
    test_sequences, test_labels = create_sequences(test_x, test_y, SEQUENCE_LENGTH)
    if len(train_sequences) == 0 or len(test_sequences) == 0:
        raise ValueError("Not enough rows after split to create non-overlapping train/test sequences")

    train_dataset = TensorDataset(
        torch.tensor(train_sequences, dtype=torch.float32),
        torch.tensor(train_labels, dtype=torch.long),
    )
    test_dataset = TensorDataset(
        torch.tensor(test_sequences, dtype=torch.float32),
        torch.tensor(test_labels, dtype=torch.long),
    )
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    model = ThreatTransformer(input_dim, D_MODEL, N_HEAD, N_LAYERS, num_classes=2)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.0001)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    for epoch in range(EPOCHS):
        model.train()
        for batch_sequences, batch_labels in train_loader:
            batch_sequences, batch_labels = batch_sequences.to(device), batch_labels.to(device)
            optimizer.zero_grad()
            loss = criterion(model(batch_sequences), batch_labels)
            loss.backward()
            optimizer.step()
        print(f"Epoch {epoch + 1}/{EPOCHS} complete")

    model.eval()
    all_preds, all_scores, all_labels = [], [], []
    with torch.no_grad():
        for batch_sequences, batch_labels in test_loader:
            batch_sequences = batch_sequences.to(device)
            output = model(batch_sequences)
            probabilities = torch.softmax(output, dim=1)
            all_scores.extend(probabilities[:, 1].cpu().numpy())
            all_preds.extend(torch.argmax(probabilities, dim=1).cpu().numpy())
            all_labels.extend(batch_labels.numpy())

    metrics = evaluate_predictions(np.array(all_labels), np.array(all_preds), np.array(all_scores))
    return model, metrics


def main():
    parser = argparse.ArgumentParser(description="Train defensive NDR models on a local CIC-style CSV")
    parser.add_argument("--data", default=DATA_FILE_PATH)
    parser.add_argument("--sample-frac", type=float, default=0.1)
    parser.add_argument("--skip-transformer", action="store_true")
    args = parser.parse_args()

    set_seeds(RANDOM_SEED)
    MODEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    features, labels = load_dataset(args.data, args.sample_frac)
    train_x, test_x, train_y, test_y, scaler, feature_list = split_and_scale(features, labels)
    joblib.dump(scaler, SCALER_OUTPUT_PATH)

    baseline_metrics = train_baselines(train_x, test_x, train_y, test_y)
    transformer_metrics = {}
    if not args.skip_transformer:
        transformer, transformer_metrics = train_transformer(
            train_x, test_x, train_y, test_y, input_dim=len(feature_list)
        )
        torch.save(transformer.state_dict(), MODEL_OUTPUT_DIR / "transformer_model.pth")

    metadata = {
        "name": "ThreatTransformer",
        "version": datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        "dataset_identifier": Path(args.data).name,
        "class_mapping": {"0": "BENIGN", "1": "ATTACK"},
        "feature_list": feature_list,
        "scaler_version": "MinMaxScaler-fit-on-training-split",
        "training_date": datetime.utcnow().isoformat(),
        "random_seed": RANDOM_SEED,
        "split_strategy": "stratified row split before scaling; sequences built separately per split",
        "sequence_length": SEQUENCE_LENGTH,
        "metrics": {
            "transformer": transformer_metrics,
            "baselines": baseline_metrics,
        },
        "limitations": [
            "Rows are shuffled because the source CSV may not preserve capture-day boundaries.",
            "Use scenario, host, flow, or time-window grouping before production evaluation.",
        ],
    }
    with METADATA_OUTPUT_PATH.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)
    print(f"Saved scaler to {SCALER_OUTPUT_PATH}")
    print(f"Saved metadata to {METADATA_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
