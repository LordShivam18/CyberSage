# train_model.py (Transformer Version - Memory Optimized)

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import joblib
import os
import math
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report

# --- Configuration ---
DATA_FILE_PATH = "./data/MachineLearningCVE.csv"
MODEL_OUTPUT_DIR = "./results/model"
SCALER_OUTPUT_PATH = "./results/scaler.gz"

# Model Hyperparameters
SEQUENCE_LENGTH = 10
TEST_SIZE = 0.2
BATCH_SIZE = 32 # <-- REDUCED BATCH SIZE
EPOCHS = 3
D_MODEL = 128 # The dimension of the transformer model
N_HEAD = 8 # Number of attention heads
N_LAYERS = 3 # Number of transformer layers

# --- 1. Data Loading and Preprocessing ---
print("Step 1: Loading and Preprocessing Data...")
def load_and_preprocess_data(filepath):
    df = pd.read_csv(filepath, encoding='latin1', low_memory=False)
    
    # --- MEMORY FIX: Use a fraction of the data ---
    print(f"Original dataset size: {len(df)} rows")
    df = df.sample(frac=0.1, random_state=42) # Using 10% of the data
    print(f"Downsampled dataset size: {len(df)} rows")
    
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
    if 'Label' not in numeric_cols:
        numeric_cols.append('Label')
    df_numeric = df[numeric_cols]
    X = df_numeric.drop('Label', axis=1)
    y = df_numeric['Label']
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, SCALER_OUTPUT_PATH)
    print(f"Scaler saved to {SCALER_OUTPUT_PATH}")
    return X_scaled, y.values

# --- 2. Sequence Creation ---
print("Step 2: Creating Sequences...")
def create_sequences(features, labels, seq_length):
    sequences, sequence_labels = [], []
    for i in range(len(features) - seq_length):
        sequences.append(features[i:i+seq_length])
        sequence_labels.append(labels[i+seq_length-1])
    return np.array(sequences), np.array(sequence_labels)

# --- 3. Custom Transformer Model Definition ---
print("Step 3: Defining Custom Transformer Model...")

class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=5000):
        super(PositionalEncoding, self).__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0).transpose(0, 1)
        self.register_buffer('pe', pe)

    def forward(self, x):
        return x + self.pe[:x.size(0), :]

class ThreatTransformer(nn.Module):
    def __init__(self, input_dim, d_model, nhead, nlayers, num_classes=2):
        super(ThreatTransformer, self).__init__()
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
        output = self.decoder(output)
        return output

# --- 4. Main Execution Block ---
def main():
    features, labels = load_and_preprocess_data(DATA_FILE_PATH)
    sequences, sequence_labels = create_sequences(features, labels, SEQUENCE_LENGTH)

    input_dim = features.shape[1]

    X_tensor = torch.tensor(sequences, dtype=torch.float32)
    y_tensor = torch.tensor(sequence_labels, dtype=torch.long)

    X_train, X_test, y_train, y_test = train_test_split(
        X_tensor, y_tensor, test_size=TEST_SIZE, random_state=42, stratify=y_tensor
    )

    train_dataset = TensorDataset(X_train, y_train)
    test_dataset = TensorDataset(X_test, y_test)
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    model = ThreatTransformer(input_dim, D_MODEL, N_HEAD, N_LAYERS, num_classes=2)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.0001)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    print(f"Using device: {device}")

    print("Step 4: Starting Transformer Model Training...")
    for epoch in range(EPOCHS):
        model.train()
        for i, (batch_sequences, batch_labels) in enumerate(train_loader):
            batch_sequences, batch_labels = batch_sequences.to(device), batch_labels.to(device)

            optimizer.zero_grad()
            outputs = model(batch_sequences)
            loss = criterion(outputs, batch_labels)
            loss.backward()
            optimizer.step()
            
            if (i + 1) % 100 == 0:
                print(f'Epoch [{epoch+1}/{EPOCHS}], Step [{i+1}/{len(train_loader)}], Loss: {loss.item():.4f}')

    print("Evaluating model...")
    model.eval()
    all_preds, all_labels = [], []
    with torch.no_grad():
        for batch_sequences, batch_labels in test_loader:
            batch_sequences = batch_sequences.to(device)
            outputs = model(batch_sequences)
            _, predicted = torch.max(outputs.data, 1)
            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(batch_labels.numpy())
            
    print(classification_report(all_labels, all_preds, target_names=['BENIGN', 'ATTACK']))

    model_path = os.path.join(MODEL_OUTPUT_DIR, "transformer_model.pth")
    torch.save(model.state_dict(), model_path)
    print(f"Transformer model saved to {model_path}")


if __name__ == '__main__':
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    main()
