# backend/main.py

import os
import json
import joblib
import asyncio
import pandas as pd
import torch
import torch.nn as nn
import math
import numpy as np
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from kafka import KafkaConsumer
from datetime import datetime
from typing import List

# ----------------------------
# Local Configuration
# ----------------------------
DATABASE_URL = "postgresql://postgres:postgres@localhost/threatdb"
KAFKA_BOOTSTRAP_SERVERS = "localhost:9092"
KAFKA_TOPIC = "network_traffic"

# ----------------------------
# FastAPI App Initialization
# ----------------------------
app = FastAPI(title="AI Cybersecurity Threat Detector API")

# ----------------------------
# CORS Middleware
# ----------------------------
origins = [
    "http://localhost:3000",      # Local frontend
    "http://192.168.29.59:3000",  # Frontend via local network IP
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],   # Allow all HTTP methods
    allow_headers=["*"],   # Allow all headers
)

# ----------------------------
# Transformer Model Definition
# ----------------------------
class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=5000):
        super(PositionalEncoding, self).__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() *
                             (-math.log(10000.0) / d_model))
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

# ----------------------------
# Load Model and Scaler
# ----------------------------
try:
    scaler = joblib.load("./results/scaler.gz")

    INPUT_DIM = 78  # Must match training script
    D_MODEL = 128
    N_HEAD = 8
    N_LAYERS = 3

    model = ThreatTransformer(INPUT_DIM, D_MODEL, N_HEAD, N_LAYERS)
    model.load_state_dict(torch.load("./results/model/transformer_model.pth"))
    model.eval()

    print("✅ Transformer model and scaler loaded successfully!")

except FileNotFoundError:
    print("🛑 Error: Model or scaler not found. Predictions will be disabled.")
    model, scaler = None, None

# ----------------------------
# Database Setup
# ----------------------------
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    prediction = Column(String, index=True)
    probability = Column(Float)
    details = Column(String)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----------------------------
# Prediction Logic
# ----------------------------
def run_prediction(flow_dict: dict):
    if not model or not scaler:
        return "ERROR", 0.0

    feature_names = scaler.get_feature_names_out()
    input_df = pd.DataFrame([flow_dict])
    for col in feature_names:
        if col not in input_df.columns:
            input_df[col] = 0
    input_df = input_df[feature_names]

    scaled_features = scaler.transform(input_df)

    # Dummy sequence length 10
    sequence = np.array([scaled_features[0]] * 10)
    sequence_tensor = torch.tensor([sequence], dtype=torch.float32)

    with torch.no_grad():
        output = model(sequence_tensor)
        probabilities = torch.softmax(output, dim=1)
        confidence, predicted_class = torch.max(probabilities, 1)

    result_label = "BENIGN" if predicted_class.item() == 0 else "ATTACK"
    return result_label, confidence.item()

# ----------------------------
# Kafka Consumer
# ----------------------------
async def consume():
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_deserializer=lambda m: json.loads(m.decode('ascii')),
        auto_offset_reset='earliest',
        group_id='threat-detector-group'
    )
    print("📡 Kafka consumer started...")
    db = SessionLocal()
    try:
        for message in consumer:
            msg_data = message.value
            prediction, probability = run_prediction(msg_data)
            if prediction == "ATTACK":
                alert = Alert(
                    prediction=prediction,
                    probability=probability,
                    details=json.dumps(msg_data)
                )
                db.add(alert)
                db.commit()
                print(f"🚨 Attack detected! Confidence: {probability:.2f}")
    finally:
        db.close()
        consumer.close()

# ----------------------------
# Startup Event
# ----------------------------
@app.on_event("startup")
async def startup_event():
    print("🚀 Application starting up...")
    Base.metadata.create_all(bind=engine)
    print("📂 Database tables ready.")
    asyncio.create_task(consume())

# ----------------------------
# API Endpoints
# ----------------------------
class AlertResponse(BaseModel):
    id: int
    timestamp: datetime
    prediction: str
    probability: float
    details: str

    class Config:
        from_attributes = True

class NetworkFlow(BaseModel):
    flow_duration: float
    tot_fwd_pkts: float
    tot_bwd_pkts: float
    totlen_fwd_pkts: float
    fwd_pkt_len_max: float
    fwd_pkt_len_min: float
    fwd_pkt_len_mean: float
    bwd_pkt_len_max: float
    flow_iat_mean: float
    flow_iat_max: float
    fwd_iat_tot: float

@app.post("/predict")
def predict_flow(flow: NetworkFlow):
    prediction, probability = run_prediction(flow.dict())
    return {"prediction": prediction, "probability": probability}

@app.get("/alerts", response_model=List[AlertResponse])
def get_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()
