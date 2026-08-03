"""Shared Torch model architecture for training and inference."""

import math

import torch
import torch.nn as nn


class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 5000):
        super().__init__()
        encoding = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        encoding[:, 0::2] = torch.sin(position * div_term)
        encoding[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", encoding.unsqueeze(0).transpose(0, 1))

    def forward(self, value):
        return value + self.pe[: value.size(0), :]


class ThreatTransformer(nn.Module):
    def __init__(self, input_dim: int, d_model: int = 128, nhead: int = 8, nlayers: int = 3, num_classes: int = 2):
        super().__init__()
        self.d_model = d_model
        self.encoder = nn.Linear(input_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model)
        layers = nn.TransformerEncoderLayer(d_model, nhead, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(layers, nlayers)
        self.decoder = nn.Linear(d_model, num_classes)

    def forward(self, src):
        encoded = self.encoder(src) * math.sqrt(self.d_model)
        encoded = self.pos_encoder(encoded)
        output = self.transformer_encoder(encoded)
        return self.decoder(output[:, -1, :])
