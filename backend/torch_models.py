from __future__ import annotations

import torch
from torch import nn


class HardenedIdsBinaryModel(nn.Module):
    """Checkpoint-compatible Conv1D + BiLSTM binary IDS model."""

    def __init__(self, input_features: int = 13, hidden_size: int = 64, dropout: float = 0.3) -> None:
        super().__init__()
        self.input_features = input_features
        self.conv1d = nn.Conv1d(1, 64, kernel_size=1)
        self.relu = nn.ReLU()
        self.batch_norm = nn.BatchNorm1d(64)
        self.lstm = nn.LSTM(
            input_size=input_features,
            hidden_size=hidden_size,
            batch_first=True,
            bidirectional=True,
        )
        self.fc1 = nn.Linear(hidden_size * 2, 32)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        if features.dim() == 2:
            features = features.unsqueeze(1)
        elif features.dim() != 3:
            raise ValueError("Expected features shaped [batch, 13] or [batch, 1, 13].")

        x = self.conv1d(features)
        x = self.relu(x)
        x = self.batch_norm(x)
        x, _ = self.lstm(x)
        x = x[:, -1, :]
        x = self.fc1(x)
        x = self.dropout(x)
        x = self.fc2(x)
        return self.sigmoid(x)


def create_hardened_ids_model() -> HardenedIdsBinaryModel:
    return HardenedIdsBinaryModel()
