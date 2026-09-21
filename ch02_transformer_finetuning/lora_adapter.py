"""Low-Rank Adaptation (LoRA) Parameter-Efficient Fine-Tuning Module.

Implements the forward pass and parameter freezing mechanism of LoRA:
    h = W_0 * x + (alpha / r) * (B * A * x)
where:
    W_0 in R^{d_out x d_in}  (frozen pre-trained weights)
    A   in R^{r x d_in}      (initialized ~ N(0, sigma^2))
    B   in R^{d_out x r}     (initialized to 0)
    r   = rank (e.g. 4, 8, 16)
    alpha = scaling factor
"""
from __future__ import annotations

import math
import random
from typing import List, Tuple, Optional


class PureLoRALayer:
    """Pure-Python / NumPy compatible LoRA linear adapter."""

    def __init__(self, in_features: int, out_features: int, rank: int = 4, alpha: float = 8.0, seed: int = 42):
        self.in_features = in_features
        self.out_features = out_features
        self.rank = rank
        self.alpha = alpha
        self.scaling = alpha / rank

        random.seed(seed)
        # Frozen base weights W_0 (simulated)
        self.w0: List[List[float]] = [
            [(random.random() - 0.5) * 0.1 for _ in range(in_features)]
            for _ in range(out_features)
        ]

        # LoRA Matrix A ~ N(0, 1/r)
        std_a = 1.0 / math.sqrt(rank)
        self.lora_a: List[List[float]] = [
            [(random.gauss(0, std_a)) for _ in range(in_features)]
            for _ in range(rank)
        ]

        # LoRA Matrix B = 0 (ensures delta W is initially zero)
        self.lora_b: List[List[float]] = [
            [0.0 for _ in range(rank)]
            for _ in range(out_features)
        ]

    def parameter_counts(self) -> Tuple[int, int, float]:
        """Returns (frozen_params, trainable_params, reduction_percentage)."""
        frozen = self.in_features * self.out_features
        trainable = (self.in_features * self.rank) + (self.rank * self.out_features)
        reduction = 100.0 * (1.0 - (trainable / (frozen + trainable)))
        return frozen, trainable, round(reduction, 2)

    def forward(self, x: List[float]) -> List[float]:
        """Forward pass: W_0 * x + scaling * (B * A * x)."""
        assert len(x) == self.in_features, f"Input size {len(x)} != {self.in_features}"

        # 1. Base linear: W_0 * x
        base_out = [0.0] * self.out_features
        for i in range(self.out_features):
            base_out[i] = sum(self.w0[i][j] * x[j] for j in range(self.in_features))

        # 2. LoRA branch: A * x
        ax = [0.0] * self.rank
        for r in range(self.rank):
            ax[r] = sum(self.lora_a[r][j] * x[j] for j in range(self.in_features))

        # 3. LoRA branch: B * (A * x)
        bax = [0.0] * self.out_features
        for i in range(self.out_features):
            bax[i] = sum(self.lora_b[i][r] * ax[r] for r in range(self.rank))

        # 4. Merge: base + scaling * bax
        return [base_out[i] + self.scaling * bax[i] for i in range(self.out_features)]
