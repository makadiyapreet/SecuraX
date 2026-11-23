"""
modules.py — Shared neural-network modules for all SecuraX phases.

Provides:
  - AttentionPooling   : LineVul-style learned-attention pooling over ALL
                         token embeddings (replaces simple [CLS] or mean pool).
  - FocalLoss          : Focal Loss (Lin et al. 2017) with optional per-class
                         inverse-frequency weights.  γ=2, α=class-weights.
  - get_class_weights  : Compute clamped inverse-frequency class weights.

Reference:
  LineVul — https://github.com/awsm-research/LineVul
  Focal Loss — https://arxiv.org/abs/1708.02002
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Optional, Sequence


# ─── Attention Pooling (LineVul-style) ───────────────────────────────────────


class AttentionPooling(nn.Module):
    """Learned single-head attention that pools a variable-length sequence
    of token embeddings into a single fixed-size vector.

    Instead of using only the [CLS] token or a naïve mean, this module
    computes a scalar attention weight per token (via a small MLP),
    normalises with softmax (masked), and returns the weighted sum.

    Architecture (following LineVul / IVDetect):
        score_i = W2 · tanh(W1 · h_i + b1) + b2      ∈ ℝ  (per token)
        α       = softmax(scores, mask)                ∈ ℝ^L
        output  = Σ α_i · h_i                          ∈ ℝ^d

    Args:
        hidden_size : dimensionality of the token embeddings (e.g. 768).
        dropout     : dropout applied to the pooled output.
    """

    def __init__(self, hidden_size: int, dropout: float = 0.1):
        super().__init__()
        self.attn = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.Tanh(),
            nn.Linear(hidden_size, 1, bias=False),   # scalar per token
        )
        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        hidden_states: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        return_weights: bool = False,
    ):
        """
        Args:
            hidden_states : (B, L, D) — encoder output.
            attention_mask: (B, L)     — 1 for real tokens, 0 for padding.
            return_weights: bool       — if True, returns (pooled, attn_weights)

        Returns:
            pooled : (B, D) — single vector per sample.
            weights (optional): (B, L) — attention weights over tokens.
        """
        scores = self.attn(hidden_states).squeeze(-1)        # (B, L)

        if attention_mask is not None:
            # Replace padded positions with -inf so softmax ignores them
            scores = scores.masked_fill(attention_mask == 0, float("-inf"))

        weights = F.softmax(scores, dim=-1)                  # (B, L)
        pooled = (weights.unsqueeze(-1) * hidden_states).sum(dim=1)         # (B, D)
        if return_weights:
            return self.dropout(pooled), weights
        return self.dropout(pooled)


# ─── Focal Loss ──────────────────────────────────────────────────────────────


class FocalLoss(nn.Module):
    """Focal Loss with optional per-class weights (for class imbalance).

    FL(p_t) = -α_t (1 - p_t)^γ  log(p_t)

    When γ = 0 this degenerates to standard weighted cross-entropy.

    Args:
        gamma       : focusing parameter (default 2).
        weight      : 1-D tensor of per-class weights (length = num_classes).
                      Pass ``None`` for uniform weights.
        reduction   : 'mean' | 'sum' | 'none'.
        label_smoothing : optional label-smoothing ε (default 0 = off).
    """

    def __init__(
        self,
        gamma: float = 2.0,
        weight: Optional[torch.Tensor] = None,
        reduction: str = "mean",
        label_smoothing: float = 0.0,
    ):
        super().__init__()
        self.gamma = gamma
        self.reduction = reduction
        self.label_smoothing = label_smoothing

        # Store weight as a buffer so it moves with .to(device)
        if weight is not None:
            self.register_buffer("weight", weight.float())
        else:
            self.weight = None

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Args:
            logits  : (B, C) raw model output (pre-softmax).
            targets : (B,)   integer class labels.
        """
        num_classes = logits.size(-1)
        log_probs = F.log_softmax(logits, dim=-1)          # (B, C)
        probs = log_probs.exp()                             # (B, C)

        # Optional label smoothing
        if self.label_smoothing > 0:
            with torch.no_grad():
                smooth = torch.full_like(log_probs, self.label_smoothing / (num_classes - 1))
                smooth.scatter_(1, targets.unsqueeze(1), 1.0 - self.label_smoothing)
            # Element-wise focal weight per class
            focal_w = (1 - probs) ** self.gamma
            loss = -(focal_w * smooth * log_probs).sum(dim=-1)  # (B,)
        else:
            # Gather the log-prob and prob of the true class
            log_pt = log_probs.gather(1, targets.unsqueeze(1)).squeeze(1)  # (B,)
            pt = log_pt.exp()
            focal_w = (1 - pt) ** self.gamma
            loss = -focal_w * log_pt                                       # (B,)

        # Per-class weighting
        if self.weight is not None:
            alpha_t = self.weight[targets]            # (B,)
            loss = alpha_t * loss

        if self.reduction == "mean":
            return loss.mean()
        elif self.reduction == "sum":
            return loss.sum()
        return loss


# ─── Class weight computation ────────────────────────────────────────────────


def get_class_weights(
    labels: Sequence[int],
    num_classes: int = 2,
    clamp_factor: float = 10.0,
) -> torch.Tensor:
    """Compute inverse-frequency class weights (clamped).

    weight_c = N / (K × count_c),  clamped to [1/clamp, clamp].

    Args:
        labels        : iterable of integer labels.
        num_classes   : total number of classes.
        clamp_factor  : maximum ratio between any two class weights.

    Returns:
        1-D float tensor of shape (num_classes,).
    """
    counts = np.bincount(np.array(labels, dtype=np.int64), minlength=num_classes)
    counts = np.clip(counts, 1, None)  # avoid division by zero
    total = counts.sum()
    weights = total / (num_classes * counts)
    weights = np.clip(weights, 1.0 / clamp_factor, clamp_factor)
    return torch.tensor(weights, dtype=torch.float32)
